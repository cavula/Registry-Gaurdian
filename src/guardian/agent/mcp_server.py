"""Eight schema-validated MCP tools with local-only notification recording."""

from datetime import datetime
from typing import Any

from jsonschema import validate

from guardian.audit.log import AuditLog
from guardian.config import Config
from guardian.models import Evidence, Image, Verdict
from guardian.policy.engine import evaluate, key
from guardian.registries.base import RegistryReader
from guardian.state import StateStore, fingerprint

STRING = {"type": "string", "minLength": 1}


def object_schema(properties: dict[str, Any]) -> dict[str, Any]:
    """Require every declared field and reject undeclared arguments."""
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def array_schema(items: dict[str, Any]) -> dict[str, Any]:
    """Describe a JSON array."""
    return {"type": "array", "items": items}


INPUTS = {
    "list_repositories": object_schema({"registry": STRING}),
    "list_images": object_schema({"registry": STRING, "repo": STRING}),
    "get_images_in_use": object_schema({}),
    "get_pull_history": object_schema({}),
    "get_scan_results": object_schema({"digest": STRING}),
    "evaluate_policy": {
        "type": "object",
        "properties": {
            "digest": STRING,
            "digests": {**array_schema(STRING), "minItems": 1, "uniqueItems": True},
        },
        "additionalProperties": False,
        "oneOf": [
            object_schema({"digest": STRING}),
            object_schema(
                {"digests": {**array_schema(STRING), "minItems": 1, "uniqueItems": True}}
            ),
        ],
    },
    "request_approval": object_schema(
        {
            "items": {
                **array_schema(object_schema({"repository": STRING, "digest": STRING})),
                "minItems": 1,
                "uniqueItems": True,
            },
            "summary": STRING,
        }
    ),
    "send_alert": object_schema({"digest": STRING, "message": STRING}),
}
OUTPUTS = {
    "list_repositories": object_schema({"repositories": array_schema(STRING)}),
    "list_images": object_schema({"images": array_schema(Image.model_json_schema())}),
    "get_images_in_use": object_schema({"digests": array_schema(STRING)}),
    "get_pull_history": object_schema(
        {
            "history": array_schema(
                object_schema(
                    {
                        "repository": STRING,
                        "digest": STRING,
                        "last_pulled_at": {"type": ["string", "null"]},
                    }
                )
            )
        }
    ),
    "get_scan_results": object_schema(
        {
            "results": array_schema(
                object_schema(
                    {
                        "repository": STRING,
                        "digest": STRING,
                        "vulns": {"type": "object"},
                        "source": {"type": ["string", "null"]},
                        "scanned_at": {"type": ["string", "null"]},
                        "security_status": {"enum": ["KNOWN", "UNKNOWN"]},
                    }
                )
            )
        }
    ),
    "evaluate_policy": object_schema(
        {
            "results": array_schema(
                object_schema(
                    {
                        "repository": STRING,
                        "digest": STRING,
                        "verdict": {"enum": [v.value for v in Verdict]},
                        "reasons": array_schema(STRING),
                    }
                )
            )
        }
    ),
    "request_approval": object_schema({"approval_id": STRING, "simulated": {"const": True}}),
    "send_alert": object_schema(
        {"ok": {"const": True}, "alert_id": STRING, "simulated": {"const": True}}
    ),
}

OUTPUTS["list_images"]["$defs"] = Image.model_json_schema().get("$defs", {})


class ToolService:
    """Read-only review tools plus staged local fakes; no delete capability."""

    def __init__(
        self,
        reader: RegistryReader | None,
        images: list[Image],
        config: Config,
        evidence: Evidence,
        now: datetime,
        audit: AuditLog,
        state: StateStore,
    ) -> None:
        self.reader = reader
        self.config = config
        self.images = evaluate(images, config, evidence, now)
        self.audit = audit
        self.state = state
        self.evaluated: set[tuple[str, str]] = set()
        self.visited_repositories: set[str] = set()
        self.requested: list[tuple[str, str]] = []
        self.alerts: dict[str, str] = {}
        self.safety_alerts: dict[str, str] = {}
        self.notifications: list[dict[str, Any]] = []
        self.complete = False
        for image in self.images:
            audit.write(
                "verdict",
                repository=image.repository,
                digest=image.digest,
                verdict=image.verdict,
                reasons=image.reasons,
            )

    def definitions(self) -> list[dict[str, Any]]:
        """Return provider-neutral tool definitions."""
        return [
            {
                "name": name,
                "description": name.replace("_", " "),
                "inputSchema": schema,
                "outputSchema": OUTPUTS[name],
            }
            for name, schema in INPUTS.items()
        ]

    def _matching(self, digest: str) -> list[Image]:
        matches = [image for image in self.images if image.digest == digest]
        if not matches:
            raise ValueError("Unknown digest")
        return matches

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Validate, audit, dispatch, and validate each tool response."""
        if name not in INPUTS:
            raise ValueError("Unknown or forbidden tool")
        validate(arguments, INPUTS[name])
        self.audit.write("tool_call", tool=name, arguments=arguments)
        if "registry" in arguments and arguments["registry"] != self.config.registry.name:
            raise ValueError("Registry is outside configured scope")
        result = self._dispatch(name, arguments)
        validate(result, OUTPUTS[name])
        return result

    def _dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "list_repositories":
            return {"repositories": sorted({i.repository for i in self.images})}
        if name == "list_images":
            repo = arguments["repo"]
            if repo not in {i.repository for i in self.images}:
                raise ValueError("Unknown repository")
            self.visited_repositories.add(repo)
            return {
                "images": [i.model_dump(mode="json") for i in self.images if i.repository == repo]
            }
        if name == "get_images_in_use":
            return {"digests": sorted({i.digest for i in self.images if i.in_use})}
        if name == "get_pull_history":
            return {
                "history": [
                    {
                        "repository": i.repository,
                        "digest": i.digest,
                        "last_pulled_at": i.last_pulled_at.isoformat()
                        if i.last_pulled_at
                        else None,
                    }
                    for i in self.images
                ]
            }
        if name == "get_scan_results":
            return {
                "results": [
                    {
                        "repository": i.repository,
                        "digest": i.digest,
                        "vulns": i.vulns,
                        "source": i.scan_source,
                        "scanned_at": i.scanned_at.isoformat() if i.scanned_at else None,
                        "security_status": "UNKNOWN" if i.security_unknown else "KNOWN",
                    }
                    for i in self._matching(arguments["digest"])
                ]
            }
        if name == "evaluate_policy":
            matches = [
                i
                for digest in arguments.get("digests", [arguments.get("digest")])
                for i in self._matching(digest)
            ]
            self.evaluated.update(key(i) for i in matches)
            return {
                "results": [
                    {
                        "repository": i.repository,
                        "digest": i.digest,
                        "verdict": i.verdict.value,
                        "reasons": i.reasons,
                    }
                    for i in matches
                ]
            }
        if name == "request_approval":
            selected = [(item["repository"], item["digest"]) for item in arguments["items"]]
            if self.evaluated != {key(i) for i in self.images}:
                raise ValueError("Every image must be evaluated before requesting approval")
            candidates = {key(i) for i in self.images if i.verdict != Verdict.KEEP}
            if set(selected) != candidates:
                raise ValueError("Request must contain all and only eligible policy candidates")
            if self.requested and self.requested != sorted(selected):
                raise ValueError("Only one approval batch is allowed")
            self.requested = sorted(selected)
            value = fingerprint(
                [
                    (i.repository, i.digest, i.verdict.value)
                    for i in self.images
                    if key(i) in selected
                ]
            )
            return {"approval_id": "simulated-" + value[:16], "simulated": True}
        self.alerts[arguments["digest"]] = arguments["message"]
        return {"ok": True, "alert_id": "simulated-alert-" + arguments["digest"], "simulated": True}

    def finalize(self, complete: bool) -> None:
        """Commit local notifications only after the runner has verified completion."""
        self.complete = complete
        if not complete:
            self.requested = []
            self.alerts = self.safety_alerts.copy()
            self.audit.write("run_incomplete", candidates_discarded=True)
            if self.alerts:
                self._record_alerts()
            return
        pairs = [
            (i.repository, i.digest, i.verdict.value)
            for i in self.images
            if key(i) in self.requested
        ]
        identifier, emitted = self.state.record(
            self.config.registry.name + ":approval", fingerprint(pairs)
        )
        if pairs:
            self.notifications.append(
                {
                    "kind": "approval",
                    "id": identifier,
                    "emitted": emitted,
                    "items": [
                        {"repository": repo, "digest": digest} for repo, digest in self.requested
                    ],
                }
            )
            if emitted:
                self.audit.write(
                    "approval",
                    approval_id=identifier,
                    simulated=True,
                    items=[
                        {"repository": repo, "digest": digest} for repo, digest in self.requested
                    ],
                    status="SIMULATED",
                )
        self.alerts.update(self.safety_alerts)
        self._record_alerts()

    def _record_alerts(self) -> None:
        """Persist safety facts even when a model review is incomplete."""
        alert_pairs = [
            (digest, next((i.verdict.value for i in self.images if i.digest == digest), "KEEP"))
            for digest in self.alerts
        ]
        _, alerts_changed = self.state.record(
            self.config.registry.name + ":alerts", fingerprint(alert_pairs)
        )
        for digest, message in self.alerts.items():
            alert_id = "simulated-alert-" + digest
            self.notifications.append(
                {
                    "kind": "alert",
                    "id": alert_id,
                    "emitted": alerts_changed,
                    "digest": digest,
                    "message": message,
                }
            )
            if alerts_changed:
                self.audit.write(
                    "alert", alert_id=alert_id, digest=digest, message=message, simulated=True
                )


def build_mcp_server(service: ToolService) -> Any:
    """Build the v1 MCP server using explicit schemas."""
    from mcp.server.lowlevel import Server
    from mcp.types import Tool

    server = Server("registry-guardian")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [Tool(**definition) for definition in service.definitions()]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return service.call(name, arguments)

    return server


async def serve_stdio(service: ToolService) -> None:
    """Serve only the eight tools over MCP stdio, without external connections."""
    from mcp.server.stdio import stdio_server

    server = build_mcp_server(service)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
