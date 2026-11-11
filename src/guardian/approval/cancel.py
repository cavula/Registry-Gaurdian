"""Authenticated email-link confirmation route: GET never cancels anything."""

from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from guardian.approval.service import ApprovalService


class SelectedItem(BaseModel):
    """A strict repository-qualified cancellation identity."""

    model_config = ConfigDict(extra="forbid")
    repository: str = Field(min_length=1)
    digest: str = Field(min_length=1)


class CancelBody(BaseModel):
    """Repository-qualified optional cancellation selection."""

    approval_id: str
    items: list[SelectedItem] | None = Field(default=None, min_length=1)


def build_cancel_app(
    service: ApprovalService,
    authenticate: Callable[[str], str],
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FastAPI:
    """Require separately validated Entra bearer identity before any mutation."""
    app = FastAPI()

    @app.get("/cancel")
    def confirmation(
        approval_id: str, repository: str | None = None, digest: str | None = None
    ) -> dict:
        if bool(repository) != bool(digest):
            raise HTTPException(status_code=400, detail="Repository and digest required together")
        return {
            "approval_id": approval_id,
            "items": [{"repository": repository, "digest": digest}] if repository else None,
            "message": "Authenticate and POST to confirm cancellation",
        }

    @app.post("/cancel")
    def cancel(body: CancelBody, authorization: str = Header(default="")) -> dict[str, str]:
        try:
            actor = authenticate(authorization)
            if not actor:
                raise PermissionError
        except Exception:
            raise HTTPException(status_code=401, detail="Authentication required") from None
        items = [(item.repository, item.digest) for item in body.items] if body.items else None
        if items is not None and len(set(items)) != len(items):
            raise HTTPException(status_code=400, detail="Duplicate cancellation selection")
        try:
            service.decide("cancel", body.approval_id, actor, clock(), items)
        except PermissionError:
            raise HTTPException(status_code=403, detail="not authorised") from None
        return {"status": "Cancellation processed"}

    return app
