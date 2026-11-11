"""Actual SDK/ASGI lifecycle and card identity tests without network access."""

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import azure.functions as functions
import httpx
import pytest
from microsoft_teams.api import AdaptiveCardInvokeActivity
from microsoft_teams.apps import App

from guardian.approval.sdk import build_functions_app, create_card_handler


def activity(data: dict, actor: str | None = "trusted-actor") -> AdaptiveCardInvokeActivity:
    """Build the real SDK's parsed invoke model; auth is tested separately."""
    return AdaptiveCardInvokeActivity.model_validate(
        {
            "id": "invoke-1",
            "type": "invoke",
            "name": "adaptiveCard/action",
            "from": {"id": "teams-user", "aadObjectId": actor},
            "recipient": {"id": "bot"},
            "conversation": {"id": "dedicated-channel"},
            "value": {"action": {"type": "Action.Execute", "data": data}},
        }
    )


def test_card_actor_comes_only_from_validated_activity() -> None:
    callback = Mock(return_value="scheduled")
    handler = create_card_handler(callback)
    data = {
        "action": "approve",
        "approval_id": "approval-1",
        "actor": "spoofed-actor",
        "user_id": "spoofed-user",
        "items": [{"repository": "app", "digest": "sha256:same"}],
    }
    context = SimpleNamespace(activity=activity(data))
    response = asyncio.run(handler(context))
    assert response.value == "scheduled"
    callback.assert_called_once_with(
        "approve", "approval-1", "trusted-actor", [("app", "sha256:same")]
    )


@pytest.mark.parametrize(
    "data, actor, expected",
    [
        ({"action": "cancel", "approval_id": "a"}, None, "not authorised"),
        ({"action": "delete", "approval_id": "a"}, "actor", "invalid action"),
        ({"action": "cancel", "approval_id": "a", "items": []}, "actor", "invalid selection"),
        (
            {
                "action": "cancel",
                "approval_id": "a",
                "items": [
                    {"repository": "app", "digest": "d"},
                    {"repository": "app", "digest": "d"},
                ],
            },
            "actor",
            "invalid selection",
        ),
    ],
)
def test_invalid_identity_or_selection_never_reaches_core(
    data: dict,
    actor: str | None,
    expected: str,
) -> None:
    callback = Mock()
    handler = create_card_handler(callback)
    response = asyncio.run(handler(SimpleNamespace(activity=activity(data, actor))))
    assert response.value == expected
    callback.assert_not_called()


def test_omitted_items_means_whole_batch() -> None:
    callback = Mock(return_value="cancelled")
    handler = create_card_handler(callback)
    response = asyncio.run(
        handler(
            SimpleNamespace(
                activity=activity(
                    {
                        "action": "cancel",
                        "approval_id": "a",
                    }
                )
            )
        )
    )
    assert response.value == "cancelled"
    callback.assert_called_once_with("cancel", "a", "trusted-actor", None)


def test_actual_sdk_asgi_startup_and_missing_token_rejection() -> None:
    callback = Mock()
    bridge = build_functions_app(callback, client_id="fixture-client", tenant_id="fixture-tenant")
    assert isinstance(bridge.teams, App)
    assert isinstance(bridge.functions, functions.AsgiFunctionApp)

    async def check() -> None:
        async with bridge.web.router.lifespan_context(bridge.web):
            assert any(route.path == "/api/messages" for route in bridge.web.routes)
            transport = httpx.ASGITransport(app=bridge.web)
            async with httpx.AsyncClient(
                transport=transport, base_url="https://fixture.test"
            ) as client:
                response = await client.post(
                    "/api/messages",
                    json={
                        "type": "invoke",
                        "id": "unauthenticated",
                        "value": {
                            "action": {
                                "type": "Action.Execute",
                                "data": {
                                    "action": "approve",
                                    "approval_id": "a",
                                    "actor": "spoofed",
                                },
                            }
                        },
                    },
                )
            assert response.status_code == 401
        callback.assert_not_called()

    asyncio.run(check())


def test_functions_asgi_lifespan_and_http_middleware() -> None:
    """Use the same startup and request middleware as Azure's Functions wrapper."""
    callback = Mock()
    bridge = build_functions_app(callback, client_id="fixture-client", tenant_id="fixture-tenant")

    async def check() -> None:
        middleware = bridge.functions.middleware
        assert await middleware.notify_startup()
        try:
            request = functions.HttpRequest(
                method="POST",
                url="https://fixture.test/api/messages",
                headers={"content-type": "application/json"},
                body=b'{"type":"invoke","id":"unauthenticated"}',
            )
            response = await middleware.handle_async(request, None)
            assert response.status_code == 401
        finally:
            await middleware.notify_shutdown()
        callback.assert_not_called()

    asyncio.run(check())
