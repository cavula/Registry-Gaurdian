"""Teams SDK activity boundary and Azure Functions ASGI hosting.

The SDK authenticates /api/messages before this module's card handler runs.
The approval core must additionally check the actor's Entra group membership.
No server is started and no service client is called by the factory.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal

import azure.functions as functions
from fastapi import FastAPI
from microsoft_teams.api import (
    AdaptiveCardActionMessageResponse,
    AdaptiveCardInvokeActivity,
)
from microsoft_teams.apps import ActivityContext, App, FastAPIAdapter
from pydantic import BaseModel, Field, ValidationError

ActionHandler = Callable[[str, str, str, list[tuple[str, str]] | None], str]
CardHandler = Callable[
    [ActivityContext[AdaptiveCardInvokeActivity]], Awaitable[AdaptiveCardActionMessageResponse]
]


class ActionItem(BaseModel):
    """A repository-qualified selection; this carries no actor identity."""

    repository: str = Field(min_length=1)
    digest: str = Field(min_length=1)


class ActionData(BaseModel):
    """Only selection and action data are taken from the untrusted card payload."""

    action: Literal["approve", "reject", "cancel"]
    approval_id: str = Field(min_length=1)
    items: list[ActionItem] | None = None


def create_card_handler(action_handler: ActionHandler) -> CardHandler:
    """Route validated SDK activity identity to the core's authorization guardrail."""

    async def card_action(
        ctx: ActivityContext[AdaptiveCardInvokeActivity],
    ) -> AdaptiveCardActionMessageResponse:
        actor = ctx.activity.from_.aad_object_id
        if not actor:
            return AdaptiveCardActionMessageResponse(value="not authorised")
        try:
            data = ActionData.model_validate(ctx.activity.value.action.data)
        except ValidationError:
            return AdaptiveCardActionMessageResponse(value="invalid action")
        items = [(item.repository, item.digest) for item in data.items] if data.items else None
        if data.items is not None and (not items or len(set(items)) != len(items)):
            return AdaptiveCardActionMessageResponse(value="invalid selection")
        # The handler must use the authenticated actor, never any payload actor/user field.
        reply = action_handler(data.action, data.approval_id, actor, items)
        return AdaptiveCardActionMessageResponse(value=reply)

    return card_action


@dataclass
class TeamsFunctionsBridge:
    """Hosting surfaces and the SDK-owned authenticated activity route."""

    functions: functions.AsgiFunctionApp
    web: FastAPI
    teams: App
    card_action: CardHandler


def build_functions_app(
    action_handler: ActionHandler,
    *,
    client_id: str | None = None,
    tenant_id: str | None = None,
) -> TeamsFunctionsBridge:
    """Create a Functions ASGI app; initialize Teams during ASGI lifespan startup.

    Credential values can be provided by the SDK's environment-variable configuration
    or managed identity. Authentication bypasses are never enabled here. Without
    credentials the SDK rejects all inbound requests rather than trusting activity JSON.
    """
    teams: App

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await teams.initialize()
        yield

    web = FastAPI(lifespan=lifespan)
    adapter = FastAPIAdapter(app=web)
    teams = App(
        http_server_adapter=adapter,
        client_id=client_id,
        tenant_id=tenant_id,
        dangerously_allow_unauthenticated_requests=False,
    )
    handler = create_card_handler(action_handler)
    teams.on_card_action(handler)
    # Functions keys are not Teams authentication. The SDK validates the Teams JWT.
    hosted = functions.AsgiFunctionApp(app=web, http_auth_level=functions.AuthLevel.ANONYMOUS)
    return TeamsFunctionsBridge(hosted, web, teams, handler)
