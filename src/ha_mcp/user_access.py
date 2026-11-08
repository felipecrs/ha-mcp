"""What a signed-in non-administrator may do through the in-process server.

Home Assistant enforces its own permissions on everything sent with the user's
token, but it cannot see ha-mcp's local state: security policies, saved code,
backups and logs on disk. So non-administrators get an explicit allowlist, and a
tool nobody thought about fails closed. Administrators are not restricted here,
and requests with no signed-in user are unaffected.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from contextlib import ExitStack
from typing import TYPE_CHECKING, Any

from starlette.types import ASGIApp, Receive, Scope, Send

from ha_mcp._vendor.fastmcp.server.middleware.middleware import (
    CallNext,
    Middleware,
    MiddlewareContext,
)
from ha_mcp._vendor.fastmcp.server.transforms import Transform
from ha_mcp._vendor.fastmcp.tools import Tool

from .errors import ErrorCode, create_error_response
from .per_user import UserIdentity, current_user, user_request
from .read_only import ReadOnlyMiddleware
from .renamed_tools import current_tool_name
from .tool_dispatch import CALL_PROXY_META_TOOLS
from .tools.helpers import raise_tool_error

if TYPE_CHECKING:
    from ha_mcp._vendor.fastmcp.server.transforms import GetToolNext
    from ha_mcp._vendor.fastmcp.utilities.versions import VersionSpec

logger = logging.getLogger(__name__)

# Keep in step with the component's mcp_endpoint.py.
USER_ID_HEADER = b"x-ha-mcp-user-id"
USER_ADMIN_HEADER = b"x-ha-mcp-user-admin"
_IDENTITY_HEADERS = frozenset({USER_ID_HEADER, USER_ADMIN_HEADER, b"authorization"})

SEARCH_META_TOOL = "ha_search_tools"

# Tools that only reach Home Assistant through the caller's own token, where a
# non-administrator's request is judged by Home Assistant itself.
NON_ADMIN_TOOLS = frozenset(
    {
        "ha_bulk_control",
        "ha_call_service",
        "ha_config_get_calendar_events",
        "ha_config_remove_calendar_event",
        "ha_config_set_calendar_event",
        "ha_get_camera_image",
        "ha_get_history",
        "ha_get_operation_status",
        "ha_get_overview",
        "ha_get_skill_guide",
        "ha_get_state",
        "ha_get_todo",
        "ha_list_floors_areas",
        "ha_list_services",
        "ha_remove_todo_item",
        "ha_search",
        "ha_set_todo_item",
    }
)


def _restricted() -> bool:
    user = current_user()
    return user is not None and not user.is_admin


def _visible(name: str) -> bool:
    return (
        name in NON_ADMIN_TOOLS
        or name in CALL_PROXY_META_TOOLS
        or name == SEARCH_META_TOOL
    )


class UserIdentityMiddleware:
    """Bind the identity the component's relay forwarded to this request.

    The listener is reached through the secret path, whose holder is already a
    trusted administrator, so these headers grant nothing new. The relay always
    replaces them on anything it forwards.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _identity(scope: Scope) -> UserIdentity | None:
        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        user_id = headers.get(USER_ID_HEADER, b"").decode("latin-1")
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, token = authorization.partition(" ")
        if not user_id or scheme.lower() != "bearer" or not token.strip():
            return None
        return UserIdentity(
            user_id=user_id,
            is_admin=headers.get(USER_ADMIN_HEADER) == b"1",
            token=token.strip(),
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        identity = self._identity(scope)
        # Nothing past this point needs the raw token in the request headers.
        scope = {
            **scope,
            "headers": [
                (name, value)
                for name, value in scope.get("headers", [])
                if name.lower() not in _IDENTITY_HEADERS
            ],
        }
        with ExitStack() as stack:
            if identity is not None:
                stack.enter_context(user_request(identity))
            await self.app(scope, receive, send)


class UserAccessTransform(Transform):
    """Hide tools a signed-in non-administrator cannot use."""

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        if not _restricted():
            return tools
        return [tool for tool in tools if _visible(tool.name)]

    async def get_tool(
        self, name: str, call_next: GetToolNext, *, version: VersionSpec | None = None
    ) -> Tool | None:
        tool = await call_next(name, version=version)
        if tool is None or not _restricted():
            return tool
        return tool if _visible(tool.name) else None


class UserAccessMiddleware(Middleware):
    """Refuse calls outside the allowlist, including through the call proxies."""

    async def on_call_tool(
        self, context: MiddlewareContext, call_next: CallNext
    ) -> Any:
        if not _restricted():
            return await call_next(context)
        name = current_tool_name(context.message.name)
        if name in CALL_PROXY_META_TOOLS:
            unwrapped = ReadOnlyMiddleware._unwrap_proxy_call(
                context.message.arguments or {}
            )
            if unwrapped is None:
                # The proxy rejects a malformed envelope before any dispatch.
                return await call_next(context)
            name = current_tool_name(unwrapped[0])
        if _visible(name):
            return await call_next(context)
        logger.info("Refused %s for a non-administrator", name)
        raise_tool_error(
            create_error_response(
                ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS,
                f"'{name}' is only available to Home Assistant administrators.",
                suggestions=["Ask an administrator to perform this action"],
                context={"tool_name": name},
            )
        )
        return None  # py/mixed-returns: unreachable, raise_tool_error raises
