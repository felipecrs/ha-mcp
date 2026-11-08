"""Build the in-process server so requests run as the user who signed in.

``ha_mcp`` is imported lazily: this runs on the server's worker thread, after
the embedded connection is in place (see :mod:`embedded_server`).
"""

from __future__ import annotations

from typing import Any


def build_per_user_server(
    server_cls: Any, settings: Any
) -> tuple[Any, dict[str, Any], bool]:
    """Return the server, its ``http_app`` arguments and whether identity is honored.

    A server build without this support (a development ``pip_spec`` pointing at
    an older release) returns False, so the relay keeps sign-in to administrators
    rather than serving other users with the server's administrator token.
    """
    try:
        from starlette.middleware import Middleware

        from ha_mcp.client.rest_client import HomeAssistantClient
        from ha_mcp.per_user import PerUserClient
        from ha_mcp.user_access import UserIdentityMiddleware
    except ImportError:
        return server_cls(), {}, False
    server = server_cls(
        client=PerUserClient(HomeAssistantClient()),
        server_name=settings.mcp_server_name,
        server_version=settings.mcp_server_version,
    )
    return server, {"middleware": [Middleware(UserIdentityMiddleware)]}, True
