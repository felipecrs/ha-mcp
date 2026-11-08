"""The stable ``/mcp`` endpoint: same relay as the webhook, Home Assistant sign-in only.

Unlike the webhook id, this path is public knowledge, so it is never a
credential: while Home Assistant sign-in is not the active mode the views answer
404. They are checked per request because aiohttp cannot unbind a view.

The ``/.well-known/oauth-protected-resource/mcp`` document names only this path,
so publishing it reveals nothing, unlike the webhook's document.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.components.http.auth_util import async_user_not_allowed_do_auth
from homeassistant.core import HomeAssistant

from .const import DATA_WEBHOOK, DOMAIN, OAUTH_BASE
from .readonly_webhook import ENDPOINT_SUFFIXES, endpoint_suffix

_LOGGER = logging.getLogger(__name__)

MCP_PATH = "/mcp"
PROTECTED_RESOURCE_PATH = f"/.well-known/oauth-protected-resource{MCP_PATH}"

# Keep in step with ha_mcp/user_access.py. The relay strips both from every
# incoming request, so only it can set them.
USER_ID_HEADER = "X-HA-MCP-User-Id"
USER_ADMIN_HEADER = "X-HA-MCP-User-Admin"

_VIEWS_REGISTERED_KEY = "ha_mcp_tools_mcp_endpoint_registered"


class ResourceServer:
    """ha_auth resource server: bearer validation + discovery URL building.

    Owns no signing key, no client credentials, and binds no root views — HA core
    is the authorization server. Held by the discovery views and the webhook
    handler.
    """

    def __init__(
        self, hass: HomeAssistant, webhook_id: str, *, per_user: bool = False
    ) -> None:
        """Bind to the HA instance and this install's webhook id.

        ``per_user`` says the running server acts as each signed-in user. Without
        it every request runs with the server's own administrator token, so only
        administrators may sign in.
        """
        self._hass = hass
        self._webhook_id = webhook_id
        self._per_user = per_user

    @property
    def webhook_id(self) -> str:
        """This install's private webhook id."""
        return self._webhook_id

    async def validate_request(self, request: web.Request) -> bool:
        """Return True iff the request carries a Bearer token HA core accepts."""
        return await self.identity_headers(request) is not None

    async def identity_headers(self, request: web.Request) -> dict[str, str] | None:
        """Return the headers that carry the caller upstream, or None if refused.

        A missing/malformed ``Authorization`` header is rejected without touching
        the validator. ``hass.auth.async_validate_access_token`` is a synchronous
        ``@callback`` in HA core; it is awaited defensively in case a future
        release makes it a coroutine, and any raise is treated as unauthorized so
        a crafted token yields a 401 challenge rather than a 500.
        """
        header = request.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            return None
        token = header[7:].strip()
        if not token:
            return None
        try:
            result = self._hass.auth.async_validate_access_token(token)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            _LOGGER.debug(
                "ha_auth: bearer validation raised; treating as unauthorized",
                exc_info=True,
            )
            return None
        if result is None:
            return None
        user = getattr(result, "user", None)
        if user is None or getattr(user, "system_generated", False):
            return None
        # The same check Core's own auth middleware makes: inactive accounts, and
        # local-only accounts arriving from outside the local network.
        if async_user_not_allowed_do_auth(self._hass, user, request):
            return None
        is_admin = bool(getattr(user, "is_admin", False))
        if not self._per_user:
            return {} if is_admin else None
        return {
            "Authorization": f"Bearer {token}",
            USER_ID_HEADER: str(user.id),
            USER_ADMIN_HEADER: "1" if is_admin else "0",
        }


def _ha_auth_cfg(hass: HomeAssistant) -> dict[str, Any] | None:
    """The live relay config, only while Home Assistant sign-in is active."""
    domain_data = hass.data.get(DOMAIN)
    cfg = domain_data.get(DATA_WEBHOOK) if isinstance(domain_data, dict) else None
    if isinstance(cfg, dict) and cfg.get("resource_server") is not None:
        return cfg
    return None


class McpEndpointView(HomeAssistantView):
    """Relay MCP traffic; the relay itself requires a valid sign-in."""

    requires_auth = False
    cors_allowed = True
    url = MCP_PATH
    name = "ha_mcp_tools:mcp"

    def __init__(
        self,
        hass: HomeAssistant,
        handler: Callable[..., Awaitable[web.StreamResponse]],
    ) -> None:
        """Bind the relay handler; liveness is resolved per request."""
        self._hass = hass
        self._handler = handler
        self.extra_urls = [f"{MCP_PATH}{suffix}" for suffix in ENDPOINT_SUFFIXES]

    async def post(self, request: web.Request) -> web.StreamResponse:
        """Forward to the relay, or 404 outside Home Assistant sign-in mode."""
        cfg = _ha_auth_cfg(self._hass)
        if cfg is None:
            return web.Response(status=404)
        return await self._handler(
            self._hass,
            cfg["webhook_id"],
            request,
            suffix=endpoint_suffix(request.path, MCP_PATH),
        )

    get = post


class McpProtectedResourceView(HomeAssistantView):
    """RFC 9728 metadata for ``/mcp`` and its endpoint variants."""

    requires_auth = False
    cors_allowed = True
    url = PROTECTED_RESOURCE_PATH
    name = "ha_mcp_tools:mcp:protected-resource"

    def __init__(
        self, hass: HomeAssistant, build_base_url: Callable[[web.Request], str]
    ) -> None:
        """Bind the base-URL builder; liveness is resolved per request."""
        self._hass = hass
        self._build_base_url = build_base_url
        self.extra_urls = [
            f"{PROTECTED_RESOURCE_PATH}{suffix}" for suffix in ENDPOINT_SUFFIXES
        ]

    async def get(self, request: web.Request) -> web.Response:
        """Serve the document, or 404 outside Home Assistant sign-in mode."""
        if _ha_auth_cfg(self._hass) is None:
            return web.json_response({"error": "not_found"}, status=404)
        base = self._build_base_url(request)
        suffix = endpoint_suffix(request.path, PROTECTED_RESOURCE_PATH)
        return web.json_response(
            {
                "resource": f"{base}{MCP_PATH}{suffix}",
                "authorization_servers": [f"{base}{OAUTH_BASE}"],
                "bearer_methods_supported": ["header"],
                "resource_documentation": "https://github.com/homeassistant-ai/ha-mcp",
            }
        )


def bind_mcp_endpoint(
    hass: HomeAssistant,
    handler: Callable[..., Awaitable[web.StreamResponse]],
    build_base_url: Callable[[web.Request], str],
) -> None:
    """Bind the views at most once per Home Assistant session."""
    if hass.data.get(_VIEWS_REGISTERED_KEY):
        return
    hass.http.register_view(McpEndpointView(hass, handler))
    hass.http.register_view(McpProtectedResourceView(hass, build_base_url))
    hass.data[_VIEWS_REGISTERED_KEY] = True
