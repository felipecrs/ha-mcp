"""Requests run as the signed-in user, and non-administrators stay on the allowlist."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ha_mcp._vendor.fastmcp.exceptions import ToolError as VendoredToolError
from ha_mcp.per_user import (
    ClientKeyedCache,
    PerUserClient,
    UserIdentity,
    cache_owner,
    current_user,
    server_client,
    user_request,
)
from ha_mcp.user_access import (
    NON_ADMIN_TOOLS,
    USER_ADMIN_HEADER,
    USER_ID_HEADER,
    UserAccessMiddleware,
    UserAccessTransform,
    UserIdentityMiddleware,
)

ALICE = UserIdentity(user_id="alice", is_admin=False, token="alice-1")
BOB = UserIdentity(user_id="bob", is_admin=False, token="bob-1")
ADMIN = UserIdentity(user_id="root", is_admin=True, token="root-1")


def _proxy() -> PerUserClient:
    default = SimpleNamespace(
        base_url="http://127.0.0.1:8123", verify_ssl=True, token="server-admin"
    )
    return PerUserClient(default)


class TestPerUserClient:
    def test_no_identity_uses_the_server_client(self):
        proxy = _proxy()
        assert proxy.token == "server-admin"
        assert cache_owner(proxy) is proxy.server_client()

    def test_users_never_share_a_client(self):
        proxy = _proxy()
        with user_request(ALICE):
            alice = cache_owner(proxy)
            assert proxy.token == "alice-1"
        with user_request(BOB):
            assert cache_owner(proxy) is not alice
            assert proxy.token == "bob-1"
        assert proxy.token == "server-admin"

    def test_refreshed_token_keeps_the_client_and_updates_its_credentials(self):
        proxy = _proxy()
        with user_request(ALICE):
            first = cache_owner(proxy)
        refreshed = UserIdentity(user_id="alice", is_admin=False, token="alice-2")
        with user_request(refreshed):
            assert cache_owner(proxy) is first
            assert first.token == "alice-2"
            assert first.httpx_client.headers["Authorization"] == "Bearer alice-2"

    def test_a_role_change_starts_a_clean_client(self):
        proxy = _proxy()
        with user_request(ALICE):
            before = cache_owner(proxy)
        promoted = UserIdentity(user_id="alice", is_admin=True, token="alice-1")
        with user_request(promoted):
            after = cache_owner(proxy)
        assert after is not before
        assert after.known_is_admin is True

    def test_server_level_work_ignores_the_caller(self):
        proxy = _proxy()
        with user_request(ALICE):
            assert server_client(proxy) is proxy.server_client()

    async def test_close_closes_every_client(self):
        proxy = _proxy()
        proxy.server_client().close = AsyncMock()
        with user_request(ALICE):
            alice = cache_owner(proxy)
        alice.close = AsyncMock()
        await proxy.close()
        alice.close.assert_awaited_once()
        proxy.server_client().close.assert_awaited_once()


class TestClientKeyedCache:
    def test_a_value_cached_for_one_user_is_invisible_to_another(self):
        proxy = _proxy()
        cache: ClientKeyedCache[str] = ClientKeyedCache()
        with user_request(ALICE):
            cache[proxy] = "alice's"
        with user_request(BOB):
            assert proxy not in cache
            assert cache.get(proxy) is None
        with user_request(ALICE):
            assert cache[proxy] == "alice's"
            assert cache.pop(proxy) == "alice's"

    def test_an_ordinary_client_keys_on_itself(self):
        client = MagicMock()
        cache: ClientKeyedCache[int] = ClientKeyedCache()
        cache[client] = 1
        assert cache[client] == 1


async def _run_asgi(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, _receive, _send):
        seen["user"] = current_user()
        seen["headers"] = dict(scope["headers"])

    await UserIdentityMiddleware(app)(
        {"type": "http", "headers": headers}, AsyncMock(), AsyncMock()
    )
    return seen


class TestUserIdentityMiddleware:
    async def test_binds_the_identity_and_hides_the_token(self):
        seen = await _run_asgi(
            [
                (b"authorization", b"Bearer tok"),
                (USER_ID_HEADER, b"alice"),
                (USER_ADMIN_HEADER, b"0"),
                (b"x-other", b"kept"),
            ]
        )
        assert seen["user"] == UserIdentity("alice", False, "tok")
        assert seen["headers"] == {b"x-other": b"kept"}
        assert current_user() is None

    @pytest.mark.parametrize(
        "headers",
        [
            [],
            [(b"authorization", b"Bearer tok")],
            [(USER_ID_HEADER, b"alice")],
            [(b"authorization", b"Basic tok"), (USER_ID_HEADER, b"alice")],
        ],
    )
    async def test_an_incomplete_identity_is_no_identity(self, headers):
        assert (await _run_asgi(headers))["user"] is None

    async def test_admin_flag_needs_an_explicit_one(self):
        seen = await _run_asgi(
            [
                (b"authorization", b"Bearer tok"),
                (USER_ID_HEADER, b"a"),
                (USER_ADMIN_HEADER, b"true"),
            ]
        )
        assert seen["user"].is_admin is False


def _context(name: str, arguments: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(message=SimpleNamespace(name=name, arguments=arguments))


class TestUserAccessMiddleware:
    @pytest.mark.parametrize(
        "name",
        [
            "ha_config_set_automation",
            "ha_manage_backup",
            "ha_report_issue",
            "ha_dev_manage_settings",
            "ha_manage_custom_tool",
            "a_tool_nobody_has_written_yet",
        ],
    )
    async def test_non_admin_is_refused_anything_unlisted(self, name):
        call_next = AsyncMock()
        with user_request(ALICE), pytest.raises(VendoredToolError):
            await UserAccessMiddleware().on_call_tool(_context(name), call_next)
        call_next.assert_not_awaited()

    @pytest.mark.parametrize(
        "arguments",
        [
            {"name": "ha_manage_backup", "arguments": {}},
            {
                "name": "ha_call_read_tool",
                "arguments": {"name": "ha_manage_backup", "arguments": {}},
            },
            {
                "name": "ha_call_write_tool",
                "arguments": '{"name": "ha_manage_backup", "arguments": {}}',
            },
        ],
    )
    async def test_call_proxies_cannot_launder_an_unlisted_tool(self, arguments):
        call_next = AsyncMock()
        with user_request(ALICE), pytest.raises(VendoredToolError):
            await UserAccessMiddleware().on_call_tool(
                _context("ha_call_write_tool", arguments), call_next
            )
        call_next.assert_not_awaited()

    async def test_non_admin_may_use_listed_tools_directly_and_through_a_proxy(self):
        call_next = AsyncMock(return_value="ok")
        with user_request(ALICE):
            middleware = UserAccessMiddleware()
            assert await middleware.on_call_tool(_context("ha_get_state"), call_next)
            assert await middleware.on_call_tool(
                _context("ha_call_read_tool", {"name": "ha_get_state"}), call_next
            )

    @pytest.mark.parametrize("identity", [ADMIN, None])
    async def test_admins_and_identityless_requests_are_unrestricted(self, identity):
        call_next = AsyncMock(return_value="ok")
        context = _context("ha_manage_backup")
        if identity is None:
            assert await UserAccessMiddleware().on_call_tool(context, call_next)
        else:
            with user_request(identity):
                assert await UserAccessMiddleware().on_call_tool(context, call_next)


class TestUserAccessTransform:
    async def test_hides_unlisted_tools_from_non_admins_only(self):
        tools = [
            SimpleNamespace(name="ha_get_state"),
            SimpleNamespace(name="ha_restart"),
        ]
        transform = UserAccessTransform()
        assert await transform.list_tools(tools) == tools
        with user_request(ADMIN):
            assert await transform.list_tools(tools) == tools
        with user_request(ALICE):
            assert await transform.list_tools(tools) == tools[:1]
            hidden = AsyncMock(return_value=tools[1])
            assert await transform.get_tool("ha_restart", hidden) is None


async def test_the_allowlist_names_real_tools(monkeypatch):
    """A renamed tool would silently vanish for non-administrators."""
    monkeypatch.setitem(os.environ, "HOMEASSISTANT_URL", "http://localhost:8123")
    monkeypatch.setitem(os.environ, "HOMEASSISTANT_TOKEN", "unit-test")
    from ha_mcp.server import HomeAssistantSmartMCPServer

    server = HomeAssistantSmartMCPServer()
    names = {tool.name for tool in await server.mcp.local_provider._list_tools()}
    assert names >= NON_ADMIN_TOOLS
