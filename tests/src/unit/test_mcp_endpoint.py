"""The stable ``/mcp`` endpoint and the identity the relay forwards upstream."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ._embedded_stubs import FakeSession, FakeUpstream, install, make_request

install()

from custom_components.ha_mcp_tools import embedded_setup as esetup  # noqa: E402
from custom_components.ha_mcp_tools import mcp_endpoint as endpoint  # noqa: E402
from custom_components.ha_mcp_tools import mcp_webhook as mw  # noqa: E402
from custom_components.ha_mcp_tools.const import (  # noqa: E402
    DATA_WEBHOOK,
    DATA_WEBHOOK_ID,
    DOMAIN,
    OAUTH_BASE,
    OPT_EXTERNAL_URL,
    OPT_WEBHOOK_AUTH,
    WEBHOOK_AUTH_HA,
    WEBHOOK_AUTH_NONE,
)
from ha_mcp import user_access  # noqa: E402

WEBHOOK_ID = "mcp_0123456789abcdef0123456789abcdef"
TARGET = "http://127.0.0.1:9584/private_secret"


def _user(*, is_admin: bool = False, **overrides) -> SimpleNamespace:
    fields = {
        "id": "user-1",
        "is_admin": is_admin,
        "is_active": True,
        "system_generated": False,
    }
    return SimpleNamespace(**{**fields, **overrides})


def _hass(user: SimpleNamespace | None = None) -> MagicMock:
    hass = MagicMock(name="hass")
    hass.data = {}
    hass.auth.async_validate_access_token = MagicMock(
        return_value=SimpleNamespace(user=user) if user else None
    )
    return hass


def _live(hass, *, per_user: bool = True, ha_auth: bool = True) -> FakeSession:
    session = FakeSession(upstream=FakeUpstream(status=200))
    hass.data[DOMAIN] = {
        DATA_WEBHOOK: {
            "webhook_id": WEBHOOK_ID,
            "target_url": TARGET,
            "session": session,
            "auth_mode": WEBHOOK_AUTH_HA if ha_auth else WEBHOOK_AUTH_NONE,
            "resource_server": (
                mw.ResourceServer(hass, WEBHOOK_ID, per_user=per_user)
                if ha_auth
                else None
            ),
            "oauth_provider": None,
        }
    }
    return session


def _request(path: str = "/mcp", *, token: str | None = "tok", **headers) -> MagicMock:
    all_headers = {"Host": "ha.example.com", **headers}
    if token:
        all_headers["Authorization"] = f"Bearer {token}"
    request = make_request(headers=all_headers)
    request.path = path
    return request


def _view(hass) -> endpoint.McpEndpointView:
    return endpoint.McpEndpointView(hass, mw._async_handle_webhook)


class TestIdentityForwarding:
    async def test_the_callers_identity_goes_upstream(self):
        hass = _hass(_user(is_admin=True))
        session = _live(hass)

        await _view(hass).post(_request())

        headers = session.calls[0]["headers"]
        assert headers["Authorization"] == "Bearer tok"
        assert headers[endpoint.USER_ID_HEADER] == "user-1"
        assert headers[endpoint.USER_ADMIN_HEADER] == "1"

    async def test_a_non_admin_is_marked_and_served(self):
        hass = _hass(_user())
        session = _live(hass)

        await _view(hass).post(_request())

        assert session.calls[0]["headers"][endpoint.USER_ADMIN_HEADER] == "0"

    async def test_a_server_without_identity_support_keeps_admin_only(self):
        hass = _hass(_user())
        session = _live(hass, per_user=False)

        response = await _view(hass).post(_request())

        assert response.status == 401
        assert session.calls == []

    async def test_admin_without_identity_support_sends_no_identity(self):
        hass = _hass(_user(is_admin=True))
        session = _live(hass, per_user=False)

        await _view(hass).post(_request())

        headers = session.calls[0]["headers"]
        assert "Authorization" not in headers
        assert endpoint.USER_ID_HEADER not in headers

    async def test_a_client_cannot_claim_an_identity(self):
        hass = _hass(_user())
        session = _live(hass)

        await _view(hass).post(
            _request(
                **{
                    endpoint.USER_ID_HEADER: "root",
                    endpoint.USER_ADMIN_HEADER: "1",
                }
            )
        )

        headers = session.calls[0]["headers"]
        assert headers[endpoint.USER_ID_HEADER] == "user-1"
        assert headers[endpoint.USER_ADMIN_HEADER] == "0"

    async def test_identity_headers_are_stripped_outside_sign_in_mode(self):
        hass = _hass()
        session = FakeSession(upstream=FakeUpstream(status=200))
        hass.data[DOMAIN] = {
            DATA_WEBHOOK: {
                "webhook_id": WEBHOOK_ID,
                "target_url": TARGET,
                "session": session,
                "auth_mode": WEBHOOK_AUTH_NONE,
                "resource_server": None,
                "oauth_provider": None,
            }
        }

        await mw._async_handle_webhook(
            hass,
            WEBHOOK_ID,
            _request(f"/api/webhook/{WEBHOOK_ID}", **{endpoint.USER_ID_HEADER: "root"}),
        )

        headers = session.calls[0]["headers"]
        assert endpoint.USER_ID_HEADER not in headers
        assert "Authorization" not in headers

    @pytest.mark.parametrize(
        "user",
        [
            _user(is_active=False),
            _user(system_generated=True),
        ],
    )
    async def test_refused_accounts(self, user):
        hass = _hass(user)
        session = _live(hass)

        assert (await _view(hass).post(_request())).status == 401
        assert session.calls == []

    async def test_core_decides_whether_a_local_only_user_may_connect(
        self, monkeypatch
    ):
        hass = _hass(_user(is_admin=True))
        session = _live(hass)
        monkeypatch.setattr(
            endpoint,
            "async_user_not_allowed_do_auth",
            lambda *_a: "User cannot authenticate remotely",
        )

        assert (await _view(hass).post(_request())).status == 401
        assert session.calls == []

    def test_both_sides_agree_on_the_header_names(self):
        assert endpoint.USER_ID_HEADER.lower().encode() == user_access.USER_ID_HEADER
        assert (
            endpoint.USER_ADMIN_HEADER.lower().encode() == user_access.USER_ADMIN_HEADER
        )


class TestMcpEndpoint:
    @pytest.mark.parametrize(
        ("path", "suffix"),
        [
            ("/mcp", ""),
            ("/mcp/readonly", "/readonly"),
            ("/mcp/catalog/search", "/catalog/search"),
            ("/mcp/readonly/catalog/full", "/readonly/catalog/full"),
        ],
    )
    async def test_forwards_to_the_same_variant_upstream(self, path, suffix):
        hass = _hass(_user())
        session = _live(hass)

        await _view(hass).post(_request(path))

        assert session.calls[0]["url"] == f"{TARGET}{suffix}"

    async def test_is_not_found_outside_sign_in_mode(self):
        """The public path must never reach the secret-URL posture's open relay."""
        hass = _hass(_user(is_admin=True))
        session = _live(hass, ha_auth=False)

        response = await _view(hass).post(_request())

        assert response.status == 404
        assert session.calls == []

    async def test_is_not_found_without_a_live_server(self):
        assert (await _view(_hass()).post(_request())).status == 404

    @pytest.mark.parametrize(
        ("path", "document"),
        [
            ("/mcp", "/.well-known/oauth-protected-resource/mcp"),
            ("/mcp/readonly", "/.well-known/oauth-protected-resource/mcp/readonly"),
        ],
    )
    async def test_an_anonymous_call_is_challenged_towards_its_document(
        self, path, document
    ):
        hass = _hass()
        session = _live(hass)

        response = await _view(hass).post(_request(path, token=None))

        assert response.status == 401
        assert (
            f'resource_metadata="https://ha.example.com{document}"'
            in response.headers["WWW-Authenticate"]
        )
        assert WEBHOOK_ID not in response.headers["WWW-Authenticate"]
        assert session.calls == []

    async def test_the_document_names_the_stable_url_not_the_webhook(self):
        hass = _hass()
        _live(hass)
        view = endpoint.McpProtectedResourceView(hass, mw._build_base_url)

        request = _request(endpoint.PROTECTED_RESOURCE_PATH + "/readonly", token=None)
        response = await view.get(request)

        document = response.json_body
        assert document["resource"] == "https://ha.example.com/mcp/readonly"
        assert document["authorization_servers"] == [
            f"https://ha.example.com{OAUTH_BASE}"
        ]
        assert WEBHOOK_ID not in json.dumps(document)

    async def test_the_document_is_not_found_outside_sign_in_mode(self):
        hass = _hass()
        _live(hass, ha_auth=False)
        view = endpoint.McpProtectedResourceView(hass, mw._build_base_url)

        response = await view.get(
            _request(endpoint.PROTECTED_RESOURCE_PATH, token=None)
        )

        assert response.status == 404

    def test_views_bind_once(self):
        hass = _hass()
        handler = AsyncMock()
        endpoint.bind_mcp_endpoint(hass, handler, mw._build_base_url)
        endpoint.bind_mcp_endpoint(hass, handler, mw._build_base_url)
        assert hass.http.register_view.call_count == 2


class TestConnectUrls:
    @staticmethod
    def _urls(auth_mode: str) -> list[str]:
        entry = SimpleNamespace(
            data={DATA_WEBHOOK_ID: WEBHOOK_ID},
            options={
                OPT_WEBHOOK_AUTH: auth_mode,
                OPT_EXTERNAL_URL: "https://ha.example.com",
            },
        )
        return esetup.build_connect_urls(MagicMock(name="hass"), entry)

    @pytest.fixture(autouse=True)
    def _no_local_url(self, monkeypatch):
        monkeypatch.setattr(esetup, "_resolve_local_url", lambda _hass: (None, None))

    def test_sign_in_mode_offers_the_stable_url(self):
        urls = self._urls(WEBHOOK_AUTH_HA)
        assert urls[0] == "https://ha.example.com/mcp"
        assert not any(WEBHOOK_ID in url for url in urls)

    def test_secret_url_mode_keeps_the_webhook(self):
        assert self._urls(WEBHOOK_AUTH_NONE)[0] == (
            f"https://ha.example.com/api/webhook/{WEBHOOK_ID}"
        )
