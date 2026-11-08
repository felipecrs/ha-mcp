"""The in-process server is only built per-user when the installed build supports it."""

from __future__ import annotations

import builtins
from types import SimpleNamespace
from unittest.mock import MagicMock

from ._embedded_stubs import install

install()

from custom_components.ha_mcp_tools.embedded_per_user import (  # noqa: E402
    build_per_user_server,
)

SETTINGS = SimpleNamespace(mcp_server_name="ha-mcp", mcp_server_version="1.2.3")


def test_builds_with_the_per_user_client_and_identity_middleware(monkeypatch):
    monkeypatch.setenv("HOMEASSISTANT_URL", "http://localhost:8123")
    monkeypatch.setenv("HOMEASSISTANT_TOKEN", "unit-test")
    from ha_mcp.per_user import PerUserClient
    from ha_mcp.user_access import UserIdentityMiddleware

    server_cls = MagicMock()
    server, app_args, per_user = build_per_user_server(server_cls, SETTINGS)

    assert server is server_cls.return_value
    assert per_user is True
    assert app_args["middleware"][0].cls is UserIdentityMiddleware
    kwargs = server_cls.call_args.kwargs
    assert isinstance(kwargs["client"], PerUserClient)
    assert kwargs["server_name"] == "ha-mcp"
    assert kwargs["server_version"] == "1.2.3"


def test_a_build_without_support_reports_it(monkeypatch):
    real_import = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name == "ha_mcp.user_access":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    server_cls = MagicMock()

    _server, app_args, per_user = build_per_user_server(server_cls, SETTINGS)

    assert per_user is False
    assert app_args == {}
    server_cls.assert_called_once_with()
