"""Run each request as the Home Assistant user who signed in (in-process server).

Tools capture one client object at registration, so that object has to pick the
right credentials per request. Requests that carry no identity (the sidebar
panel, conversation agents, background work) use the server's own client.
"""

from __future__ import annotations

import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast

_V = TypeVar("_V")


@dataclass(frozen=True)
class UserIdentity:
    """A user the component's relay authenticated for this request."""

    user_id: str
    is_admin: bool
    token: str = field(repr=False)


_current_user: ContextVar[UserIdentity | None] = ContextVar(
    "ha_mcp_current_user", default=None
)


def current_user() -> UserIdentity | None:
    """The signed-in user of this request, if it carries one."""
    return _current_user.get()


@contextmanager
def user_request(identity: UserIdentity) -> Iterator[None]:
    """Run this request and its nested tool calls as ``identity``."""
    token = _current_user.set(identity)
    try:
        yield
    finally:
        _current_user.reset(token)


def cache_owner(client: Any) -> Any:
    """The object per-client state belongs to: a shared proxy is not one."""
    owner = getattr(type(client), "cache_owner", None)
    return owner(client) if owner is not None else client


def server_client(client: Any) -> Any:
    """The client for server-level work that must not depend on the caller."""
    resolve = getattr(type(client), "server_client", None)
    return resolve(client) if resolve is not None else client


class ClientKeyedCache(weakref.WeakKeyDictionary[Any, _V]):
    """Per-client state that never crosses users behind a request-scoped proxy."""

    def __getitem__(self, key: Any) -> _V:
        return super().__getitem__(cache_owner(key))

    def __setitem__(self, key: Any, value: _V) -> None:
        super().__setitem__(cache_owner(key), value)

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(cache_owner(key))

    def __contains__(self, key: object) -> bool:
        return super().__contains__(cache_owner(key))

    def get(self, key: Any, default: Any = None) -> _V | None:  # type: ignore[override]
        return cast("_V | None", super().get(cache_owner(key), default))

    def pop(self, key: Any, *args: Any) -> _V:
        return cast("_V", super().pop(cache_owner(key), *args))

    def setdefault(self, key: Any, default: Any = None) -> _V:
        return super().setdefault(cache_owner(key), default)


class PerUserClient:
    """Forward to the current user's client, or the server's when there is none."""

    def __init__(self, default: Any) -> None:
        self._default = default
        self._clients: dict[str, Any] = {}
        self._retired: list[Any] = []

    def server_client(self) -> Any:
        """The client holding the server's own administrator token."""
        return self._default

    def cache_owner(self) -> Any:
        """Key per-client caches by the client this request really uses."""
        return self._current()

    def _current(self) -> Any:
        identity = current_user()
        if identity is None:
            return self._default
        client = self._clients.get(identity.user_id)
        if client is None or client.known_is_admin is not identity.is_admin:
            return self._create(identity, client)
        if client.token != identity.token:
            # Core access tokens last 30 minutes. Keeping the client across a
            # refresh keeps its caches and bounds this dict to one per user.
            client.token = identity.token
            client.httpx_client.headers["Authorization"] = f"Bearer {identity.token}"
        return client

    def _create(self, identity: UserIdentity, previous: Any) -> Any:
        from .client.rest_client import HomeAssistantClient

        if previous is not None:
            # A role change drops what was cached under the old role. An
            # in-flight call may still use the old client, so close it later.
            self._retired.append(previous)
        client = HomeAssistantClient(
            base_url=self._default.base_url,
            token=identity.token,
            verify_ssl=self._default.verify_ssl,
            is_admin=identity.is_admin,
        )
        self._clients[identity.user_id] = client
        return client

    async def close(self) -> None:
        """Close every client this proxy owns."""
        clients = [*self._clients.values(), *self._retired, self._default]
        self._clients.clear()
        self._retired.clear()
        for client in clients:
            await client.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._current(), name)
