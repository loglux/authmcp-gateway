"""Tests for `mcp/health.py` — async health checker.

`HealthChecker.check_server` lives inside `async with httpx.AsyncClient(...)`,
so tests inject a fake AsyncClient via `monkeypatch.setattr(httpx,
"AsyncClient", ...)`. The fake client is a thin shell over
`httpx.MockTransport` so request handlers are easy to write.

The DB side uses the `mcp_db` fixture so `update_server_health` writes to a
real SQLite file (and we can assert the row updated).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from authmcp_gateway.mcp import health as health_mod
from authmcp_gateway.mcp import store

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_db(initialized_db):
    store.init_mcp_database(initialized_db)
    return initialized_db


@pytest.fixture
def reset_global_checker():
    """Each test starts without a global health checker."""
    health_mod._health_checker = None
    yield
    health_mod._health_checker = None


def _patch_async_client(monkeypatch, handler):
    """Make every `httpx.AsyncClient(...)` constructed in the module under
    test reroute through `httpx.MockTransport(handler)`."""
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return real_async_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(health_mod.httpx, "AsyncClient", factory)


def _tools_list_response(tools=None) -> httpx.Response:
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "result": {"tools": tools or []}},
        headers={"content-type": "application/json"},
    )


# ---------------------------------------------------------------------------
# __init__ + _get_recovery_lock + lifecycle
# ---------------------------------------------------------------------------


def test_init_uses_shared_session_ids_when_provided(mcp_db):
    shared = {1: "session-abc"}
    checker = health_mod.HealthChecker(mcp_db, shared_session_ids=shared)
    assert checker._session_ids is shared


def test_init_creates_own_session_ids_when_no_shared(mcp_db):
    checker = health_mod.HealthChecker(mcp_db)
    assert checker._session_ids == {}


def test_get_recovery_lock_creates_and_reuses_per_server(mcp_db):
    checker = health_mod.HealthChecker(mcp_db)
    lock1 = checker._get_recovery_lock(7)
    lock2 = checker._get_recovery_lock(7)
    lock_other = checker._get_recovery_lock(8)
    assert lock1 is lock2
    assert lock1 is not lock_other


@pytest.mark.asyncio
async def test_start_and_stop_clean_lifecycle(mcp_db, monkeypatch):
    """start() launches a background task; stop() cancels it cleanly."""

    # Replace the loop body so the task doesn't actually run health checks.
    async def _noop_loop(self):
        try:
            while self._running:
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise

    monkeypatch.setattr(health_mod.HealthChecker, "_health_check_loop", _noop_loop)

    checker = health_mod.HealthChecker(mcp_db, interval=1)
    checker.start()
    assert checker._running is True
    assert checker._task is not None

    # Calling start() again is a no-op (logs a warning, doesn't double-task).
    first_task = checker._task
    checker.start()
    assert checker._task is first_task

    await checker.stop()
    assert checker._running is False


@pytest.mark.asyncio
async def test_stop_is_noop_when_not_running(mcp_db):
    checker = health_mod.HealthChecker(mcp_db)
    # Must not raise when there's no task to cancel.
    await checker.stop()


# ---------------------------------------------------------------------------
# get_health_checker / initialize_health_checker
# ---------------------------------------------------------------------------


def test_get_health_checker_raises_when_uninitialised(reset_global_checker):
    with pytest.raises(RuntimeError, match="not initialized"):
        health_mod.get_health_checker()


def test_initialize_health_checker_returns_singleton(reset_global_checker, mcp_db):
    inst1 = health_mod.initialize_health_checker(mcp_db, interval=30)
    inst2 = health_mod.get_health_checker()
    assert inst1 is inst2
    assert inst1.interval == 30


# ---------------------------------------------------------------------------
# check_all_servers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_all_servers_returns_empty_list_when_none(mcp_db):
    checker = health_mod.HealthChecker(mcp_db)
    assert await checker.check_all_servers() == []


@pytest.mark.asyncio
async def test_check_all_servers_filters_baseexception_results(mcp_db, monkeypatch):
    """If one per-server check raises, other results still come through."""
    store.create_mcp_server(mcp_db, "ok", "https://ok.example.com/mcp")
    store.create_mcp_server(mcp_db, "broken", "https://broken.example.com/mcp")

    checker = health_mod.HealthChecker(mcp_db)

    real = checker.check_server

    async def selective_check(server):
        if server["name"] == "broken":
            raise RuntimeError("simulated failure")
        return await real(server)

    monkeypatch.setattr(checker, "check_server", selective_check)

    # The "ok" server's HTTP call should succeed via mocked transport.
    def handler(_request):
        return _tools_list_response(tools=[{"name": "x"}])

    _patch_async_client(monkeypatch, handler)

    results = await checker.check_all_servers()
    # broken raised → filtered; ok returned a dict with status=online.
    names = [r["server_name"] for r in results]
    assert names == ["ok"]
    assert results[0]["status"] == "online"


# ---------------------------------------------------------------------------
# check_server — happy path / errors / timeouts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_server_online_updates_db_and_returns_tools_count(mcp_db, monkeypatch):
    sid = store.create_mcp_server(mcp_db, "good", "https://good.example.com/mcp")

    def handler(_request):
        return _tools_list_response(tools=[{"name": "search"}, {"name": "read"}, {"name": "write"}])

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))

    assert result["status"] == "online"
    assert result["tools_count"] == 3
    assert result["error"] is None
    assert result["response_time_ms"] is not None

    # DB row was updated.
    server = store.get_mcp_server(mcp_db, sid)
    assert server["status"] == "online"
    assert server["tools_count"] == 3


@pytest.mark.asyncio
async def test_check_server_http_500_returns_error_status(mcp_db, monkeypatch):
    sid = store.create_mcp_server(mcp_db, "bad", "https://bad.example.com/mcp")

    def handler(_request):
        return httpx.Response(500, text="internal server error")

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))
    assert result["status"] == "error"
    assert "HTTP 500" in result["error"]

    # DB persisted error status.
    assert store.get_mcp_server(mcp_db, sid)["status"] == "error"


@pytest.mark.asyncio
async def test_check_server_timeout_returns_offline(mcp_db, monkeypatch):
    sid = store.create_mcp_server(mcp_db, "slow", "https://slow.example.com/mcp")

    def handler(_request):
        raise httpx.TimeoutException("read timeout")

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))
    assert result["status"] == "offline"
    assert "Timeout" in result["error"]
    assert store.get_mcp_server(mcp_db, sid)["status"] == "offline"


@pytest.mark.asyncio
async def test_check_server_unexpected_error_falls_through_to_error_branch(mcp_db, monkeypatch):
    """RuntimeError from the JSON parse path lands in the
    PROXY_DISCOVERY_DB_ERRORS catch and surfaces as `status=error`."""
    sid = store.create_mcp_server(mcp_db, "weird", "https://weird.example.com/mcp")

    def handler(_request):
        # Returns 200 but with a body parse_sse_response can't make sense of —
        # it raises ValueError (caught by PROXY_DISCOVERY_DB_ERRORS).
        return httpx.Response(200, text="not-json", headers={"content-type": "text/plain"})

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_check_server_401_with_refresh_hash_attempts_token_refresh(mcp_db, monkeypatch):
    """When a backend returns 401 and the server has a refresh_token_hash,
    the health checker calls into the token manager and retries."""
    sid = store.create_mcp_server(
        mcp_db,
        "needs-refresh",
        "https://needs-refresh.example.com/mcp",
        auth_type="bearer",
        auth_token="old-token",
    )
    # Mark server as having a refresh capability.
    store.update_mcp_server(
        mcp_db, sid, refresh_token_hash="sha-fake", refresh_token_encrypted=None
    )

    call_count = {"n": 0}

    def handler(_request):
        call_count["n"] += 1
        # First call → 401, retry → 200 OK.
        if call_count["n"] == 1:
            return httpx.Response(401, text="unauthorized")
        return _tools_list_response(tools=[{"name": "ok"}])

    _patch_async_client(monkeypatch, handler)

    # Stub the token manager so the refresh "succeeds".
    class _StubTokenMgr:
        async def refresh_server_token(self, _server_id, triggered_by="manual"):
            return True, None

    monkeypatch.setattr(
        "authmcp_gateway.mcp.token_manager.get_token_manager",
        lambda: _StubTokenMgr(),
    )

    checker = health_mod.HealthChecker(mcp_db)
    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))

    assert result["status"] == "online"
    assert call_count["n"] >= 2  # original + retry after refresh


@pytest.mark.asyncio
async def test_check_server_400_no_session_initializes_then_retries(mcp_db, monkeypatch):
    """Stateful Streamable-HTTP backends return 400 with 'session' in the
    body the first time we hit them. The health checker should call
    `initialize`, store the returned `mcp-session-id`, then retry tools/list.
    """
    sid = store.create_mcp_server(mcp_db, "stateful", "https://state.example.com/mcp")

    state = {"call": 0}

    def handler(request):
        state["call"] += 1
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        method = body.get("method", "")

        if method == "initialize":
            # Backend hands back a session id via response header.
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"protocolVersion": "2025-03-26"},
                },
                headers={
                    "content-type": "application/json",
                    "mcp-session-id": "sess-from-init",
                },
            )

        if method == "tools/list":
            # First tools/list (no session) → 400 with "session" hint
            if "mcp-session-id" not in {k.lower() for k in request.headers.keys()}:
                return httpx.Response(
                    400,
                    text="No valid session id",
                    headers={"content-type": "text/plain"},
                )
            # Retry with session header → 200 OK
            return _tools_list_response(tools=[{"name": "x"}])

        return httpx.Response(404)

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))

    assert result["status"] == "online"
    # Session id was cached on the checker for next time.
    assert checker._session_ids[sid] == "sess-from-init"


@pytest.mark.asyncio
async def test_check_server_404_stale_session_reinitializes_then_retries(mcp_db, monkeypatch):
    """A backend that was restarted answers requests carrying the old
    Mcp-Session-Id with 404 (MCP spec, Session Management). The health check
    must re-initialize and retry instead of flagging the server offline.
    """
    sid = store.create_mcp_server(mcp_db, "restarted", "https://restarted.example.com/mcp")

    state = {"tools_calls": 0}

    def handler(request):
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        method = body.get("method", "")

        if method == "initialize":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"protocolVersion": "2025-03-26"},
                },
                headers={
                    "content-type": "application/json",
                    "mcp-session-id": "sess-after-restart",
                },
            )

        if method == "tools/list":
            state["tools_calls"] += 1
            sent = {k.lower(): v for k, v in request.headers.items()}.get("mcp-session-id")
            # The stale session the checker had cached is gone after restart.
            if sent == "stale-sess":
                return httpx.Response(
                    404,
                    text="Session not found",
                    headers={"content-type": "text/plain"},
                )
            return _tools_list_response(tools=[{"name": "x"}])

        return httpx.Response(404)

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    checker._session_ids[sid] = "stale-sess"

    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))

    assert result["status"] == "online"
    assert checker._session_ids[sid] == "sess-after-restart"
    assert state["tools_calls"] == 2  # original 404 + retry


@pytest.mark.asyncio
async def test_check_server_404_without_session_is_reported_as_error(mcp_db, monkeypatch):
    """Without a cached session a 404 means "endpoint not found", not an
    expired session — no re-initialize, the HTTP error is reported as-is."""
    sid = store.create_mcp_server(mcp_db, "wrong-path", "https://wrong.example.com/nope")

    state = {"initialize": 0, "calls": 0}

    def handler(request):
        state["calls"] += 1
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        if body.get("method") == "initialize":
            state["initialize"] += 1
        return httpx.Response(404, text="Not Found", headers={"content-type": "text/plain"})

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    result = await checker.check_server(store.get_mcp_server(mcp_db, sid))

    assert result["status"] == "error"  # HTTP status failure, surfaced as-is
    assert "404" in result["error"]
    assert state["initialize"] == 0  # no recovery attempt
    assert state["calls"] == 1  # no retry


# ---------------------------------------------------------------------------
# _initialize_session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initialize_session_returns_session_id_from_header(mcp_db, monkeypatch):
    sid = store.create_mcp_server(mcp_db, "init-only", "https://init.example.com/mcp")

    def handler(_request):
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26"}},
            headers={
                "content-type": "application/json",
                "mcp-session-id": "fresh-session-id",
            },
        )

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    async with httpx.AsyncClient() as client:
        sess = await checker._initialize_session(
            client,
            server_url="https://init.example.com/mcp",
            headers={},
            server_id=sid,
            server_name="init-only",
        )
    assert sess == "fresh-session-id"
    assert checker._session_ids[sid] == "fresh-session-id"


@pytest.mark.asyncio
async def test_initialize_session_returns_empty_string_when_header_missing(mcp_db, monkeypatch):
    """No `mcp-session-id` in response → backend doesn't use sessions; return ''."""
    sid = store.create_mcp_server(mcp_db, "stateless", "https://stateless.example.com/mcp")

    def handler(_request):
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26"}},
            headers={"content-type": "application/json"},
        )

    _patch_async_client(monkeypatch, handler)

    checker = health_mod.HealthChecker(mcp_db)
    async with httpx.AsyncClient() as client:
        sess = await checker._initialize_session(
            client,
            server_url="https://stateless.example.com/mcp",
            headers={},
            server_id=sid,
            server_name="stateless",
        )
    assert sess == ""
    assert sid not in checker._session_ids
