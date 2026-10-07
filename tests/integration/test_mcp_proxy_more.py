"""Extra tests for `mcp/proxy.py` to push coverage past 35%.

The existing `test_mcp_proxy.py` covers the policy/idempotency helpers and
high-level list_tools/call_tool with mocked `_proxy_jsonrpc`. This file adds:

- pure module-level helpers (parse_sse_response, get_auth_headers,
  normalize_server_name)
- proxy lifecycle (_get_client / close)
- cache helpers (invalidate_cache, _is_cache_valid, dedup helpers)
- routing (_route_tool_to_server, _route_resource_to_server, _route_prompt_to_server)
- aggregation (list_resources, list_prompts, list_resource_templates,
  get_aggregated_capabilities)
- read_resource / get_prompt / complete dispatch and not-found errors
- the inline `_proxy_jsonrpc` HTTP path via `httpx.MockTransport`
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from authmcp_gateway.mcp import proxy as proxy_mod
from authmcp_gateway.mcp import store
from authmcp_gateway.mcp.proxy import (
    McpProxy,
    PromptNotFoundError,
    ResourceNotFoundError,
    ToolNotFoundError,
    get_auth_headers,
    normalize_server_name,
    parse_sse_response,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_db(initialized_db):
    """Real initialized DB. Slow on this volume (~4.5s) — only use it when
    the test actually executes a `store.*` call. Most tests monkeypatch
    `_get_servers`/`_proxy_jsonrpc` and never touch SQLite, so they take a
    plain `db_path` string (per-test tmp path with no init) instead."""
    store.init_mcp_database(initialized_db)
    return initialized_db


def _make_response(*, status=200, json_body=None, text=None, content_type=None, headers=None):
    """Build a real httpx.Response (not via a request) for unit assertions."""
    final_headers = dict(headers or {})
    if content_type is not None:
        final_headers["content-type"] = content_type
    if json_body is not None:
        return httpx.Response(status, json=json_body, headers=final_headers)
    return httpx.Response(status, text=text or "", headers=final_headers)


def _patch_async_client(monkeypatch, handler):
    """Reroute every httpx.AsyncClient(...) constructed inside proxy through
    a MockTransport so we can inspect requests / shape responses."""
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return real_async_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(proxy_mod.httpx, "AsyncClient", factory)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def test_normalize_server_name_strips_separators_and_lowercases():
    assert normalize_server_name("Rag-Home") == "raghome"
    assert normalize_server_name("My_Server") == "myserver"
    assert normalize_server_name("WhatsApp Bot") == "whatsappbot"


def test_get_auth_headers_none_includes_only_content_negotiation():
    headers = get_auth_headers({"auth_type": "none"})
    assert headers["Content-Type"] == "application/json"
    assert "Authorization" not in headers


def test_get_auth_headers_bearer():
    headers = get_auth_headers({"auth_type": "bearer", "auth_token": "tok"})
    assert headers["Authorization"] == "Bearer tok"


def test_get_auth_headers_basic():
    headers = get_auth_headers({"auth_type": "basic", "auth_token": "Zm9v"})
    assert headers["Authorization"] == "Basic Zm9v"


def test_get_auth_headers_bearer_without_token_omits_authorization():
    headers = get_auth_headers({"auth_type": "bearer", "auth_token": None})
    assert "Authorization" not in headers


def test_parse_sse_response_application_json_fast_path():
    resp = _make_response(
        json_body={"jsonrpc": "2.0", "result": {"ok": True}}, content_type="application/json"
    )
    assert parse_sse_response(resp) == {"jsonrpc": "2.0", "result": {"ok": True}}


def test_parse_sse_response_returns_last_jsonrpc_message_in_sse():
    text = (
        'data: {"jsonrpc":"2.0","id":1,"result":{"first":true}}\n'
        "\n"
        'data: {"jsonrpc":"2.0","id":2,"result":{"second":true}}\n'
        "\n"
    )
    resp = _make_response(text=text, content_type="text/event-stream")
    out = parse_sse_response(resp)
    assert out == {"jsonrpc": "2.0", "id": 2, "result": {"second": True}}


def test_parse_sse_response_returns_last_non_jsonrpc_data_message():
    """If the SSE stream has only non-RPC `data:` lines (no `result`/`error`)
    the helper falls back to the last decoded JSON message."""
    text = 'data: {"hello":"world"}\n\n'
    resp = _make_response(text=text, content_type="text/event-stream")
    assert parse_sse_response(resp) == {"hello": "world"}


def test_parse_sse_response_raises_when_no_message_in_sse():
    resp = _make_response(text="event: ping\ndata:\n\n", content_type="text/event-stream")
    with pytest.raises(ValueError, match="No valid JSON-RPC message"):
        parse_sse_response(resp)


def test_parse_sse_response_skips_invalid_json_lines():
    text = 'data: not-json\n\ndata: {"jsonrpc":"2.0","result":{}}\n\n'
    resp = _make_response(text=text, content_type="text/event-stream")
    assert parse_sse_response(resp) == {"jsonrpc": "2.0", "result": {}}


def test_parse_sse_response_unknown_content_type_falls_back_to_json():
    resp = _make_response(json_body={"ok": 1}, content_type="application/octet-stream")
    assert parse_sse_response(resp) == {"ok": 1}


def test_parse_sse_response_unknown_content_type_with_garbage_raises():
    resp = _make_response(text="not-json-at-all", content_type="application/octet-stream")
    with pytest.raises(ValueError, match="Unexpected content-type"):
        parse_sse_response(resp)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_client_creates_and_reuses_then_close_clears(db_path):
    proxy = McpProxy(db_path)
    c1 = await proxy._get_client()
    c2 = await proxy._get_client()
    assert c1 is c2
    await proxy.close()
    assert proxy._http_client is None


@pytest.mark.asyncio
async def test_close_is_safe_when_no_client(db_path):
    proxy = McpProxy(db_path)
    await proxy.close()  # must not raise


@pytest.mark.asyncio
async def test_close_recreates_client_after_close(db_path):
    proxy = McpProxy(db_path)
    c1 = await proxy._get_client()
    await proxy.close()
    c2 = await proxy._get_client()
    assert c1 is not c2


# ---------------------------------------------------------------------------
# Simple synchronous helpers
# ---------------------------------------------------------------------------


def test_invalidate_cache_for_specific_server(db_path):
    proxy = McpProxy(db_path)
    proxy._tools_cache[1] = [{"name": "a"}]
    proxy._resources_cache[1] = [{"uri": "u"}]
    proxy._prompts_cache[1] = [{"name": "p"}]
    proxy._capabilities_cache[1] = {"tools": {}}
    proxy._session_ids[1] = "sess-1"
    proxy._tools_cache[2] = [{"name": "keep"}]

    proxy.invalidate_cache(1)

    assert 1 not in proxy._tools_cache
    assert 1 not in proxy._resources_cache
    assert 1 not in proxy._prompts_cache
    assert 1 not in proxy._capabilities_cache
    assert 1 not in proxy._session_ids
    assert proxy._tools_cache[2] == [{"name": "keep"}]


def test_invalidate_cache_clears_all_when_no_id(db_path):
    proxy = McpProxy(db_path)
    proxy._tools_cache[1] = [{"name": "a"}]
    proxy._tools_cache[2] = [{"name": "b"}]
    proxy._capabilities_cache[1] = {"tools": {}}
    proxy._session_ids[1] = "sess-1"

    proxy.invalidate_cache()

    assert proxy._tools_cache == {}
    assert proxy._capabilities_cache == {}
    assert proxy._session_ids == {}


def test_is_cache_valid_false_when_no_timestamp(db_path):
    proxy = McpProxy(db_path)
    assert proxy._is_cache_valid(1) is False


def test_is_cache_valid_true_after_update(db_path):
    proxy = McpProxy(db_path)
    proxy._update_cache_timestamp(7)
    assert proxy._is_cache_valid(7) is True


def test_dedup_cache_get_returns_none_for_missing_key(db_path):
    proxy = McpProxy(db_path)
    assert proxy._get_dedup_cached("missing") is None


def test_dedup_cache_set_then_get_returns_value(db_path):
    proxy = McpProxy(db_path)
    proxy._set_dedup_cache("k", {"result": {"ok": True}})
    assert proxy._get_dedup_cached("k") == {"result": {"ok": True}}


def test_dedup_cache_get_evicts_expired_entry(db_path):
    proxy = McpProxy(db_path)
    proxy._dedup_ttl_seconds = 0
    proxy._set_dedup_cache("k", {"result": {"ok": True}})
    # Force a tiny gap so `now - ts > 0` is true.
    proxy._dedup_cache["k"] = (time.time() - 1, {"result": {"ok": True}})
    assert proxy._get_dedup_cached("k") is None
    assert "k" not in proxy._dedup_cache


def test_is_success_result_handles_isError_states(db_path):
    proxy = McpProxy(db_path)
    assert proxy._is_success_result({"result": {"isError": False}}) is True
    assert proxy._is_success_result({"result": {"isError": True}}) is False
    assert proxy._is_success_result({"result": {}}) is True
    assert proxy._is_success_result({"error": {"code": -32000}}) is False
    assert proxy._is_success_result({"result": "string-not-dict"}) is False


def test_session_recovery_lock_is_per_server(db_path):
    proxy = McpProxy(db_path)
    a = proxy._get_session_recovery_lock(1)
    b = proxy._get_session_recovery_lock(1)
    c = proxy._get_session_recovery_lock(2)
    assert a is b
    assert a is not c


def test_build_dedup_key_uses_client_request_id(db_path):
    proxy = McpProxy(db_path)
    key = proxy._build_dedup_key({"id": 4}, "any_tool", {"client_request_id": "req-42"})
    assert key == "4:any_tool:req:req-42"


def test_build_dedup_key_returns_none_for_unknown_tool_without_keys(db_path):
    proxy = McpProxy(db_path)
    assert proxy._build_dedup_key({"id": 4}, "search", {"q": "x"}) is None


def test_build_dedup_key_for_send_message_hashes_recipient_and_body(db_path):
    proxy = McpProxy(db_path)
    key = proxy._build_dedup_key(
        {"id": 2},
        "send_message",
        {"recipient_jid": "123@s.whatsapp.net", "message": "hello"},
    )
    assert key is not None
    assert key.startswith("2:send_message:sha256:")


def test_build_dedup_key_send_message_returns_none_without_recipient(db_path):
    proxy = McpProxy(db_path)
    assert proxy._build_dedup_key({"id": 2}, "send_message", {"message": "hi"}) is None


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_tool_via_prefix(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "RAG", "tool_prefix": "rag_"}
    s_b = {"id": 2, "name": "WA", "tool_prefix": "wa_"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])
    routed = await proxy._route_tool_to_server("wa_send_message")
    assert routed == s_b


@pytest.mark.asyncio
async def test_route_tool_via_explicit_mapping(mcp_db, monkeypatch):
    sid_a = store.create_mcp_server(mcp_db, "alpha", "https://a.example/mcp")
    sid_b = store.create_mcp_server(mcp_db, "beta", "https://b.example/mcp")
    store.create_tool_mapping(mcp_db, "weird_tool", sid_b)

    proxy = McpProxy(mcp_db)
    s_a = {"id": sid_a, "name": "alpha", "tool_prefix": None}
    s_b = {"id": sid_b, "name": "beta", "tool_prefix": None}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    routed = await proxy._route_tool_to_server("weird_tool")
    assert routed["id"] == sid_b


@pytest.mark.asyncio
async def test_route_tool_via_auto_discovery_cache(mcp_db, monkeypatch):
    proxy = McpProxy(mcp_db)
    s_a = {"id": 1, "name": "A", "tool_prefix": None}
    s_b = {"id": 2, "name": "B", "tool_prefix": None}
    proxy._tools_cache[2] = [{"name": "magic"}]
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    routed = await proxy._route_tool_to_server("magic")
    assert routed == s_b


@pytest.mark.asyncio
async def test_route_tool_broadcast_when_no_other_strategy_matches(mcp_db, monkeypatch):
    proxy = McpProxy(mcp_db)
    s_a = {"id": 1, "name": "A", "tool_prefix": None}
    s_b = {"id": 2, "name": "B", "tool_prefix": None}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    async def fake_fetch(server):
        if server["id"] == 2:
            return [{"name": "broadcast_tool"}]
        return []

    monkeypatch.setattr(proxy, "_fetch_tools_from_server", fake_fetch)

    routed = await proxy._route_tool_to_server("broadcast_tool")
    assert routed == s_b


@pytest.mark.asyncio
async def test_route_tool_returns_none_when_no_servers(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [])
    assert await proxy._route_tool_to_server("anything") is None


@pytest.mark.asyncio
async def test_route_resource_via_cache(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    proxy._resources_cache[1] = [{"uri": "res://thing"}]
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a])
    assert await proxy._route_resource_to_server("res://thing") == s_a


@pytest.mark.asyncio
async def test_route_resource_via_broadcast(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a])

    async def fake_fetch(server):
        return [{"uri": "res://thing", "_server_id": server["id"]}]

    monkeypatch.setattr(proxy, "_fetch_resources_from_server", fake_fetch)
    assert await proxy._route_resource_to_server("res://thing") == s_a


@pytest.mark.asyncio
async def test_route_resource_returns_none_when_uri_unknown(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a])

    async def fake_fetch(_server):
        return []

    monkeypatch.setattr(proxy, "_fetch_resources_from_server", fake_fetch)
    assert await proxy._route_resource_to_server("res://missing") is None


@pytest.mark.asyncio
async def test_route_prompt_via_cache(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    proxy._prompts_cache[1] = [{"name": "explain"}]
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a])
    assert await proxy._route_prompt_to_server("explain") == s_a


@pytest.mark.asyncio
async def test_route_prompt_via_broadcast(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a])

    async def fake_fetch(_server):
        return [{"name": "explain"}]

    monkeypatch.setattr(proxy, "_fetch_prompts_from_server", fake_fetch)
    assert await proxy._route_prompt_to_server("explain") == s_a


# ---------------------------------------------------------------------------
# Aggregation: get_aggregated_capabilities, list_resources, list_prompts,
# list_resource_templates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_aggregated_capabilities_empty_servers_returns_default(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [])
    caps = await proxy.get_aggregated_capabilities()
    assert caps == {"tools": {}}


@pytest.mark.asyncio
async def test_get_aggregated_capabilities_merges_results(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    s_b = {"id": 2, "name": "B"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    async def fake_fetch(server):
        if server["id"] == 1:
            return {"tools": {}, "resources": {}}
        return {"prompts": {}, "logging": {}}

    monkeypatch.setattr(proxy, "_fetch_capabilities_from_server", fake_fetch)
    caps = await proxy.get_aggregated_capabilities()

    assert "tools" in caps
    assert "resources" in caps
    assert "prompts" in caps
    assert "logging" in caps


@pytest.mark.asyncio
async def test_get_aggregated_capabilities_filters_exceptions(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    s_b = {"id": 2, "name": "B"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    async def fake_fetch(server):
        if server["id"] == 1:
            raise RuntimeError("boom")
        return {"resources": {}}

    monkeypatch.setattr(proxy, "_fetch_capabilities_from_server", fake_fetch)
    caps = await proxy.get_aggregated_capabilities()
    assert "tools" in caps  # always advertised
    assert "resources" in caps


@pytest.mark.asyncio
async def test_list_resources_empty_when_no_servers(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [])
    assert await proxy.list_resources() == []


@pytest.mark.asyncio
async def test_list_resources_filters_baseexception_results(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    s_b = {"id": 2, "name": "B"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    async def fake_fetch(server):
        if server["id"] == 1:
            raise RuntimeError("kaboom")
        return [{"uri": "res://x", "_server_id": 2, "_server_name": "B"}]

    monkeypatch.setattr(proxy, "_fetch_resources_from_server", fake_fetch)
    out = await proxy.list_resources()
    assert len(out) == 1
    assert out[0]["uri"] == "res://x"


@pytest.mark.asyncio
async def test_list_prompts_aggregation_and_filtering(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    s_b = {"id": 2, "name": "B"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    async def fake_fetch(server):
        if server["id"] == 1:
            raise RuntimeError("nope")
        return [{"name": "explain", "_server_id": 2, "_server_name": "B"}]

    monkeypatch.setattr(proxy, "_fetch_prompts_from_server", fake_fetch)
    out = await proxy.list_prompts()
    assert [p["name"] for p in out] == ["explain"]


@pytest.mark.asyncio
async def test_list_prompts_empty_when_no_servers(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [])
    assert await proxy.list_prompts() == []


@pytest.mark.asyncio
async def test_list_resource_templates_aggregation(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    s_b = {"id": 2, "name": "B"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    async def fake_jsonrpc(server, method, params=None, **_):
        assert method == "resources/templates/list"
        if server["id"] == 1:
            return {"result": {"resourceTemplates": [{"uriTemplate": "tpl://a"}]}}
        return {"result": {"resourceTemplates": [{"uriTemplate": "tpl://b"}]}}

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)
    templates = await proxy.list_resource_templates()
    uris = sorted(t["uriTemplate"] for t in templates)
    assert uris == ["tpl://a", "tpl://b"]
    # _server_id was injected by fetch_one
    for t in templates:
        assert "_server_id" in t


@pytest.mark.asyncio
async def test_list_resource_templates_handles_per_server_errors(db_path, monkeypatch):
    """A backend without the resources/templates capability raises an
    httpx-shaped error; the aggregator must fall through to the others."""
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}
    s_b = {"id": 2, "name": "B"}
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a, s_b])

    async def fake_jsonrpc(server, method, params=None, **_):
        if server["id"] == 1:
            raise httpx.HTTPError("Method not found")
        return {"result": {"resourceTemplates": [{"uriTemplate": "tpl://b"}]}}

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)
    templates = await proxy.list_resource_templates()
    assert [t["uriTemplate"] for t in templates] == ["tpl://b"]


@pytest.mark.asyncio
async def test_list_resource_templates_empty_when_no_servers(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [])
    assert await proxy.list_resource_templates() == []


# ---------------------------------------------------------------------------
# read_resource / get_prompt / complete dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_resource_routes_to_owner(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}

    async def fake_route(uri, user_id=None, server_name=None):
        return server

    async def fake_jsonrpc(s, method, params=None, **_):
        assert method == "resources/read"
        assert params == {"uri": "res://x"}
        return {"result": {"contents": []}}

    monkeypatch.setattr(proxy, "_route_resource_to_server", fake_route)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    data, srv = await proxy.read_resource("res://x")
    assert srv == server
    assert data["result"] == {"contents": []}


@pytest.mark.asyncio
async def test_read_resource_raises_when_not_found(db_path, monkeypatch):
    proxy = McpProxy(db_path)

    async def fake_route(*_a, **_kw):
        return None

    monkeypatch.setattr(proxy, "_route_resource_to_server", fake_route)
    with pytest.raises(ResourceNotFoundError):
        await proxy.read_resource("res://missing")


@pytest.mark.asyncio
async def test_get_prompt_routes_to_owner_and_includes_arguments(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}

    captured = {}

    async def fake_route(name, user_id=None, server_name=None):
        return server

    async def fake_jsonrpc(s, method, params=None, **_):
        captured["method"] = method
        captured["params"] = params
        return {"result": {"messages": []}}

    monkeypatch.setattr(proxy, "_route_prompt_to_server", fake_route)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    data, srv = await proxy.get_prompt("explain", arguments={"topic": "x"})
    assert srv == server
    assert data["result"]["messages"] == []
    assert captured["method"] == "prompts/get"
    assert captured["params"] == {"name": "explain", "arguments": {"topic": "x"}}


@pytest.mark.asyncio
async def test_get_prompt_omits_arguments_when_none(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}
    captured = {}

    async def fake_route(*_a, **_kw):
        return server

    async def fake_jsonrpc(_s, _method, params=None, **_):
        captured["params"] = params
        return {"result": {"messages": []}}

    monkeypatch.setattr(proxy, "_route_prompt_to_server", fake_route)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    await proxy.get_prompt("explain")
    assert captured["params"] == {"name": "explain"}


@pytest.mark.asyncio
async def test_get_prompt_raises_when_not_found(db_path, monkeypatch):
    proxy = McpProxy(db_path)

    async def fake_route(*_a, **_kw):
        return None

    monkeypatch.setattr(proxy, "_route_prompt_to_server", fake_route)
    with pytest.raises(PromptNotFoundError):
        await proxy.get_prompt("missing")


@pytest.mark.asyncio
async def test_complete_routes_via_prompt_ref(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}

    async def fake_route_prompt(name, user_id=None, server_name=None):
        assert name == "explain"
        return server

    async def fake_jsonrpc(s, method, params=None, **_):
        assert method == "completion/complete"
        assert params["ref"] == {"type": "ref/prompt", "name": "explain"}
        assert params["argument"] == {"name": "topic", "value": "x"}
        return {"result": {"completion": {"values": []}}}

    monkeypatch.setattr(proxy, "_route_prompt_to_server", fake_route_prompt)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    data, srv = await proxy.complete(
        ref={"type": "ref/prompt", "name": "explain"},
        argument={"name": "topic", "value": "x"},
    )
    assert srv == server
    assert "completion" in data["result"]


@pytest.mark.asyncio
async def test_complete_routes_via_resource_ref(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}

    async def fake_route_resource(uri, user_id=None, server_name=None):
        assert uri == "res://thing"
        return server

    async def fake_jsonrpc(_s, _method, _params=None, **_):
        return {"result": {"completion": {"values": []}}}

    monkeypatch.setattr(proxy, "_route_resource_to_server", fake_route_resource)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    _data, srv = await proxy.complete(
        ref={"type": "ref/resource", "uri": "res://thing"},
        argument={"name": "v", "value": "1"},
    )
    assert srv == server


@pytest.mark.asyncio
async def test_complete_falls_back_to_first_server(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    s_a = {"id": 1, "name": "A"}

    async def fake_route_prompt(*_a, **_kw):
        return None

    async def fake_jsonrpc(_s, _method, _params=None, **_):
        return {"result": {"completion": {"values": []}}}

    monkeypatch.setattr(proxy, "_route_prompt_to_server", fake_route_prompt)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [s_a])
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    _data, srv = await proxy.complete(
        ref={"type": "ref/prompt", "name": "missing"},
        argument={"name": "v", "value": "1"},
    )
    assert srv == s_a


@pytest.mark.asyncio
async def test_complete_raises_when_no_server(db_path, monkeypatch):
    proxy = McpProxy(db_path)

    async def fake_route_prompt(*_a, **_kw):
        return None

    monkeypatch.setattr(proxy, "_route_prompt_to_server", fake_route_prompt)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [])

    with pytest.raises(ResourceNotFoundError):
        await proxy.complete(
            ref={"type": "ref/prompt", "name": "x"},
            argument={"name": "v", "value": "1"},
        )


# ---------------------------------------------------------------------------
# call_tool not-found / list_tools empty
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_tools_empty_when_no_servers(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(proxy, "_get_servers", lambda **_: [])
    assert await proxy.list_tools() == []


@pytest.mark.asyncio
async def test_call_tool_raises_tool_not_found(db_path, monkeypatch):
    proxy = McpProxy(db_path)

    async def fake_route(*_a, **_kw):
        return None

    monkeypatch.setattr(proxy, "_route_tool_to_server", fake_route)
    with pytest.raises(ToolNotFoundError):
        await proxy.call_tool("ghost_tool")


# ---------------------------------------------------------------------------
# _proxy_jsonrpc — HTTP path via httpx.MockTransport
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_jsonrpc_happy_path_returns_parsed_result(db_path, monkeypatch):
    """200 application/json → parse_sse_response returns the body verbatim."""
    proxy = McpProxy(db_path)
    server = {
        "id": 1,
        "name": "good",
        "url": "https://good.example/mcp",
        "auth_type": "none",
        "refresh_token_hash": None,
    }

    received_headers: list = []

    def handler(request):
        received_headers.append(dict(request.headers))
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
            headers={"content-type": "application/json"},
        )

    _patch_async_client(monkeypatch, handler)

    data = await proxy._proxy_jsonrpc(server, "tools/list")
    assert data == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert received_headers[0]["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_proxy_jsonrpc_captures_session_id_from_response_header(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {
        "id": 1,
        "name": "good",
        "url": "https://good.example/mcp",
        "auth_type": "none",
        "refresh_token_hash": None,
    }

    def handler(_request):
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {}},
            headers={
                "content-type": "application/json",
                "mcp-session-id": "captured-sess",
            },
        )

    _patch_async_client(monkeypatch, handler)

    await proxy._proxy_jsonrpc(server, "tools/list")
    assert proxy._session_ids[1] == "captured-sess"


@pytest.mark.asyncio
async def test_proxy_jsonrpc_400_session_recovery_reinitializes_and_retries(db_path, monkeypatch):
    """First call (with stale session id) returns 400 'no session'. The
    proxy clears state, calls _fetch_capabilities_from_server (mocked to
    install a new session id), then retries the original call."""
    proxy = McpProxy(db_path)
    server = {
        "id": 1,
        "name": "good",
        "url": "https://good.example/mcp",
        "auth_type": "none",
        "refresh_token_hash": None,
    }
    proxy._session_ids[1] = "stale-sess"

    state = {"call": 0}

    def handler(request):
        state["call"] += 1
        # First request — backend rejects stale session.
        if state["call"] == 1:
            return httpx.Response(
                400,
                text="No valid session id",
                headers={"content-type": "text/plain"},
            )
        # Retry uses the freshly-installed session.
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
            headers={"content-type": "application/json"},
        )

    _patch_async_client(monkeypatch, handler)

    async def fake_fetch_caps(srv):
        proxy._session_ids[srv["id"]] = "fresh-sess"
        proxy._capabilities_cache[srv["id"]] = {"tools": {}}
        return proxy._capabilities_cache[srv["id"]]

    async def fake_fetch_tools(_srv):
        return []

    monkeypatch.setattr(proxy, "_fetch_capabilities_from_server", fake_fetch_caps)
    monkeypatch.setattr(proxy, "_fetch_tools_from_server", fake_fetch_tools)

    data = await proxy._proxy_jsonrpc(server, "tools/call", {"name": "x"})
    assert data["result"]["ok"] is True
    assert proxy._session_ids[1] == "fresh-sess"
    assert state["call"] == 2  # original 400 + retry


@pytest.mark.asyncio
async def test_proxy_jsonrpc_404_session_recovery_reinitializes_and_retries(db_path, monkeypatch):
    """Per MCP spec a backend that terminated a session answers requests
    carrying that session id with 404. The proxy must treat that like the
    400 case: drop the stale state, re-initialize, retry the original call."""
    proxy = McpProxy(db_path)
    server = {
        "id": 1,
        "name": "good",
        "url": "https://good.example/mcp",
        "auth_type": "none",
        "refresh_token_hash": None,
    }
    proxy._session_ids[1] = "stale-sess"

    state = {"call": 0}

    def handler(request):
        state["call"] += 1
        # First request — backend no longer knows this session.
        if state["call"] == 1:
            return httpx.Response(
                404,
                text="Session not found",
                headers={"content-type": "text/plain"},
            )
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
            headers={"content-type": "application/json"},
        )

    _patch_async_client(monkeypatch, handler)

    async def fake_fetch_caps(srv):
        proxy._session_ids[srv["id"]] = "fresh-sess"
        proxy._capabilities_cache[srv["id"]] = {"tools": {}}
        return proxy._capabilities_cache[srv["id"]]

    async def fake_fetch_tools(_srv):
        return []

    monkeypatch.setattr(proxy, "_fetch_capabilities_from_server", fake_fetch_caps)
    monkeypatch.setattr(proxy, "_fetch_tools_from_server", fake_fetch_tools)

    data = await proxy._proxy_jsonrpc(server, "tools/call", {"name": "x"})
    assert data["result"]["ok"] is True
    assert proxy._session_ids[1] == "fresh-sess"
    assert state["call"] == 2  # original 404 + retry


@pytest.mark.asyncio
async def test_proxy_jsonrpc_404_without_session_does_not_reinitialize(db_path, monkeypatch):
    """A 404 on a request that carried no Mcp-Session-Id is a routing error
    ("endpoint not found"), not an expired session — no re-initialize, the
    HTTP error surfaces to the caller."""
    proxy = McpProxy(db_path)
    server = {
        "id": 1,
        "name": "wrong-path",
        "url": "https://good.example/nope",
        "auth_type": "none",
        "refresh_token_hash": None,
    }
    # No session id cached for this server.

    state = {"call": 0, "caps": 0}

    def handler(_request):
        state["call"] += 1
        return httpx.Response(
            404,
            text="Not Found",
            headers={"content-type": "text/plain"},
        )

    _patch_async_client(monkeypatch, handler)

    async def fake_fetch_caps(srv):
        state["caps"] += 1
        return {}

    monkeypatch.setattr(proxy, "_fetch_capabilities_from_server", fake_fetch_caps)

    with pytest.raises(httpx.HTTPStatusError):
        await proxy._proxy_jsonrpc(server, "tools/call", {"name": "x"})

    assert state["call"] == 1  # no retry
    assert state["caps"] == 0  # no re-initialize attempt


@pytest.mark.asyncio
async def test_proxy_jsonrpc_401_triggers_refresh_and_retries(mcp_db, monkeypatch):
    """401 on a server with refresh_token_hash → call into token_manager,
    re-read server row from DB, retry once with the (now refreshed) token."""
    sid = store.create_mcp_server(
        mcp_db,
        "needs",
        "https://needs.example/mcp",
        auth_type="bearer",
        auth_token="old-token",
    )
    store.update_mcp_server(mcp_db, sid, refresh_token_hash="hash-fake")
    server = store.get_mcp_server(mcp_db, sid)

    state = {"call": 0}

    def handler(request):
        state["call"] += 1
        if state["call"] == 1:
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
            headers={"content-type": "application/json"},
        )

    _patch_async_client(monkeypatch, handler)

    class _StubTokenMgr:
        async def refresh_server_token(self, _server_id, triggered_by="manual"):
            return True, None

    monkeypatch.setattr(
        "authmcp_gateway.mcp.token_manager.get_token_manager",
        lambda: _StubTokenMgr(),
    )

    proxy = McpProxy(mcp_db)
    data = await proxy._proxy_jsonrpc(server, "tools/list")
    assert data["result"]["ok"] is True
    assert state["call"] == 2  # 401 + retry


@pytest.mark.asyncio
async def test_proxy_jsonrpc_raises_for_unrelated_4xx(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {
        "id": 1,
        "name": "x",
        "url": "https://x.example/mcp",
        "auth_type": "none",
        "refresh_token_hash": None,
    }

    def handler(_request):
        return httpx.Response(403, text="forbidden")

    _patch_async_client(monkeypatch, handler)

    with pytest.raises(httpx.HTTPStatusError):
        await proxy._proxy_jsonrpc(server, "tools/list")


@pytest.mark.asyncio
async def test_proxy_jsonrpc_propagates_timeout_when_no_session_to_recover(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {
        "id": 1,
        "name": "x",
        "url": "https://x.example/mcp",
        "auth_type": "none",
        "refresh_token_hash": None,
    }

    def handler(_request):
        raise httpx.TimeoutException("read timeout")

    _patch_async_client(monkeypatch, handler)

    with pytest.raises(httpx.TimeoutException):
        await proxy._proxy_jsonrpc(server, "tools/list")


# ---------------------------------------------------------------------------
# _fetch_tools_from_server: cache + happy path + http error → DB update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_tools_returns_cached_when_fresh(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}
    proxy._tools_cache[1] = [{"name": "cached"}]
    proxy._update_cache_timestamp(1)

    called = False

    async def fake_jsonrpc(*_a, **_kw):
        nonlocal called
        called = True
        return {"result": {"tools": []}}

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    out = await proxy._fetch_tools_from_server(server)
    assert out == [{"name": "cached"}]
    assert called is False  # cache hit avoided network


@pytest.mark.asyncio
async def test_fetch_tools_handles_invalid_response_shape(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 99, "name": "weird"}

    async def fake_ensure(_s):
        return None

    async def fake_jsonrpc(*_a, **_kw):
        return {"result": {}}  # no "tools" key — falls into the warning branch

    monkeypatch.setattr(proxy, "_ensure_session", fake_ensure)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    # Returns [] without touching the DB (no update_server_health call here).
    assert await proxy._fetch_tools_from_server(server) == []


@pytest.mark.asyncio
async def test_fetch_tools_http_error_marks_server_error(mcp_db, monkeypatch):
    sid = store.create_mcp_server(mcp_db, "bad", "https://bad.example/mcp")
    server = store.get_mcp_server(mcp_db, sid)

    proxy = McpProxy(mcp_db)

    async def fake_ensure(_s):
        return None

    async def fake_jsonrpc(*_a, **_kw):
        raise httpx.HTTPError("boom")

    monkeypatch.setattr(proxy, "_ensure_session", fake_ensure)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    out = await proxy._fetch_tools_from_server(server)
    assert out == []
    refreshed = store.get_mcp_server(mcp_db, sid)
    assert refreshed["status"] == "error"


# ---------------------------------------------------------------------------
# _fetch_prompts_from_server / _fetch_resources_from_server cached paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_prompts_returns_cached_when_fresh(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}
    proxy._prompts_cache[1] = [{"name": "cached_p"}]
    proxy._update_cache_timestamp(1)

    async def fake_jsonrpc(*_a, **_kw):
        raise AssertionError("should not be called")

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)
    out = await proxy._fetch_prompts_from_server(server)
    assert out == [{"name": "cached_p"}]


@pytest.mark.asyncio
async def test_fetch_resources_returns_cached_when_fresh(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}
    proxy._resources_cache[1] = [{"uri": "res://cached"}]
    proxy._update_cache_timestamp(1)

    async def fake_jsonrpc(*_a, **_kw):
        raise AssertionError("should not be called")

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)
    out = await proxy._fetch_resources_from_server(server)
    assert out == [{"uri": "res://cached"}]


@pytest.mark.asyncio
async def test_fetch_prompts_swallows_method_not_found(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "A"}

    async def fake_ensure(_s):
        return None

    async def fake_jsonrpc(*_a, **_kw):
        raise httpx.HTTPError("Method not found")

    monkeypatch.setattr(proxy, "_ensure_session", fake_ensure)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    assert await proxy._fetch_prompts_from_server(server) == []


# ---------------------------------------------------------------------------
# call_tool — dedup hit / inflight
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_tool_returns_dedup_cache_hit_without_calling_backend(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "WA", "tool_prefix": "wa_"}
    proxy._tools_cache[1] = [
        {
            "name": "send_message",
            "inputSchema": {},
            "annotations": {"idempotentHint": True, "readOnlyHint": False},
        }
    ]

    async def fake_route(*_a, **_kw):
        return server

    backend_called = False

    async def fake_jsonrpc(*_a, **_kw):
        nonlocal backend_called
        backend_called = True
        return {"result": {"ok": True}}

    monkeypatch.setattr(proxy, "_route_tool_to_server", fake_route)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    # Pre-populate dedup cache for the explicit idempotency key.
    proxy._set_dedup_cache(
        "1:wa_send_message:idem:k-7", {"result": {"content": [{"x": 1}], "isError": False}}
    )

    args = {"idempotency_key": "k-7", "recipient_jid": "x", "message": "hi"}
    data, srv = await proxy.call_tool("wa_send_message", args)

    assert backend_called is False
    assert srv == server
    assert data["result"]["_meta"]["tool_name"] == "wa_send_message"


@pytest.mark.asyncio
async def test_call_tool_inflight_dedup_lets_second_caller_await_first(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "WA", "tool_prefix": "wa_"}
    proxy._tools_cache[1] = [
        {
            "name": "send_message",
            "inputSchema": {},
            "annotations": {"idempotentHint": True, "readOnlyHint": False},
        }
    ]

    async def fake_route(*_a, **_kw):
        return server

    proceed = asyncio.Event()
    seen_calls = {"n": 0}

    async def fake_jsonrpc(*_a, **_kw):
        seen_calls["n"] += 1
        await proceed.wait()
        return {"result": {"content": [{"y": 2}], "isError": False}}

    monkeypatch.setattr(proxy, "_route_tool_to_server", fake_route)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_jsonrpc)

    args = {"idempotency_key": "k-9", "recipient_jid": "x", "message": "hi"}

    task1 = asyncio.create_task(proxy.call_tool("wa_send_message", dict(args)))
    # Yield so task1 reaches _proxy_jsonrpc and registers an inflight future.
    await asyncio.sleep(0.05)
    task2 = asyncio.create_task(proxy.call_tool("wa_send_message", dict(args)))
    await asyncio.sleep(0.05)

    proceed.set()
    (data1, _), (data2, _) = await asyncio.gather(task1, task2)

    # Only the first task hit the backend.
    assert seen_calls["n"] == 1
    # Both got a result with gateway metadata; data2 went through inflight path.
    assert data1["result"]["_meta"]["tool_name"] == "wa_send_message"
    assert data2["result"]["_meta"]["tool_name"] == "wa_send_message"
