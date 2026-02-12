import json

import pytest
from starlette.requests import Request

from authmcp_gateway.mcp.handler import McpHandler


def _make_request() -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_tool_call_logs_backend_error(monkeypatch):
    handler = McpHandler(db_path=":memory:")

    class DummyProxy:
        async def call_tool(self, tool_name, arguments, user_id, server_name=None):
            return {"error": {"code": -32000, "message": "backend failed"}}

    handler.proxy = DummyProxy()

    logged = {}

    def fake_log_mcp_request(**kwargs):
        logged.update(kwargs)

    monkeypatch.setattr(
        "authmcp_gateway.security.logger.log_mcp_request",
        fake_log_mcp_request
    )

    response = await handler._handle_tool_call(
        jsonrpc_id=1,
        tool_name="bad_tool",
        arguments={},
        user_id=123,
        server_name=None,
        request=_make_request()
    )

    body = json.loads(response.body.decode("utf-8"))
    assert "error" in body
    assert logged.get("success") is False
    assert "backend failed" in (logged.get("error_message") or "")
