import logging

import pytest

from authmcp_gateway.mcp import token_manager as tm


@pytest.mark.asyncio
async def test_refresh_logs_invalid_expires_at(caplog, monkeypatch):
    manager = tm.TokenManager(db_path=":memory:")

    server = {
        "id": 1,
        "name": "TestServer",
        "url": "http://example.com/mcp",
        "refresh_token_hash": "hash",
        "token_expires_at": "bad-date",
        "refresh_endpoint": "/oauth/token",
    }

    monkeypatch.setattr(tm, "get_mcp_server", lambda db_path, server_id: server)
    monkeypatch.setattr(tm, "update_mcp_server_token", lambda *args, **kwargs: None)
    monkeypatch.setattr(tm, "log_token_audit", lambda *args, **kwargs: None)

    async def _fake_call_token_endpoint(self, token_url, refresh_token):
        return "access-token", None, 60

    monkeypatch.setattr(tm.TokenManager, "_call_token_endpoint", _fake_call_token_endpoint)

    manager.cache_refresh_token(1, "refresh-token")

    caplog.set_level(logging.DEBUG)
    success, error = await manager.refresh_server_token(1, triggered_by="test")

    assert success is True
    assert error is None
    assert "Invalid token_expires_at format" in caplog.text
