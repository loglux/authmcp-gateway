"""Tests for security event logging and MCP request stats."""

import json

from authmcp_gateway.db import get_db
from authmcp_gateway.security.logger import (
    cleanup_old_logs,
    get_mcp_request_stats,
    get_security_events,
    log_security_event,
)


def _create_tables(db_path):
    """Create required tables for security logger tests."""
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                severity TEXT,
                details TEXT,
                user_id INTEGER,
                username TEXT,
                ip_address TEXT,
                endpoint TEXT,
                method TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                user_id INTEGER,
                mcp_server_id INTEGER,
                method TEXT,
                tool_name TEXT,
                success INTEGER,
                error_message TEXT,
                response_time_ms INTEGER,
                ip_address TEXT,
                is_suspicious INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                user_id INTEGER,
                action TEXT
            )
        """)


def test_create_tables(db_path):
    """Security + MCP tables created without error."""
    _create_tables(db_path)
    with get_db(db_path, row_factory=None) as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        names = {t[0] for t in tables}
        assert "security_events" in names
        assert "mcp_requests" in names


def test_log_security_event(db_path):
    """Event stored with all fields."""
    _create_tables(db_path)
    log_security_event(
        db_path=db_path,
        event_type="unauthorized_access",
        severity="medium",
        details={"reason": "no token"},
        user_id=1,
        username="alice",
        ip_address="10.0.0.1",
        endpoint="/mcp",
        method="POST",
    )
    with get_db(db_path) as conn:
        row = conn.execute("SELECT * FROM security_events LIMIT 1").fetchone()
        assert row is not None
        assert row["event_type"] == "unauthorized_access"
        assert row["severity"] == "medium"
        assert row["ip_address"] == "10.0.0.1"
        parsed = json.loads(row["details"])
        assert parsed["reason"] == "no token"


def test_get_security_events(db_path):
    """Events retrieved correctly."""
    _create_tables(db_path)
    for i in range(3):
        log_security_event(
            db_path=db_path,
            event_type="test_event",
            severity="low",
            ip_address=f"10.0.0.{i}",
        )
    events = get_security_events(db_path)
    assert len(events) == 3


def test_get_security_events_severity_filter(db_path):
    """Severity filter works."""
    _create_tables(db_path)
    log_security_event(db_path=db_path, event_type="a", severity="low")
    log_security_event(db_path=db_path, event_type="b", severity="high")
    log_security_event(db_path=db_path, event_type="c", severity="low")

    high_events = get_security_events(db_path, severity="high")
    assert len(high_events) == 1
    assert high_events[0]["event_type"] == "b"


def test_get_mcp_request_stats(db_path):
    """Aggregation returns correct counts."""
    _create_tables(db_path)
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path, row_factory=None) as conn:
        # 2 successful, 1 failed
        conn.execute(
            "INSERT INTO mcp_requests (timestamp, method, success, response_time_ms) "
            "VALUES (?, ?, ?, ?)",
            (now, "tools/list", 1, 50),
        )
        conn.execute(
            "INSERT INTO mcp_requests (timestamp, method, success, response_time_ms) "
            "VALUES (?, ?, ?, ?)",
            (now, "tools/call", 1, 100),
        )
        conn.execute(
            "INSERT INTO mcp_requests (timestamp, method, success, response_time_ms) "
            "VALUES (?, ?, ?, ?)",
            (now, "tools/call", 0, 200),
        )

    stats = get_mcp_request_stats(db_path, last_hours=1)
    assert stats["total_requests"] == 3
    assert stats["successful_requests"] == 2
    assert stats["failed_requests"] == 1
    assert stats["success_rate"] == round(2 / 3 * 100, 2)
    assert stats["by_server"] == {"Unknown": 3}


def test_get_mcp_request_stats_by_server(db_path):
    """by_server groups request counts per backend server name."""
    _create_tables(db_path)
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("INSERT INTO mcp_servers (id, name) VALUES (1, 'GitHub Tools')")
        conn.execute("INSERT INTO mcp_servers (id, name) VALUES (2, 'Knowledge Base')")
        conn.execute(
            "INSERT INTO mcp_requests (timestamp, mcp_server_id, method, success) "
            "VALUES (?, 1, 'tools/call', 1)",
            (now,),
        )
        conn.execute(
            "INSERT INTO mcp_requests (timestamp, mcp_server_id, method, success) "
            "VALUES (?, 2, 'tools/call', 1)",
            (now,),
        )
        conn.execute(
            "INSERT INTO mcp_requests (timestamp, mcp_server_id, method, success) "
            "VALUES (?, 2, 'tools/call', 1)",
            (now,),
        )

    stats = get_mcp_request_stats(db_path, last_hours=1)
    assert stats["by_server"] == {"GitHub Tools": 1, "Knowledge Base": 2}


def test_cleanup_archives(db_path, tmp_path, monkeypatch):
    """Old rows deleted and archived to JSONL."""
    _create_tables(db_path)
    archive_file = tmp_path / "archive.jsonl"

    # Insert old rows
    old_ts = "2000-01-01T00:00:00+00:00"
    with get_db(db_path, row_factory=None) as conn:
        conn.execute(
            "INSERT INTO security_events (timestamp, event_type, severity) VALUES (?, ?, ?)",
            (old_ts, "old_event", "low"),
        )
        conn.execute(
            "INSERT INTO mcp_requests (timestamp, method, success) VALUES (?, ?, ?)",
            (old_ts, "tools/list", 1),
        )
        conn.execute(
            "INSERT INTO auth_audit_log (timestamp, user_id, action) VALUES (?, ?, ?)",
            (old_ts, 1, "login"),
        )

    class _FakeConfig:
        mcp_log_db_archive_enabled = True
        mcp_log_db_archive_path = str(archive_file)

    # cleanup_old_logs does `from authmcp_gateway.config import get_config` locally
    import authmcp_gateway.config

    monkeypatch.setattr(authmcp_gateway.config, "get_config", lambda: _FakeConfig())

    result = cleanup_old_logs(db_path, days_to_keep=1)
    assert result["security_events"] == 1
    assert result["mcp_requests"] == 1
    assert result["auth_audit_log"] == 1

    # Verify archive file
    assert archive_file.exists()
    lines = archive_file.read_text().splitlines()
    assert len(lines) == 3
    for line in lines:
        payload = json.loads(line)
        assert "table" in payload
        assert "row" in payload
