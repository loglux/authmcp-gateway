import json
import sqlite3
from pathlib import Path

from authmcp_gateway.security import logger as sec_logger


def _create_tables(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute(
        """
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
        """
    )
    cur.execute(
        """
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
            is_suspicious INTEGER
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id INTEGER,
            action TEXT
        )
        """
    )
    conn.commit()


def _insert_old_rows(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    old_ts = "2000-01-01T00:00:00+00:00"
    cur.execute(
        "INSERT INTO security_events (timestamp, event_type, severity) VALUES (?, ?, ?)",
        (old_ts, "test", "low"),
    )
    cur.execute(
        "INSERT INTO mcp_requests (timestamp, method, success) VALUES (?, ?, ?)",
        (old_ts, "tools/list", 1),
    )
    cur.execute(
        "INSERT INTO auth_audit_log (timestamp, user_id, action) VALUES (?, ?, ?)",
        (old_ts, 1, "login"),
    )
    conn.commit()


def test_cleanup_archives_old_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "logs.db"
    archive_path = tmp_path / "archive.jsonl"

    conn = sqlite3.connect(db_path)
    _create_tables(conn)
    _insert_old_rows(conn)
    conn.close()

    class _DummyConfig:
        mcp_log_db_archive_enabled = True
        mcp_log_db_archive_path = str(archive_path)

    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: _DummyConfig())

    result = sec_logger.cleanup_old_logs(str(db_path), days_to_keep=1)

    assert result["security_events"] == 1
    assert result["mcp_requests"] == 1
    assert result["auth_audit_log"] == 1
    assert archive_path.exists()

    lines = archive_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    for line in lines:
        payload = json.loads(line)
        assert "table" in payload
        assert "row" in payload
