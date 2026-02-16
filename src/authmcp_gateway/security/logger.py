"""Security and MCP request logging functions."""

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_last_mcp_db_check_ts = 0.0


def log_security_event(
    db_path: str,
    event_type: str,
    severity: str,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    endpoint: Optional[str] = None,
    method: Optional[str] = None,
) -> None:
    """Log security-related event.

    Args:
        db_path: Path to SQLite database
        event_type: Type of security event (unauthorized_access, rate_limited,
                   suspicious_payload, auth_failed, etc.)
        severity: Severity level (low, medium, high, critical)
        details: Optional dictionary with additional context (will be JSON-encoded)
        user_id: Optional user ID
        username: Optional username
        ip_address: Optional IP address
        endpoint: Optional endpoint path
        method: Optional HTTP method
    """
    try:
        import json

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO security_events (
                event_type, severity, user_id, username, ip_address,
                endpoint, method, details, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                severity,
                user_id,
                username,
                ip_address,
                endpoint,
                method,
                json.dumps(details) if details else None,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        conn.commit()
        conn.close()

        logger.info(
            f"Security event logged: {event_type} (severity={severity}, "
            f"user={username or 'N/A'}, ip={ip_address or 'N/A'})"
        )

    except Exception as e:
        logger.error(f"Failed to log security event: {e}")


def log_mcp_request(
    db_path: str,
    user_id: Optional[int],
    mcp_server_id: Optional[int],
    method: str,
    tool_name: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    response_time_ms: Optional[int] = None,
    ip_address: Optional[str] = None,
    is_suspicious: bool = False,
) -> None:
    """Log MCP request to file.

    Args:
        db_path: Path to SQLite database (ignored, kept for compatibility)
        user_id: User ID making the request
        mcp_server_id: MCP server ID (if applicable)
        method: MCP method (tools/list, tools/call, initialize)
        tool_name: Tool name (if tools/call)
        success: Whether request succeeded
        error_message: Error message (if failed)
        response_time_ms: Response time in milliseconds
        ip_address: Client IP address
        is_suspicious: Whether request was flagged as suspicious
    """
    try:
        from authmcp_gateway.config import get_config
        from authmcp_gateway.logging_config import get_mcp_logger, log_mcp_request_to_file

        # Get username and server_name from database
        username = None
        server_name = None

        if user_id or mcp_server_id:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            if user_id:
                cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                row = cursor.fetchone()
                if row:
                    username = row[0]

            if mcp_server_id:
                cursor.execute("SELECT name FROM mcp_servers WHERE id = ?", (mcp_server_id,))
                row = cursor.fetchone()
                if row:
                    server_name = row[0]

            conn.close()

        # Log to file (default, low overhead)
        mcp_logger = get_mcp_logger()
        log_mcp_request_to_file(
            logger=mcp_logger,
            method=method,
            server_id=mcp_server_id,
            server_name=server_name,
            user_id=user_id,
            username=username,
            tool_name=tool_name,
            response_time_ms=response_time_ms,
            success=success,
            error=error_message,
            suspicious=is_suspicious,
        )

        config = get_config()

        # Optional DB logging for MCP requests (future internal storage)
        if getattr(config, "mcp_log_db_enabled", False):
            conn_db = sqlite3.connect(db_path)
            cursor_db = conn_db.cursor()
            cursor_db.execute(
                """
                INSERT INTO mcp_requests (
                    user_id, mcp_server_id, method, tool_name, success,
                    error_message, response_time_ms, ip_address, is_suspicious
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    mcp_server_id,
                    method,
                    tool_name,
                    success,
                    error_message,
                    response_time_ms,
                    ip_address,
                    is_suspicious,
                ),
            )
            conn_db.commit()
            conn_db.close()

        # Optional DB size/row checks (best-effort)
        if getattr(config, "mcp_log_db_enabled", False):
            global _last_mcp_db_check_ts
            now = time.time()
            interval = max(1, int(getattr(config, "mcp_log_db_check_interval_seconds", 300)))
            if now - _last_mcp_db_check_ts >= interval:
                _last_mcp_db_check_ts = now
                try:
                    conn_check = sqlite3.connect(db_path)
                    cur = conn_check.cursor()
                    cur.execute("PRAGMA page_count")
                    page_count = cur.fetchone()[0]
                    cur.execute("PRAGMA page_size")
                    page_size = cur.fetchone()[0]
                    db_mb = (page_count * page_size) / (1024 * 1024)
                    cur.execute("SELECT COUNT(*) FROM mcp_requests")
                    mcp_rows = cur.fetchone()[0]
                    conn_check.close()

                    max_mb = getattr(config, "mcp_log_db_max_mb", 200)
                    max_rows = getattr(config, "mcp_log_db_max_rows", 200000)
                    if db_mb > max_mb or mcp_rows > max_rows:
                        days = getattr(config, "mcp_log_db_days_to_keep", 30)
                        logger.warning(
                            f"MCP log DB limits exceeded (size={db_mb:.1f}MB rows={mcp_rows}); "
                            f"running cleanup with days_to_keep={days}"
                        )
                        cleanup_old_logs(db_path, days_to_keep=days)
                except Exception as e:
                    logger.debug(f"MCP DB size check failed: {e}")

        logger.debug(
            f"MCP request logged: {method} (tool={tool_name or 'N/A'}, "
            f"success={success}, time={response_time_ms}ms)"
        )

    except Exception as e:
        logger.error(f"Failed to log MCP request: {e}")


def cleanup_old_logs(db_path: str, days_to_keep: int = 30) -> Dict[str, int]:
    """Delete logs older than specified number of days.

    Args:
        db_path: Path to SQLite database
        days_to_keep: Number of days to keep logs (default: 30)

    Returns:
        Dictionary with counts of deleted records per table
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days_to_keep)).isoformat()

        # Optional archive to file before deletion
        from authmcp_gateway.config import get_config

        config = get_config()
        archive_path = getattr(config, "mcp_log_db_archive_path", None)
        archive_enabled = getattr(config, "mcp_log_db_archive_enabled", False)

        ALLOWED_TABLES = {"security_events", "mcp_requests", "auth_audit_log"}

        def _archive_table(table_name: str) -> int:
            if not (archive_enabled and archive_path):
                return 0
            if table_name not in ALLOWED_TABLES:
                logger.error(f"Rejected invalid table name in cleanup: {table_name}")
                return 0
            cursor.execute(f"SELECT * FROM {table_name} WHERE timestamp < ?", (cutoff_date,))
            columns = [d[0] for d in cursor.description]
            archived = 0
            with open(archive_path, "a", encoding="utf-8") as f:
                while True:
                    rows = cursor.fetchmany(500)
                    if not rows:
                        break
                    for row in rows:
                        payload = {"table": table_name, "row": dict(zip(columns, row))}
                        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
                        archived += 1
            return archived

        archived_security = _archive_table("security_events")
        archived_mcp = _archive_table("mcp_requests")
        archived_auth = _archive_table("auth_audit_log")

        # Delete old security events
        cursor.execute("DELETE FROM security_events WHERE timestamp < ?", (cutoff_date,))
        security_deleted = cursor.rowcount

        # Delete old MCP requests
        cursor.execute("DELETE FROM mcp_requests WHERE timestamp < ?", (cutoff_date,))
        mcp_deleted = cursor.rowcount

        # Delete old auth audit logs
        cursor.execute("DELETE FROM auth_audit_log WHERE timestamp < ?", (cutoff_date,))
        auth_deleted = cursor.rowcount

        conn.commit()
        conn.close()

        result = {
            "security_events": security_deleted,
            "mcp_requests": mcp_deleted,
            "auth_audit_log": auth_deleted,
            "total": security_deleted + mcp_deleted + auth_deleted,
        }
        if archive_enabled and archive_path:
            result["archived"] = {
                "security_events": archived_security,
                "mcp_requests": archived_mcp,
                "auth_audit_log": archived_auth,
            }

        logger.info(
            f"Cleanup completed: deleted {result['total']} old log entries "
            f"(security={security_deleted}, mcp={mcp_deleted}, auth={auth_deleted})"
        )

        return result

    except Exception as e:
        logger.error(f"Failed to cleanup old logs: {e}")
        return {"error": str(e)}


def get_security_events(
    db_path: str,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    last_hours: Optional[int] = None,
) -> list[Dict[str, Any]]:
    """Get security events with optional filters.

    Args:
        db_path: Path to SQLite database
        severity: Filter by severity (low, medium, high, critical)
        event_type: Filter by event type
        limit: Maximum number of events to return
        last_hours: Only return events from last N hours

    Returns:
        List of security event dictionaries
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM security_events WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        if last_hours:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=last_hours)).isoformat()
            query += " AND timestamp >= ?"
            params.append(cutoff)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        events = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return events

    except Exception as e:
        logger.error(f"Failed to get security events: {e}")
        return []


def get_mcp_request_stats(db_path: str, last_hours: int = 24) -> Dict[str, Any]:
    """Get MCP request statistics.

    Args:
        db_path: Path to SQLite database
        last_hours: Time window in hours (default: 24)

    Returns:
        Dictionary with statistics
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=last_hours)).isoformat()

        # Total requests
        cursor.execute("SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ?", (cutoff,))
        total_requests = cursor.fetchone()[0]

        # Successful requests
        cursor.execute(
            "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND success = 1", (cutoff,)
        )
        successful_requests = cursor.fetchone()[0]

        # Failed requests
        cursor.execute(
            "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND success = 0", (cutoff,)
        )
        failed_requests = cursor.fetchone()[0]

        # Suspicious requests
        cursor.execute(
            "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND is_suspicious = 1",
            (cutoff,),
        )
        suspicious_requests = cursor.fetchone()[0]

        # Average response time
        cursor.execute(
            "SELECT AVG(response_time_ms) FROM mcp_requests WHERE timestamp >= ? AND response_time_ms IS NOT NULL",
            (cutoff,),
        )
        avg_response_time = cursor.fetchone()[0]

        # Top tools (include server info when available)
        cursor.execute(
            """
            SELECT r.tool_name, r.mcp_server_id, s.name, COUNT(*) as count
            FROM mcp_requests r
            LEFT JOIN mcp_servers s ON s.id = r.mcp_server_id
            WHERE r.timestamp >= ? AND r.tool_name IS NOT NULL
            GROUP BY r.tool_name, r.mcp_server_id, s.name
            ORDER BY count DESC
            LIMIT 5
            """,
            (cutoff,),
        )
        top_tools = [
            {
                "tool": row[0],
                "server_id": row[1],
                "server_name": row[2],
                "count": row[3],
            }
            for row in cursor.fetchall()
        ]

        conn.close()

        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "suspicious_requests": suspicious_requests,
            "success_rate": (
                round(successful_requests / total_requests * 100, 2) if total_requests > 0 else 0
            ),
            "avg_response_time_ms": round(avg_response_time, 2) if avg_response_time else 0,
            "top_tools": top_tools,
            "time_window_hours": last_hours,
        }

    except Exception as e:
        logger.error(f"Failed to get MCP request stats: {e}")
        return {
            "error": str(e),
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "suspicious_requests": 0,
            "success_rate": 0,
            "avg_response_time_ms": 0,
            "top_tools": [],
            "time_window_hours": last_hours,
        }


def get_mcp_requests(
    db_path: str,
    limit: int = 50,
    last_seconds: int = 60,
    method: str = None,
    success: bool = None,
) -> list:
    """Get recent MCP requests from DB (fallback to log files).

    Args:
        db_path: Path to SQLite database (ignored, kept for compatibility)
        limit: Maximum number of requests to return
        last_seconds: Number of seconds to look back
        method: Filter by method (optional)
        success: Filter by success status (optional)

    Returns:
        List of MCP request records
    """
    try:
        from authmcp_gateway.config import get_config

        config = get_config()

        # Calculate time threshold (match SQLite CURRENT_TIMESTAMP format)
        threshold = datetime.now(timezone.utc) - timedelta(seconds=last_seconds)
        threshold_sql = threshold.strftime("%Y-%m-%d %H:%M:%S")

        if getattr(config, "mcp_log_db_enabled", False):
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = """
                SELECT
                    r.id,
                    r.user_id,
                    u.username,
                    r.mcp_server_id,
                    s.name AS server_name,
                    r.method,
                    r.tool_name,
                    r.success,
                    r.error_message,
                    r.response_time_ms,
                    r.ip_address,
                    r.is_suspicious,
                    r.timestamp
                FROM mcp_requests r
                LEFT JOIN users u ON u.id = r.user_id
                LEFT JOIN mcp_servers s ON s.id = r.mcp_server_id
                WHERE r.timestamp >= ?
            """
            params = [threshold_sql]

            if method:
                query += " AND r.method = ?"
                params.append(method)

            if success is not None:
                query += " AND r.success = ?"
                params.append(1 if success else 0)

            query += " ORDER BY r.timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()

            return [
                {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "mcp_server_id": row["mcp_server_id"],
                    "server_name": row["server_name"],
                    "method": row["method"],
                    "tool_name": row["tool_name"],
                    "success": bool(row["success"]),
                    "error_message": row["error_message"],
                    "response_time_ms": row["response_time_ms"],
                    "ip_address": row["ip_address"],
                    "is_suspicious": bool(row["is_suspicious"]),
                    "timestamp": row["timestamp"],
                }
                for row in rows
            ]

        # Fallback to file-based logs if DB logging disabled
        import json
        from pathlib import Path

        log_file = Path("data/logs/mcp_requests.log")
        if not log_file.exists():
            return []

        requests = []
        with open(log_file, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    timestamp_str = entry.get("timestamp", "").replace("Z", "+00:00")
                    entry_time = datetime.fromisoformat(timestamp_str)
                    if entry_time < threshold:
                        continue

                    if method and entry.get("method") != method:
                        continue

                    if success is not None and entry.get("success") != success:
                        continue

                    requests.append(
                        {
                            "id": len(requests) + 1,  # Synthetic ID
                            "user_id": entry.get("user_id"),
                            "username": entry.get("username"),
                            "mcp_server_id": entry.get("server_id"),
                            "server_name": entry.get("server_name"),
                            "method": entry.get("method"),
                            "tool_name": entry.get("tool_name"),
                            "success": entry.get("success", True),
                            "error_message": entry.get("error"),
                            "response_time_ms": entry.get("response_time_ms"),
                            "ip_address": entry.get("ip_address"),
                            "is_suspicious": entry.get("suspicious", False),
                            "timestamp": entry.get("timestamp"),
                        }
                    )
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"Failed to parse MCP log entry: {e}")
                    continue

        requests.sort(key=lambda x: x["timestamp"], reverse=True)
        return requests[:limit]

    except Exception as e:
        logger.error(f"Error reading MCP requests: {e}")
        return []
