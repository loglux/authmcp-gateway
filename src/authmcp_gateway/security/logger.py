"""Security and MCP request logging functions."""

import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def log_security_event(
    db_path: str,
    event_type: str,
    severity: str,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    endpoint: Optional[str] = None,
    method: Optional[str] = None
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
                datetime.now(timezone.utc).isoformat()
            )
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
    is_suspicious: bool = False
) -> None:
    """Log MCP request.

    Args:
        db_path: Path to SQLite database
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
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """
            INSERT INTO mcp_requests (
                user_id, mcp_server_id, method, tool_name, success,
                error_message, response_time_ms, ip_address, is_suspicious, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                mcp_server_id,
                method,
                tool_name,
                1 if success else 0,
                error_message,
                response_time_ms,
                ip_address,
                1 if is_suspicious else 0,
                datetime.now(timezone.utc).isoformat()
            )
        )
        
        conn.commit()
        conn.close()
        
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
        
        # Delete old security events
        cursor.execute(
            "DELETE FROM security_events WHERE timestamp < ?",
            (cutoff_date,)
        )
        security_deleted = cursor.rowcount
        
        # Delete old MCP requests
        cursor.execute(
            "DELETE FROM mcp_requests WHERE timestamp < ?",
            (cutoff_date,)
        )
        mcp_deleted = cursor.rowcount
        
        # Delete old auth audit logs
        cursor.execute(
            "DELETE FROM auth_audit_log WHERE timestamp < ?",
            (cutoff_date,)
        )
        auth_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        result = {
            "security_events": security_deleted,
            "mcp_requests": mcp_deleted,
            "auth_audit_log": auth_deleted,
            "total": security_deleted + mcp_deleted + auth_deleted
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
    last_hours: Optional[int] = None
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
        cursor.execute(
            "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ?",
            (cutoff,)
        )
        total_requests = cursor.fetchone()[0]
        
        # Successful requests
        cursor.execute(
            "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND success = 1",
            (cutoff,)
        )
        successful_requests = cursor.fetchone()[0]
        
        # Failed requests
        cursor.execute(
            "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND success = 0",
            (cutoff,)
        )
        failed_requests = cursor.fetchone()[0]
        
        # Suspicious requests
        cursor.execute(
            "SELECT COUNT(*) FROM mcp_requests WHERE timestamp >= ? AND is_suspicious = 1",
            (cutoff,)
        )
        suspicious_requests = cursor.fetchone()[0]
        
        # Average response time
        cursor.execute(
            "SELECT AVG(response_time_ms) FROM mcp_requests WHERE timestamp >= ? AND response_time_ms IS NOT NULL",
            (cutoff,)
        )
        avg_response_time = cursor.fetchone()[0]
        
        # Top tools
        cursor.execute(
            """
            SELECT tool_name, COUNT(*) as count
            FROM mcp_requests
            WHERE timestamp >= ? AND tool_name IS NOT NULL
            GROUP BY tool_name
            ORDER BY count DESC
            LIMIT 5
            """,
            (cutoff,)
        )
        top_tools = [{"tool": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "suspicious_requests": suspicious_requests,
            "success_rate": round(successful_requests / total_requests * 100, 2) if total_requests > 0 else 0,
            "avg_response_time_ms": round(avg_response_time, 2) if avg_response_time else 0,
            "top_tools": top_tools,
            "time_window_hours": last_hours
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
            "time_window_hours": last_hours
        }


def get_mcp_requests(
    db_path: str,
    limit: int = 50,
    last_seconds: int = 60,
    method: str = None,
    success: bool = None,
) -> list:
    """Get recent MCP requests for live monitoring.
    
    Args:
        db_path: Path to SQLite database
        limit: Maximum number of requests to return
        last_seconds: Number of seconds to look back
        method: Filter by method (optional)
        success: Filter by success status (optional)
        
    Returns:
        List of MCP request records
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Calculate time threshold
        threshold = datetime.now(timezone.utc) - timedelta(seconds=last_seconds)
        threshold_str = threshold.isoformat()
        
        # Build query
        query = """
            SELECT 
                r.id,
                r.user_id,
                u.username,
                r.mcp_server_id,
                s.name as server_name,
                r.method,
                r.tool_name,
                r.success,
                r.error_message,
                r.response_time_ms,
                r.ip_address,
                r.is_suspicious,
                r.timestamp
            FROM mcp_requests r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN mcp_servers s ON r.mcp_server_id = s.id
            WHERE r.timestamp >= ?
        """
        params = [threshold_str]
        
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
        
        requests = []
        for row in rows:
            requests.append({
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
            })
        
        conn.close()
        return requests
        
    except Exception as e:
        logger.error(f"Failed to get MCP requests: {e}")
        return []
