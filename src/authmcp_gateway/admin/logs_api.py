"""Admin API: Auth logs, security events, and cleanup."""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config

logger = logging.getLogger(__name__)

__all__ = [
    "api_logs",
    "api_mcp_auth_events",
    "api_cleanup_auth_logs_file",
    "api_security_events",
    "api_cleanup_db_logs",
]


@api_error_handler
async def api_logs(request: Request) -> JSONResponse:
    """Get auth logs from database with pagination."""
    event_type = request.query_params.get("event_type")
    limit = int(request.query_params.get("limit", "50"))
    offset = int(request.query_params.get("offset", "0"))
    days = request.query_params.get("days")  # Filter by days (e.g., "1", "7", "30")

    try:
        import sqlite3

        conn = sqlite3.connect(get_config().auth.sqlite_path)
        cursor = conn.cursor()

        # Build WHERE clause
        where_clauses = []
        params = []

        if event_type:
            where_clauses.append("event_type = ?")
            params.append(event_type)

        if days:
            cutoff_date = (datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat()
            where_clauses.append("timestamp >= ?")
            params.append(cutoff_date)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Get total count
        cursor.execute(f"SELECT COUNT(*) FROM auth_audit_log {where_sql}", params)
        total = cursor.fetchone()[0]

        # Get paginated results (sorted by timestamp descending)
        cursor.execute(
            f"""
            SELECT event_type, user_id, username, ip_address, user_agent,
                   success, details, timestamp
            FROM auth_audit_log
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        )

        logs = []
        for row in cursor.fetchall():
            logs.append(
                {
                    "event_type": row[0],
                    "user_id": row[1],
                    "username": row[2],
                    "ip_address": row[3],
                    "user_agent": row[4],
                    "success": bool(row[5]),
                    "details": row[6],
                    "timestamp": row[7],
                }
            )

        conn.close()

        return JSONResponse({"logs": logs, "total": total, "limit": limit, "offset": offset})

    except Exception as e:
        logger.error(f"Failed to read auth logs from database: {e}")
        return JSONResponse({"error": "Failed to read logs"}, status_code=500)


@api_error_handler
async def api_mcp_auth_events(request: Request) -> JSONResponse:
    """Get recent MCP OAuth auth events from auth log."""
    limit = int(request.query_params.get("limit", "10"))
    last_seconds_raw = request.query_params.get("last_seconds")
    last_seconds = int(last_seconds_raw) if last_seconds_raw is not None else None
    log_file = Path("data/logs/auth.log")

    if not log_file.exists():
        return JSONResponse({"events": []})

    cutoff = None
    if last_seconds is not None and last_seconds > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=last_seconds)
    allowed_types = {"mcp_oauth_authorize", "mcp_oauth_token", "mcp_oauth_error"}
    events = []

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    event_type = entry.get("event_type")
                    details = entry.get("details") or ""
                    if event_type not in allowed_types:
                        if event_type == "login" and (
                            "Authorization code flow" in details or "password grant" in details
                        ):
                            entry = dict(entry)
                            entry["event_type"] = "mcp_oauth_token"
                        else:
                            continue
                    ts = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
                    if cutoff and ts < cutoff:
                        continue
                    events.append(entry)
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except Exception as e:
        logger.error(f"Failed to read auth logs for MCP auth events: {e}")
        return JSONResponse({"error": "Failed to read logs"}, status_code=500)

    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return JSONResponse({"events": events[:limit]})


@api_error_handler
async def api_cleanup_auth_logs_file(request: Request) -> JSONResponse:
    """Cleanup old auth logs (older than 30 days)."""
    log_file = Path("data/logs/auth.log")

    if not log_file.exists():
        return JSONResponse({"success": True, "deleted": 0})

    cutoff_date = datetime.utcnow() - timedelta(days=30)
    kept_logs = []
    deleted_count = 0

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    log_time = datetime.fromisoformat(log_entry["timestamp"].replace("Z", "+00:00"))

                    if log_time >= cutoff_date:
                        kept_logs.append(line)
                    else:
                        deleted_count += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    # Keep malformed entries to avoid data loss
                    kept_logs.append(line)

        # Write back only recent logs
        with open(log_file, "w", encoding="utf-8") as f:
            f.writelines(kept_logs)

    except Exception as e:
        logger.error(f"Failed to cleanup logs: {e}")
        return JSONResponse({"error": "Failed to cleanup logs"}, status_code=500)

    return JSONResponse({"success": True, "deleted": deleted_count})


@api_error_handler
async def api_security_events(request: Request) -> JSONResponse:
    """Get security events with filters."""
    from authmcp_gateway.security.logger import get_security_events

    severity = request.query_params.get("severity")
    event_type = request.query_params.get("event_type")
    limit = int(request.query_params.get("limit", "100"))
    last_hours = request.query_params.get("last_hours")

    events = get_security_events(
        db_path=get_config().auth.sqlite_path,
        severity=severity,
        event_type=event_type,
        limit=limit,
        last_hours=int(last_hours) if last_hours else None,
    )

    return JSONResponse(events)


@api_error_handler
async def api_cleanup_db_logs(request: Request) -> JSONResponse:
    """Cleanup old DB logs (security + MCP)."""
    from authmcp_gateway.security.logger import cleanup_old_logs

    body = await request.json()
    days_to_keep = body.get("days_to_keep", 30)

    result = cleanup_old_logs(db_path=get_config().auth.sqlite_path, days_to_keep=days_to_keep)

    return JSONResponse(result)
