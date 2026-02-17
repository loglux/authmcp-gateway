"""Admin API: Backend MCP token management."""

import logging
from datetime import datetime, timezone

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config, render_template

logger = logging.getLogger(__name__)

__all__ = [
    "admin_mcp_tokens",
    "api_get_token_statuses",
    "api_get_token_audit_logs",
    "api_refresh_server_token",
]


async def admin_mcp_tokens(request: Request) -> HTMLResponse:
    """Admin page: Backend MCP token management."""
    return render_template("admin/mcp_tokens.html")


@api_error_handler
async def api_get_token_statuses(request: Request) -> JSONResponse:
    """API: Get token status for all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers

    servers = list_mcp_servers(get_config(request).auth.sqlite_path, enabled_only=False)

    token_statuses = []
    for server in servers:
        # Calculate token status
        token_expires_at = server.get("token_expires_at")
        token_expired = False
        time_until_expiry_seconds = None

        if token_expires_at:
            if isinstance(token_expires_at, str):
                # Parse ISO format datetime
                try:
                    token_expires_at = datetime.fromisoformat(
                        token_expires_at.replace("Z", "+00:00")
                    )
                except (ValueError, TypeError) as e:
                    logger.debug(
                        f"Failed to parse token_expires_at for server {server.get('id')}: {e}"
                    )
                    token_expires_at = None

            if token_expires_at:
                now = datetime.now(timezone.utc)
                if token_expires_at.tzinfo is None:
                    token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

                delta = token_expires_at - now
                time_until_expiry_seconds = int(delta.total_seconds())
                token_expired = time_until_expiry_seconds <= 0

        status = {
            "server_id": server["id"],
            "server_name": server["name"],
            "auth_type": server.get("auth_type", "none"),
            "has_refresh_token": bool(server.get("refresh_token_hash")),
            "token_expires_at": server.get("token_expires_at"),
            "token_expired": token_expired,
            "time_until_expiry_seconds": time_until_expiry_seconds,
            "last_refreshed": server.get("token_last_refreshed"),
            "can_auto_refresh": bool(
                server.get("refresh_token_hash") and server.get("refresh_endpoint")
            ),
        }
        token_statuses.append(status)

    return JSONResponse(token_statuses)


@api_error_handler
async def api_get_token_audit_logs(request: Request) -> JSONResponse:
    """API: Get token refresh audit logs."""
    from authmcp_gateway.mcp.store import get_token_audit_logs

    # Get limit from query params
    limit = int(request.query_params.get("limit", 50))
    server_id = request.query_params.get("server_id")

    if server_id:
        server_id = int(server_id)

    logs = get_token_audit_logs(
        db_path=get_config(request).auth.sqlite_path, mcp_server_id=server_id, limit=limit
    )

    return JSONResponse(logs)


@api_error_handler
async def api_refresh_server_token(request: Request) -> JSONResponse:
    """API: Manually refresh token for a backend MCP server."""
    from authmcp_gateway.mcp.token_manager import get_token_manager

    server_id = int(request.path_params["server_id"])

    # Get token manager
    token_mgr = get_token_manager()

    # Trigger refresh
    success, error = await token_mgr.refresh_server_token(server_id, triggered_by="manual")

    if success:
        return JSONResponse({"detail": "Token refreshed successfully"})
    else:
        return JSONResponse({"detail": f"Failed to refresh token: {error}"}, status_code=400)
