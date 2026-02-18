"""Admin API: MCP server management."""

import logging
from datetime import datetime

import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config, render_template

logger = logging.getLogger(__name__)

__all__ = [
    "admin_mcp_servers",
    "parse_jwt_expiration",
    "api_list_mcp_servers",
    "api_mcp_servers_token_status",
    "api_create_mcp_server",
    "api_delete_mcp_server",
    "api_update_mcp_server",
    "api_test_mcp_server",
    "api_get_mcp_server_tools",
]


async def admin_mcp_servers(_: Request) -> HTMLResponse:
    """MCP servers management page."""
    from authmcp_gateway.settings_manager import get_settings_manager

    try:
        sm = get_settings_manager()
        default_timeout = sm.get("timeouts", "proxy_timeout", default=30)
    except Exception:
        default_timeout = 30

    return render_template(
        "admin/mcp_servers.html",
        active_page="mcp-servers",
        default_timeout=default_timeout,
    )


def parse_jwt_expiration(token: str) -> dict:
    """Parse JWT token to extract expiration info.

    Args:
        token: JWT token string

    Returns:
        Dict with expires_at, days_left, status or {"status": "unknown"}
    """
    try:
        # Decode without signature verification (we just need exp claim)
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get("exp")

        if exp:
            exp_dt = datetime.fromtimestamp(exp)
            now = datetime.now()
            days_left = (exp_dt - now).days

            # Determine status
            if days_left < 0:
                status = "expired"
            elif days_left < 7:
                status = "warning"
            else:
                status = "ok"

            return {
                "expires_at": exp_dt.isoformat(),
                "expires_at_formatted": exp_dt.strftime("%Y-%m-%d %H:%M"),
                "days_left": days_left,
                "status": status,
                "has_expiration": True,
            }
        else:
            # JWT without exp claim - never expires
            return {"status": "never", "has_expiration": False, "message": "No expiration"}
    except Exception as e:
        logger.debug(f"Failed to parse JWT token: {e}")

    return {"status": "unknown", "has_expiration": False, "message": "Not a JWT token"}


async def api_list_mcp_servers(request: Request) -> JSONResponse:
    """API: List all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers

    servers = list_mcp_servers(get_config(request).auth.sqlite_path)

    return JSONResponse({"servers": servers})


async def api_mcp_servers_token_status(request: Request) -> JSONResponse:
    """API: Get token expiration status for all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers

    servers = list_mcp_servers(get_config(request).auth.sqlite_path)

    result = []
    for server in servers:
        token_info = {"status": "none"}  # Default for servers without auth

        # Only check Bearer tokens
        if server.get("auth_type") == "bearer" and server.get("auth_token"):
            token_info = parse_jwt_expiration(server["auth_token"])

        result.append(
            {
                "id": server["id"],
                "name": server["name"],
                "auth_type": server["auth_type"],
                "token_status": token_info,
            }
        )

    return JSONResponse({"servers": result})


@api_error_handler
async def api_create_mcp_server(request: Request) -> JSONResponse:
    """API: Create new MCP server."""
    from authmcp_gateway.mcp.store import create_mcp_server

    _config = get_config(request)
    data = await request.json()

    # Parse timeout: None means "use global default"
    timeout_val = data.get("timeout")
    if timeout_val is not None:
        try:
            timeout_val = int(timeout_val) if timeout_val else None
        except (ValueError, TypeError):
            timeout_val = None

    server_id = create_mcp_server(
        db_path=_config.auth.sqlite_path,
        name=data["name"],
        url=data["url"],
        description=data.get("description"),
        tool_prefix=data.get("tool_prefix"),
        enabled=data.get("enabled", True),
        auth_type=data.get("auth_type", "none"),
        auth_token=data.get("auth_token"),
        routing_strategy=data.get("routing_strategy", "prefix"),
        timeout=timeout_val,
    )

    # Trigger health check for new server
    from authmcp_gateway.mcp.health import get_health_checker

    try:
        health_checker = get_health_checker()
        from authmcp_gateway.mcp.store import get_mcp_server

        server = get_mcp_server(_config.auth.sqlite_path, server_id)
        if server:
            await health_checker.check_server(server)
    except Exception as e:
        # Health checker might not be initialized yet; log for visibility.
        logger.debug(f"Health check skipped for new server {server_id}: {e}")

    return JSONResponse({"id": server_id, "message": "Server created successfully"})


@api_error_handler
async def api_delete_mcp_server(request: Request) -> JSONResponse:
    """API: Delete MCP server."""
    from authmcp_gateway.mcp.store import delete_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])

    success = delete_mcp_server(_config.auth.sqlite_path, server_id)

    if success:
        # Invalidate cache
        from authmcp_gateway.mcp.proxy import McpProxy

        proxy = McpProxy(_config.auth.sqlite_path)
        proxy.invalidate_cache(server_id)

        return JSONResponse({"message": "Server deleted successfully"})
    else:
        return JSONResponse({"error": "Server not found"}, status_code=404)


@api_error_handler
async def api_update_mcp_server(request: Request) -> JSONResponse:
    """API: Update MCP server."""
    from authmcp_gateway.mcp.store import get_mcp_server, update_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    data = await request.json()

    # Sanitize timeout: empty/zero → None (use global default)
    if "timeout" in data:
        try:
            data["timeout"] = int(data["timeout"]) if data["timeout"] else None
        except (ValueError, TypeError):
            data["timeout"] = None

    # Update server
    success = update_mcp_server(db_path=_config.auth.sqlite_path, server_id=server_id, **data)

    if success:
        # Invalidate cache
        from authmcp_gateway.mcp.proxy import McpProxy

        proxy = McpProxy(_config.auth.sqlite_path)
        proxy.invalidate_cache(server_id)

        # Trigger health check for updated server
        from authmcp_gateway.mcp.health import get_health_checker

        try:
            health_checker = get_health_checker()
            server = get_mcp_server(_config.auth.sqlite_path, server_id)
            if server:
                await health_checker.check_server(server)
        except Exception as e:
            # Health checker might not be initialized yet; log for visibility.
            logger.debug(f"Health check skipped for updated server {server_id}: {e}")

        return JSONResponse({"message": "Server updated successfully"})
    else:
        return JSONResponse({"error": "Server not found"}, status_code=404)


@api_error_handler
async def api_test_mcp_server(request: Request) -> JSONResponse:
    """API: Test MCP server connection."""
    from authmcp_gateway.mcp.health import HealthChecker
    from authmcp_gateway.mcp.store import get_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    server = get_mcp_server(_config.auth.sqlite_path, server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    # Perform health check
    health_checker = HealthChecker(_config.auth.sqlite_path)
    result = await health_checker.check_server(server)

    # Convert datetime to ISO string for JSON serialization
    if "checked_at" in result and result["checked_at"]:
        result["checked_at"] = result["checked_at"].isoformat()

    return JSONResponse(result)


@api_error_handler
async def api_get_mcp_server_tools(request: Request) -> JSONResponse:
    """API: Get tools from MCP server."""
    from authmcp_gateway.mcp.proxy import McpProxy
    from authmcp_gateway.mcp.store import get_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    server = get_mcp_server(_config.auth.sqlite_path, server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    # Fetch tools from server
    proxy = McpProxy(_config.auth.sqlite_path)
    tools = await proxy._fetch_tools_from_server(server)

    # Extract tool names
    tool_names = [tool.get("name") for tool in tools if "name" in tool]

    return JSONResponse(tool_names)
