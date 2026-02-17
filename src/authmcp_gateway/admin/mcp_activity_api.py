"""Admin API: MCP activity monitoring, stats, and security audit."""

import logging

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import (
    api_error_handler,
    get_config,
    render_template,
    requires_admin,
)

logger = logging.getLogger(__name__)

__all__ = [
    "admin_mcp_activity",
    "admin_mcp_audit",
    "admin_mcp_requests_api",
    "api_mcp_stats",
    "api_run_mcp_audit",
    "api_export_mcp_audit",
]


@requires_admin
async def admin_mcp_activity(request: Request) -> HTMLResponse:
    """MCP Activity monitoring page - real-time view."""
    return render_template("admin/mcp_activity.html", active_page="mcp-activity")


@requires_admin
async def admin_mcp_audit(request: Request) -> HTMLResponse:
    """MCP Security Audit page - audit any MCP server security."""
    return render_template("admin/mcp_audit.html", active_page="mcp-audit")


@requires_admin
async def admin_mcp_requests_api(request: Request) -> JSONResponse:
    """API endpoint for live MCP requests."""
    from authmcp_gateway.security.logger import get_mcp_requests

    # Get query parameters
    limit = int(request.query_params.get("limit", "50"))
    if limit < 1:
        limit = 1
    elif limit > 200:
        limit = 200
    last_seconds = int(request.query_params.get("last_seconds", "60"))
    method = request.query_params.get("method")
    success_param = request.query_params.get("success")

    success = None
    if success_param is not None:
        success = success_param.lower() == "true"

    requests = get_mcp_requests(
        db_path=get_config(request).auth.sqlite_path,
        limit=limit,
        last_seconds=last_seconds,
        method=method,
        success=success,
    )

    return JSONResponse({"requests": requests})


@api_error_handler
async def api_mcp_stats(request: Request) -> JSONResponse:
    """Get MCP request statistics."""
    from authmcp_gateway.mcp.store import list_mcp_servers
    from authmcp_gateway.security.logger import get_mcp_request_stats

    _config = get_config(request)
    last_hours = int(request.query_params.get("last_hours", "24"))
    include_top_tools = request.query_params.get("include_top_tools", "false").lower() == "true"

    # Get request stats
    stats = get_mcp_request_stats(db_path=_config.auth.sqlite_path, last_hours=last_hours)

    # Get server stats
    servers = list_mcp_servers(_config.auth.sqlite_path, enabled_only=False)
    active_servers = sum(1 for s in servers if s.get("status") == "online")
    total_servers = len(servers)

    # Rename fields to match Dashboard expectations
    result = {
        "requests_24h": stats.get("total_requests", 0),
        "active_servers": active_servers,
        "total_servers": total_servers,
        "success_rate": stats.get("success_rate", 0),
        "avg_response_time": stats.get("avg_response_time_ms", 0),
        "trend": "",  # TODO: Calculate trend from previous period
    }

    # Add top tools if requested
    if include_top_tools:
        top_tools = stats.get("top_tools", [])
        # Reformat to match Dashboard expectations
        result["top_tools"] = [
            {"name": t["tool"], "count": t["count"], "server": t.get("server_name") or "Unknown"}
            for t in top_tools
        ]

    return JSONResponse(result)


@requires_admin
@api_error_handler
async def api_run_mcp_audit(request: Request) -> JSONResponse:
    """API: Run security audit on an MCP server."""
    from authmcp_gateway.security.mcp_auditor import MCPSecurityAuditor

    body = await request.json()
    url = body.get("url")
    bearer_token = body.get("bearer_token")

    if not url:
        return JSONResponse({"error": "URL is required"}, status_code=400)

    # Validate URL format
    if not url.startswith(("http://", "https://")):
        return JSONResponse({"error": "URL must start with http:// or https://"}, status_code=400)

    # Run security audit (blocking I/O) in a worker thread
    import anyio

    auditor = MCPSecurityAuditor(url, bearer_token)
    results = await anyio.to_thread.run_sync(auditor.run_all_tests)

    # Ensure details render cleanly in UI
    try:
        import json as _json

        for test in results.get("tests", []):
            details = test.get("details")
            if details is None or isinstance(details, str):
                continue
            try:
                test["details"] = _json.dumps(details, ensure_ascii=False, indent=2)
            except Exception:
                test["details"] = str(details)
    except Exception:
        pass

    return JSONResponse(results)


@requires_admin
@api_error_handler
async def api_export_mcp_audit(request: Request) -> JSONResponse:
    """API: Export MCP security audit results as JSON."""
    from authmcp_gateway.security.mcp_auditor import MCPSecurityAuditor

    body = await request.json()
    url = body.get("url")
    bearer_token = body.get("bearer_token")

    if not url:
        return JSONResponse({"error": "URL is required"}, status_code=400)

    # Run audit and export
    auditor = MCPSecurityAuditor(url, bearer_token)
    export_data = auditor.export_json()

    return JSONResponse(export_data)
