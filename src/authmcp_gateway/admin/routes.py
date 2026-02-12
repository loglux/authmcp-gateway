"""Admin panel routes."""
import logging
import sqlite3
import jwt
import json
from pathlib import Path
from typing import Optional, Callable, Any
from functools import wraps
from datetime import datetime, timedelta, timezone
from jinja2 import Environment, FileSystemLoader
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from authmcp_gateway.auth.user_store import (
    get_all_users,
    get_auth_logs,
    update_user_status,
    make_user_superuser,
)
from authmcp_gateway.config import AppConfig

logger = logging.getLogger(__name__)


# Admin authentication decorator (simplified version)
def requires_admin(func):
    """Decorator to require admin authentication for routes."""
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        # Admin auth is handled by AdminAuthMiddleware
        # This decorator is just for marking admin routes
        return await func(request, *args, **kwargs)
    return wrapper

# Setup Jinja2 templates
TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))

# Global config instance
_config: Optional[AppConfig] = None


def initialize(config: AppConfig) -> None:
    """Initialize admin routes with config."""
    global _config
    _config = config
    logger.info("Admin routes initialized")


def render_template(template_name: str, **context) -> HTMLResponse:
    """Render Jinja2 template with context.

    Args:
        template_name: Name of template file (e.g., "admin/dashboard.html")
        **context: Template context variables

    Returns:
        HTMLResponse with rendered template
    """
    template = jinja_env.get_template(template_name)
    html = template.render(**context)
    return HTMLResponse(content=html)


def api_error_handler(func: Callable) -> Callable:
    """Decorator for consistent error handling in admin API endpoints.

    Handles:
    - Config initialization check
    - Exception catching and logging
    - Consistent error response format

    Usage:
        @api_error_handler
        async def my_api_endpoint(request: Request) -> JSONResponse:
            # Your code here
            return JSONResponse({"result": "success"})
    """
    @wraps(func)
    async def wrapper(*args, **kwargs) -> JSONResponse:
        # Check if config is initialized
        if _config is None:
            logger.error(f"{func.__name__}: Config not initialized")
            return JSONResponse(
                {"error": "Config not initialized"},
                status_code=500
            )

        try:
            # Call the actual function
            return await func(*args, **kwargs)
        except Exception as e:
            # Log the error with context
            logger.exception(f"{func.__name__} failed: {e}")
            return JSONResponse(
                {"error": str(e)},
                status_code=500
            )

    return wrapper


def _get_common_styles() -> str:
    """Get common CSS styles for admin pages.

    Returns:
        CSS style block with common admin panel styles
    """
    return """
        .sidebar {
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .nav-link {
            color: rgba(255,255,255,0.8);
            transition: all 0.3s;
        }
        .nav-link:hover, .nav-link.active {
            color: white;
            background: rgba(255,255,255,0.1);
            border-radius: 8px;
        }
    """


def _get_sidebar_nav(active_page: str = "") -> str:
    """Generate unified sidebar navigation menu.

    Args:
        active_page: The current active page (dashboard, users, mcp-servers, settings, logs, api-test)

    Returns:
        HTML string for sidebar navigation (complete <li> elements)
    """
    menu_items = [
        ("dashboard", "/admin", '<i class="bi bi-speedometer2"></i> Dashboard'),
        ("users", "/admin/users", '<i class="bi bi-people"></i> Users'),
        ("mcp-servers", "/admin/mcp-servers", '<i class="bi bi-hdd-network"></i> MCP Servers'),
        ("settings", "/admin/settings", '<i class="bi bi-gear"></i> Settings'),
        ("logs", "/admin/logs", '<i class="bi bi-clock-history"></i> Auth Logs'),
        ("mcp-audit", "/admin/mcp-audit", '<i class="bi bi-shield-check"></i> Security Audit'),
        ("api-test", "/admin/api-test", '<i class="bi bi-code-square"></i> API Test'),
    ]

    nav_html = ""
    for page_id, url, label in menu_items:
        active_class = "active" if page_id == active_page else ""
        nav_html += f'''                    <li class="nav-item mb-2">
                        <a class="nav-link {active_class}" href="{url}">
                            {label}
                        </a>
                    </li>
'''

    # Add external MCP endpoint link
    nav_html += '''                    <li class="nav-item mt-4">
                        <a class="nav-link" href="/mcp" target="_blank">
                            <i class="bi bi-box-arrow-up-right"></i> MCP Endpoint
                        </a>
                    </li>
'''

    return nav_html


async def admin_dashboard(_: Request) -> HTMLResponse:
    """Admin dashboard page."""
    return render_template("admin/dashboard.html", active_page="dashboard")


async def admin_users(_: Request) -> HTMLResponse:
    """Admin users management page."""
    return render_template("admin/users.html", active_page="users")


@requires_admin
async def admin_logs(_: Request) -> HTMLResponse:
    """Admin auth logs page."""
    return render_template("admin/logs.html", active_page="logs")


@requires_admin
async def admin_security_logs(_: Request) -> HTMLResponse:
    """Admin security events page."""
    return render_template("admin/security_logs.html", active_page="security-logs")


@requires_admin
async def admin_api_test(_: Request) -> HTMLResponse:
    """Admin API testing page."""
    return render_template("admin/api_test.html", active_page="api-test")


async def api_stats(_: Request) -> JSONResponse:
    """Get dashboard statistics."""
    users = get_all_users(_config.auth.sqlite_path)
    logs = get_auth_logs(_config.auth.sqlite_path, limit=1000)

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)

    recent_logins = len([
        log for log in logs
        if log["event_type"] in ["login", "admin_login"]
        and log["success"]
        and datetime.fromisoformat(log["created_at"]).replace(tzinfo=timezone.utc) > day_ago
    ])

    return JSONResponse({
        "total_users": len(users),
        "active_users": len([u for u in users if u["is_active"]]),
        "superusers": len([u for u in users if u["is_superuser"]]),
        "recent_logins": recent_logins,
        "system": {
            "jwt_algorithm": _config.jwt.algorithm,
            "access_token_ttl": f"{_config.jwt.access_token_expire_minutes} min",
            "refresh_token_ttl": f"{_config.jwt.refresh_token_expire_days} days",
            "public_url": _config.mcp_public_url,
        }
    })


@api_error_handler
async def api_users(_: Request) -> JSONResponse:
    """Get all users."""
    users = get_all_users(_config.auth.sqlite_path)
    return JSONResponse(users)


@api_error_handler
async def api_create_user(request: Request) -> JSONResponse:
    """Create new user (admin endpoint - bypasses allow_registration check)."""
    from authmcp_gateway.auth.user_store import create_user
    from authmcp_gateway.auth.password import hash_password
    from authmcp_gateway.settings_manager import get_settings_manager
    import re

    body = await request.json()
    username = body.get("username")
    email = body.get("email")
    password = body.get("password")
    is_superuser = body.get("is_superuser", False)

    # Validate input
    if not username or not email or not password:
        return JSONResponse({"error": "Username, email, and password are required"}, status_code=400)

    # Validate password strength using dynamic settings
    settings_manager = get_settings_manager()
    password_policy = settings_manager.get("password_policy", default={})

    min_length = password_policy.get("min_length", 8)
    require_uppercase = password_policy.get("require_uppercase", True)
    require_lowercase = password_policy.get("require_lowercase", True)
    require_digit = password_policy.get("require_digit", True)
    require_special = password_policy.get("require_special", False)

    # Check minimum length
    if len(password) < min_length:
        return JSONResponse({"error": f"Password must be at least {min_length} characters long"}, status_code=400)

    # Check for uppercase letter
    if require_uppercase and not re.search(r"[A-Z]", password):
        return JSONResponse({"error": "Password must contain at least one uppercase letter"}, status_code=400)

    # Check for lowercase letter
    if require_lowercase and not re.search(r"[a-z]", password):
        return JSONResponse({"error": "Password must contain at least one lowercase letter"}, status_code=400)

    # Check for digit
    if require_digit and not re.search(r"\d", password):
        return JSONResponse({"error": "Password must contain at least one digit"}, status_code=400)

    # Check for special character
    if require_special and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        return JSONResponse({"error": "Password must contain at least one special character"}, status_code=400)

    # Hash password and create user
    password_hash = hash_password(password)

    try:
        user_id = create_user(
            db_path=_config.auth.sqlite_path,
            username=username,
            email=email,
            password_hash=password_hash,
            is_superuser=is_superuser
        )

        return JSONResponse({
            "id": user_id,
            "username": username,
            "email": email,
            "is_superuser": is_superuser
        }, status_code=201)

    except sqlite3.IntegrityError:
        return JSONResponse({"error": "Username or email already exists"}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@api_error_handler
async def api_logs(request: Request) -> JSONResponse:
    """Get auth logs from file with pagination."""
    event_type = request.query_params.get("event_type")
    limit = int(request.query_params.get("limit", "50"))
    offset = int(request.query_params.get("offset", "0"))
    days = request.query_params.get("days")  # Filter by days (e.g., "1", "7", "30")

    log_file = Path("data/logs/auth.log")
    
    if not log_file.exists():
        return JSONResponse({"logs": [], "total": 0, "limit": limit, "offset": offset})
    
    # Read and parse log file
    logs = []
    cutoff_date = None
    if days:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=int(days))
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    
                    # Filter by event type
                    if event_type and log_entry.get("event_type") != event_type:
                        continue
                    
                    # Filter by date
                    if cutoff_date:
                        log_time = datetime.fromisoformat(log_entry["timestamp"].replace("Z", "+00:00"))
                        if log_time < cutoff_date:
                            continue
                    
                    logs.append(log_entry)
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except Exception as e:
        logger.error(f"Failed to read auth logs: {e}")
        return JSONResponse({"error": "Failed to read logs"}, status_code=500)
    
    # Sort by timestamp descending (newest first)
    logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    total = len(logs)
    paginated_logs = logs[offset:offset + limit]
    
    return JSONResponse({"logs": paginated_logs, "total": total, "limit": limit, "offset": offset})


@api_error_handler
async def api_cleanup_logs(request: Request) -> JSONResponse:
    """Cleanup old auth logs (older than 30 days)."""
    log_file = Path("data/logs/auth.log")
    
    if not log_file.exists():
        return JSONResponse({"success": True, "deleted": 0})
    
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    kept_logs = []
    deleted_count = 0
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
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
        with open(log_file, 'w', encoding='utf-8') as f:
            f.writelines(kept_logs)
    
    except Exception as e:
        logger.error(f"Failed to cleanup logs: {e}")
        return JSONResponse({"error": "Failed to cleanup logs"}, status_code=500)
    
    return JSONResponse({"success": True, "deleted": deleted_count})


@api_error_handler
async def api_update_user_status(request: Request) -> Response:
    """Update user active status."""
    user_id = int(request.path_params["user_id"])
    body = await request.json()
    is_active = body.get("is_active", True)

    # Safety check: prevent deactivating the last active superuser
    if not is_active:
        users = get_all_users(_config.auth.sqlite_path)
        user = next((u for u in users if u["id"] == user_id), None)

        if user and user["is_superuser"]:
            active_superusers = [
                u for u in users
                if u["is_superuser"] and u["is_active"] and u["id"] != user_id
            ]

            if len(active_superusers) == 0:
                return JSONResponse(
                    {"error": "Cannot deactivate the last active superuser"},
                    status_code=400
                )

    update_user_status(_config.auth.sqlite_path, user_id, is_active)
    return Response(status_code=200)


@api_error_handler
async def api_make_superuser(request: Request) -> Response:
    """Make user a superuser."""
    user_id = int(request.path_params["user_id"])
    make_user_superuser(_config.auth.sqlite_path, user_id)
    return Response(status_code=200)


@api_error_handler
async def api_delete_user(request: Request) -> JSONResponse:
    """Delete user."""
    from authmcp_gateway.auth.user_store import delete_user

    user_id = int(request.path_params["user_id"])

    # Safety check: prevent deleting the last active superuser
    users = get_all_users(_config.auth.sqlite_path)
    user = next((u for u in users if u["id"] == user_id), None)

    if user and user["is_superuser"]:
        active_superusers = [
            u for u in users
            if u["is_superuser"] and u["is_active"] and u["id"] != user_id
        ]

        if len(active_superusers) == 0:
            return JSONResponse(
                {"error": "Cannot delete the last active superuser"},
                status_code=400
            )

    # Delete user
    success = delete_user(_config.auth.sqlite_path, user_id)

    if success:
        return JSONResponse({"message": "User deleted successfully"})
    else:
        return JSONResponse({"error": "User not found"}, status_code=404)


async def admin_settings(_: Request) -> HTMLResponse:
    """Admin settings page."""
    return render_template("admin/settings.html", active_page="settings")


async def api_get_settings(_: Request) -> JSONResponse:
    """Get current settings."""
    from authmcp_gateway.settings_manager import get_settings_manager
    settings_manager = get_settings_manager()
    return JSONResponse(settings_manager.get_all())


@api_error_handler
async def api_save_settings(request: Request) -> JSONResponse:
    """Save settings."""
    from authmcp_gateway.settings_manager import get_settings_manager
    settings_manager = get_settings_manager()

    body = await request.json()
    settings_manager.update(body)
    settings_manager.save()

    return JSONResponse({"success": True, "message": "Settings saved successfully"})


# ============================================================================
# MCP SERVERS MANAGEMENT
# ============================================================================

async def admin_mcp_servers(_: Request) -> HTMLResponse:
    """MCP servers management page."""
    return render_template("admin/mcp_servers.html", active_page="mcp-servers")


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
        exp = decoded.get('exp')
        
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
                "has_expiration": True
            }
        else:
            # JWT without exp claim - never expires
            return {
                "status": "never",
                "has_expiration": False,
                "message": "No expiration"
            }
    except Exception as e:
        logger.debug(f"Failed to parse JWT token: {e}")
    
    return {
        "status": "unknown",
        "has_expiration": False,
        "message": "Not a JWT token"
    }


async def api_list_mcp_servers(_: Request) -> JSONResponse:
    """API: List all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers

    servers = list_mcp_servers(_config.auth.sqlite_path)

    return JSONResponse({"servers": servers})


async def api_mcp_servers_token_status(_: Request) -> JSONResponse:
    """API: Get token expiration status for all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers

    servers = list_mcp_servers(_config.auth.sqlite_path)
    
    result = []
    for server in servers:
        token_info = {"status": "none"}  # Default for servers without auth
        
        # Only check Bearer tokens
        if server.get("auth_type") == "bearer" and server.get("auth_token"):
            token_info = parse_jwt_expiration(server["auth_token"])
        
        result.append({
            "id": server["id"],
            "name": server["name"],
            "auth_type": server["auth_type"],
            "token_status": token_info
        })
    
    return JSONResponse({"servers": result})


@api_error_handler
async def api_create_mcp_server(request: Request) -> JSONResponse:
    """API: Create new MCP server."""
    from authmcp_gateway.mcp.store import create_mcp_server

    data = await request.json()

    server_id = create_mcp_server(
        db_path=_config.auth.sqlite_path,
        name=data["name"],
        url=data["url"],
        description=data.get("description"),
        tool_prefix=data.get("tool_prefix"),
        enabled=data.get("enabled", True),
        auth_type=data.get("auth_type", "none"),
        auth_token=data.get("auth_token"),
        routing_strategy=data.get("routing_strategy", "prefix")
    )

    # Trigger health check for new server
    from authmcp_gateway.mcp.health import get_health_checker
    try:
        health_checker = get_health_checker()
        from authmcp_gateway.mcp.store import get_mcp_server
        server = get_mcp_server(_config.auth.sqlite_path, server_id)
        if server:
            await health_checker.check_server(server)
    except:
        pass  # Health checker might not be initialized yet

    return JSONResponse({"id": server_id, "message": "Server created successfully"})


@api_error_handler
async def api_delete_mcp_server(request: Request) -> JSONResponse:
    """API: Delete MCP server."""
    from authmcp_gateway.mcp.store import delete_mcp_server

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
    from authmcp_gateway.mcp.store import update_mcp_server, get_mcp_server

    server_id = int(request.path_params["server_id"])
    data = await request.json()

    # Update server
    success = update_mcp_server(
        db_path=_config.auth.sqlite_path,
        server_id=server_id,
        **data
    )

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
        except:
            pass  # Health checker might not be initialized yet

        return JSONResponse({"message": "Server updated successfully"})
    else:
        return JSONResponse({"error": "Server not found"}, status_code=404)


@api_error_handler
async def api_test_mcp_server(request: Request) -> JSONResponse:
    """API: Test MCP server connection."""
    from authmcp_gateway.mcp.health import HealthChecker
    from authmcp_gateway.mcp.store import get_mcp_server

    server_id = int(request.path_params["server_id"])
    server = get_mcp_server(_config.auth.sqlite_path, server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    # Perform health check
    health_checker = HealthChecker(_config.auth.sqlite_path)
    result = await health_checker.check_server(server)

    # Convert datetime to ISO string for JSON serialization
    if 'checked_at' in result and result['checked_at']:
        result['checked_at'] = result['checked_at'].isoformat()

    return JSONResponse(result)


@api_error_handler
async def api_security_events(request: Request) -> JSONResponse:
    """Get security events with filters."""
    from authmcp_gateway.security.logger import get_security_events
    
    severity = request.query_params.get("severity")
    event_type = request.query_params.get("event_type")
    limit = int(request.query_params.get("limit", "100"))
    last_hours = request.query_params.get("last_hours")
    
    events = get_security_events(
        db_path=_config.auth.sqlite_path,
        severity=severity,
        event_type=event_type,
        limit=limit,
        last_hours=int(last_hours) if last_hours else None
    )
    
    return JSONResponse(events)


@api_error_handler
async def api_mcp_stats(request: Request) -> JSONResponse:
    """Get MCP request statistics."""
    from authmcp_gateway.security.logger import get_mcp_request_stats
    from authmcp_gateway.mcp.store import list_mcp_servers
    
    last_hours = int(request.query_params.get("last_hours", "24"))
    include_top_tools = request.query_params.get("include_top_tools", "false").lower() == "true"
    
    # Get request stats
    stats = get_mcp_request_stats(
        db_path=_config.auth.sqlite_path,
        last_hours=last_hours
    )
    
    # Get server stats
    servers = list_mcp_servers(_config.auth.sqlite_path, enabled_only=False)
    active_servers = sum(1 for s in servers if s.get('status') == 'online')
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
            {
                "name": t["tool"],
                "count": t["count"],
                "server": "Unknown"  # TODO: Add server info to log
            }
            for t in top_tools
        ]
    
    return JSONResponse(result)


@api_error_handler
async def api_cleanup_logs(request: Request) -> JSONResponse:
    """Cleanup old logs."""
    from authmcp_gateway.security.logger import cleanup_old_logs
    
    body = await request.json()
    days_to_keep = body.get("days_to_keep", 30)
    
    result = cleanup_old_logs(
        db_path=_config.auth.sqlite_path,
        days_to_keep=days_to_keep
    )
    
    return JSONResponse(result)


@api_error_handler
async def api_get_mcp_server_tools(request: Request) -> JSONResponse:
    """API: Get tools from MCP server."""
    from authmcp_gateway.mcp.proxy import McpProxy
    from authmcp_gateway.mcp.store import get_mcp_server

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


# ============================================================================
# BACKEND TOKEN MANAGEMENT
# ============================================================================

async def admin_mcp_tokens(request: Request) -> HTMLResponse:
    """Admin page: Backend MCP token management."""
    if _config is None:
        return HTMLResponse("<h1>Error: Config not initialized</h1>", status_code=500)

    return render_template("admin/mcp_tokens.html")


@api_error_handler
async def api_get_token_statuses(request: Request) -> JSONResponse:
    """API: Get token status for all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers
    from datetime import datetime, timezone

    servers = list_mcp_servers(_config.auth.sqlite_path, enabled_only=False)

    token_statuses = []
    for server in servers:
        # Calculate token status
        token_expires_at = server.get('token_expires_at')
        token_expired = False
        time_until_expiry_seconds = None

        if token_expires_at:
            if isinstance(token_expires_at, str):
                # Parse ISO format datetime
                try:
                    token_expires_at = datetime.fromisoformat(token_expires_at.replace('Z', '+00:00'))
                except:
                    token_expires_at = None

            if token_expires_at:
                now = datetime.now(timezone.utc)
                if token_expires_at.tzinfo is None:
                    token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

                delta = token_expires_at - now
                time_until_expiry_seconds = int(delta.total_seconds())
                token_expired = time_until_expiry_seconds <= 0

        status = {
            'server_id': server['id'],
            'server_name': server['name'],
            'auth_type': server.get('auth_type', 'none'),
            'has_refresh_token': bool(server.get('refresh_token_hash')),
            'token_expires_at': server.get('token_expires_at'),
            'token_expired': token_expired,
            'time_until_expiry_seconds': time_until_expiry_seconds,
            'last_refreshed': server.get('token_last_refreshed'),
            'can_auto_refresh': bool(
                server.get('refresh_token_hash') and
                server.get('refresh_endpoint')
            )
        }
        token_statuses.append(status)

    return JSONResponse(token_statuses)


@api_error_handler
async def api_get_token_audit_logs(request: Request) -> JSONResponse:
    """API: Get token refresh audit logs."""
    from authmcp_gateway.mcp.store import get_token_audit_logs

    # Get limit from query params
    limit = int(request.query_params.get('limit', 50))
    server_id = request.query_params.get('server_id')

    if server_id:
        server_id = int(server_id)

    logs = get_token_audit_logs(
        db_path=_config.auth.sqlite_path,
        mcp_server_id=server_id,
        limit=limit
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
    success, error = await token_mgr.refresh_server_token(
        server_id,
        triggered_by='manual'
    )

    if success:
        return JSONResponse({"detail": "Token refreshed successfully"})
    else:
        return JSONResponse(
            {"detail": f"Failed to refresh token: {error}"},
            status_code=400
        )


@requires_admin
async def admin_mcp_activity(request: Request) -> HTMLResponse:
    """MCP Activity monitoring page - real-time view."""
    return render_template("admin/mcp_activity.html", active_page="mcp-activity")


@requires_admin
async def admin_mcp_requests_api(request: Request) -> Response:
    """API endpoint for live MCP requests."""
    from authmcp_gateway.security.logger import get_mcp_requests
    
    # Get query parameters
    limit = int(request.query_params.get("limit", "50"))
    last_seconds = int(request.query_params.get("last_seconds", "60"))
    method = request.query_params.get("method")
    success_param = request.query_params.get("success")
    
    success = None
    if success_param is not None:
        success = success_param.lower() == "true"
    
    requests = get_mcp_requests(
        db_path=_config.auth.sqlite_path,
        limit=limit,
        last_seconds=last_seconds,
        method=method,
        success=success,
    )
    
    return JSONResponse({"requests": requests})


# ============================================================================
# MCP SECURITY AUDIT
# ============================================================================

@requires_admin
async def admin_mcp_audit(request: Request) -> HTMLResponse:
    """MCP Security Audit page - audit any MCP server security."""
    return render_template("admin/mcp_audit.html", active_page="mcp-audit")


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
    
    # Run security audit
    auditor = MCPSecurityAuditor(url, bearer_token)
    results = auditor.run_all_tests()
    
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
