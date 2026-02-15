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
from starlette.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
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
jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)

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


async def user_portal(request: Request) -> HTMLResponse:
    """User portal page for obtaining access token (non-admin)."""
    from authmcp_gateway.auth.jwt_handler import verify_token

    token = request.cookies.get("user_token")
    if not token:
        return RedirectResponse(url="/login", status_code=302)

    try:
        payload = verify_token(token, "access", _config.jwt)
        if payload.get("is_superuser"):
            return RedirectResponse(url="/admin", status_code=302)
    except Exception:
        return RedirectResponse(url="/login", status_code=302)

    username = payload.get("username")
    if not username and payload.get("sub"):
        try:
            user = get_user_by_id(_config.auth.sqlite_path, int(payload["sub"]))
            if user:
                username = user.get("username")
        except Exception:
            username = None

    return render_template("user_portal.html", username=username)


async def user_login_page(_: Request) -> HTMLResponse:
    """User login page (non-admin)."""
    return render_template("user_login.html")


async def user_login_api(request: Request) -> JSONResponse:
    """Login for non-admin users and set user_token cookie."""
    from authmcp_gateway.auth.user_store import (
        get_user_by_username,
        update_last_login,
        log_auth_event,
    )
    from authmcp_gateway.auth.password import verify_password
    from authmcp_gateway.auth.token_service import get_or_create_admin_token
    from authmcp_gateway.config import load_config

    body = await request.json()
    username = body.get("username")
    password = body.get("password")

    if not username or not password:
        return JSONResponse({"detail": "Username and password required"}, status_code=400)

    user = get_user_by_username(_config.auth.sqlite_path, username)
    if not user or not verify_password(password, user["password_hash"]):
        log_auth_event(
            db_path=_config.auth.sqlite_path,
            event_type="login",
            username=username,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
            details="Invalid credentials"
        )
        return JSONResponse({"detail": "Invalid username or password"}, status_code=401)

    if user.get("is_superuser"):
        return JSONResponse(
            {"detail": "Admin accounts must use the admin panel."},
            status_code=403
        )

    update_last_login(_config.auth.sqlite_path, user["id"])

    config = load_config()
    access_token, _ = get_or_create_admin_token(
        _config.auth.sqlite_path,
        user["id"],
        user["username"],
        False,
        config.jwt,
        config.jwt.access_token_expire_minutes,
        current_token=request.cookies.get("user_token"),
    )

    response = JSONResponse({"success": True})
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_logout(_: Request) -> Response:
    """Clear user session cookie."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("user_token")
    return response


async def user_account_token(request: Request) -> JSONResponse:
    """Return access token for authenticated non-admin user."""
    from authmcp_gateway.auth.jwt_handler import verify_token, decode_token_unsafe
    from authmcp_gateway.auth.user_store import is_token_blacklisted, get_user_by_id
    from authmcp_gateway.auth.token_service import get_or_create_admin_token
    from authmcp_gateway.config import load_config

    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    try:
        payload = verify_token(token, "access", _config.jwt)
        jti = decode_token_unsafe(token).get("jti")
        if jti and is_token_blacklisted(_config.auth.sqlite_path, jti):
            return JSONResponse({"detail": "Token revoked"}, status_code=401)
        if payload.get("is_superuser"):
            return JSONResponse({"detail": "Admin accounts must use the admin panel."}, status_code=403)
    except Exception:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    user_id = payload.get("sub")
    username = payload.get("username")
    if not username and user_id:
        user = get_user_by_id(_config.auth.sqlite_path, int(user_id))
        username = user["username"] if user else ""

    config = load_config()
    access_token, _ = get_or_create_admin_token(
        _config.auth.sqlite_path,
        int(user_id),
        username,
        False,
        config.jwt,
        config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    response = JSONResponse({"access_token": access_token})
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_account_rotate_token(request: Request) -> JSONResponse:
    """Rotate access token for authenticated non-admin user."""
    from authmcp_gateway.auth.jwt_handler import verify_token, decode_token_unsafe
    from authmcp_gateway.auth.user_store import is_token_blacklisted
    from authmcp_gateway.auth.token_service import rotate_admin_token
    from authmcp_gateway.config import load_config

    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    try:
        payload = verify_token(token, "access", _config.jwt)
        jti = decode_token_unsafe(token).get("jti")
        if jti and is_token_blacklisted(_config.auth.sqlite_path, jti):
            return JSONResponse({"detail": "Token revoked"}, status_code=401)
        if payload.get("is_superuser"):
            return JSONResponse({"detail": "Admin accounts must use the admin panel."}, status_code=403)
    except Exception:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    config = load_config()
    user_id = int(payload.get("sub"))
    username = payload.get("username")
    new_token, _ = rotate_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        False,
        config.jwt,
        config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    response = JSONResponse({"access_token": new_token})
    response.set_cookie(
        "user_token",
        new_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_account_info(request: Request) -> JSONResponse:
    """Return user info, token expiry, and accessible MCP servers."""
    from authmcp_gateway.auth.jwt_handler import verify_token, decode_token_unsafe
    from authmcp_gateway.auth.user_store import is_token_blacklisted, get_user_by_id
    from authmcp_gateway.auth.token_service import get_or_create_admin_token
    from authmcp_gateway.mcp.store import list_mcp_servers
    from datetime import datetime, timezone
    from authmcp_gateway.config import load_config

    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    try:
        payload = verify_token(token, "access", _config.jwt)
        jti = decode_token_unsafe(token).get("jti")
        if jti and is_token_blacklisted(_config.auth.sqlite_path, jti):
            return JSONResponse({"detail": "Token revoked"}, status_code=401)
        if payload.get("is_superuser"):
            return JSONResponse({"detail": "Admin accounts must use the admin panel."}, status_code=403)
    except Exception:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    user_id = payload.get("sub")
    username = payload.get("username")
    if not username and user_id:
        user = get_user_by_id(_config.auth.sqlite_path, int(user_id))
        username = user["username"] if user else ""

    config = load_config()
    access_token, exp_dt = get_or_create_admin_token(
        _config.auth.sqlite_path,
        int(user_id),
        username,
        False,
        config.jwt,
        config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    expires_at = None
    expires_in_seconds = None
    if exp_dt:
        try:
            expires_at = exp_dt.isoformat()
            expires_in_seconds = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
        except Exception:
            pass

    servers = list_mcp_servers(_config.auth.sqlite_path, enabled_only=True, user_id=int(user_id) if user_id else None)
    public_base = (_config.mcp_public_url or "").rstrip("/")
    server_list = []
    from authmcp_gateway.mcp.proxy import normalize_server_name
    for s in servers:
        server_slug = normalize_server_name(s["name"])
        server_list.append({
            "id": s["id"],
            "name": s["name"],
            "endpoint": f"{public_base}/mcp/{server_slug}" if public_base else f"/mcp/{server_slug}"
        })

    response = JSONResponse({
        "username": username,
        "expires_at": expires_at,
        "expires_in_seconds": expires_in_seconds,
        "servers": server_list,
        "gateway_endpoint": f"{public_base}/mcp" if public_base else "/mcp"
    })
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=config.jwt.access_token_expire_minutes * 60,
    )
    return response


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
        ("mcp-activity", "/admin/mcp-activity", '<i class="bi bi-activity"></i> MCP Activity'),
        ("mcp-servers", "/admin/mcp-servers", '<i class="bi bi-hdd-network"></i> MCP Servers'),
        ("security-logs", "/admin/security-logs", '<i class="bi bi-shield-exclamation"></i> Security Events'),
        ("mcp-audit", "/admin/mcp-audit", '<i class="bi bi-shield-check"></i> Security Audit'),
        ("settings", "/admin/settings", '<i class="bi bi-gear"></i> Settings'),
        ("oauth-clients", "/admin/oauth-clients", '<i class="bi bi-shield-lock"></i> OAuth Clients'),
        ("users", "/admin/users", '<i class="bi bi-people"></i> Users'),
        ("logs", "/admin/logs", '<i class="bi bi-clock-history"></i> Auth Logs'),
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
async def admin_oauth_clients(_: Request) -> HTMLResponse:
    """Admin OAuth clients management page."""
    return render_template("admin/oauth_clients.html", active_page="oauth-clients")


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
async def api_get_user_mcp_permissions(request: Request) -> JSONResponse:
    """Get MCP server access permissions for a user."""
    user_id = int(request.path_params["user_id"])

    users = get_all_users(_config.auth.sqlite_path)
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        return JSONResponse({"error": "User not found"}, status_code=404)

    from authmcp_gateway.mcp.store import list_mcp_servers, get_user_mcp_permissions

    servers = list_mcp_servers(_config.auth.sqlite_path, enabled_only=False)
    permissions = get_user_mcp_permissions(_config.auth.sqlite_path, user_id)
    perm_map = {p["mcp_server_id"]: p for p in permissions}

    response_servers = []
    for server in servers:
        perm = perm_map.get(server["id"])
        can_access = True if perm is None else bool(perm.get("can_access"))
        response_servers.append({
            "server_id": server["id"],
            "name": server["name"],
            "url": server["url"],
            "enabled": bool(server.get("enabled", 1)),
            "can_access": can_access,
            "source": "default" if perm is None else "explicit"
        })

    return JSONResponse({
        "user": {"id": user["id"], "username": user["username"]},
        "servers": response_servers
    })


@api_error_handler
async def api_set_user_mcp_permission(request: Request) -> JSONResponse:
    """Set MCP server access permission for a user."""
    user_id = int(request.path_params["user_id"])
    body = await request.json()
    server_id = body.get("server_id")
    can_access = body.get("can_access")

    if server_id is None or can_access is None:
        return JSONResponse({"error": "server_id and can_access are required"}, status_code=400)

    from authmcp_gateway.mcp.store import get_mcp_server, set_user_mcp_permission

    server = get_mcp_server(_config.auth.sqlite_path, int(server_id))
    if not server:
        return JSONResponse({"error": "MCP server not found"}, status_code=404)

    set_user_mcp_permission(
        db_path=_config.auth.sqlite_path,
        user_id=user_id,
        mcp_server_id=int(server_id),
        can_access=bool(can_access)
    )

    return JSONResponse({
        "success": True,
        "server_id": int(server_id),
        "can_access": bool(can_access)
    })


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
    """Get auth logs from database with pagination."""
    event_type = request.query_params.get("event_type")
    limit = int(request.query_params.get("limit", "50"))
    offset = int(request.query_params.get("offset", "0"))
    days = request.query_params.get("days")  # Filter by days (e.g., "1", "7", "30")

    try:
        import sqlite3
        conn = sqlite3.connect(_config.auth.sqlite_path)
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
            params + [limit, offset]
        )

        logs = []
        for row in cursor.fetchall():
            logs.append({
                "event_type": row[0],
                "user_id": row[1],
                "username": row[2],
                "ip_address": row[3],
                "user_agent": row[4],
                "success": bool(row[5]),
                "details": row[6],
                "timestamp": row[7]
            })

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
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    event_type = entry.get("event_type")
                    details = entry.get("details") or ""
                    if event_type not in allowed_types:
                        if event_type == "login" and ("Authorization code flow" in details or "password grant" in details):
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


async def admin_settings(request: Request) -> HTMLResponse:
    """Admin settings page with current user's access token."""
    # Get current user from request state (set by AdminAuthMiddleware)
    user_id = request.state.user_id
    username = request.state.username
    is_superuser = request.state.is_superuser
    
    # Reuse stored token or rotate if needed
    from datetime import datetime, timezone, timedelta
    from authmcp_gateway.auth.token_service import get_or_create_admin_token, format_expires_in
    from authmcp_gateway.config import load_config
    config = load_config()
    
    access_token, exp_dt = get_or_create_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        is_superuser,
        config.jwt,
        config.jwt.admin_token_expire_minutes,
        current_token=request.cookies.get("admin_token"),
    )
    token_expires_in = format_expires_in(exp_dt)
    if not token_expires_in:
        token_expires_in = format_expires_in(
            datetime.now(timezone.utc) + timedelta(minutes=config.jwt.admin_token_expire_minutes)
        )
    
    return render_template(
        "admin/settings.html",
        active_page="settings",
        access_token=access_token,
        token_expires_in=token_expires_in,
    )


@api_error_handler
async def api_admin_access_token(request: Request) -> JSONResponse:
    """API: Get current admin access token."""
    user_id = request.state.user_id
    username = request.state.username
    is_superuser = request.state.is_superuser
    from authmcp_gateway.auth.token_service import get_or_create_admin_token, format_expires_in
    from authmcp_gateway.config import load_config

    config = load_config()
    access_token, exp_dt = get_or_create_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        is_superuser,
        config.jwt,
        config.jwt.admin_token_expire_minutes,
        current_token=request.cookies.get("admin_token"),
    )
    token_expires_in = format_expires_in(exp_dt)

    return JSONResponse({"access_token": access_token, "token_expires_in": token_expires_in})


@api_error_handler
async def api_admin_rotate_token(request: Request) -> JSONResponse:
    """API: Rotate admin access token."""
    user_id = request.state.user_id
    username = request.state.username
    is_superuser = request.state.is_superuser
    from authmcp_gateway.auth.token_service import rotate_admin_token, format_expires_in
    from authmcp_gateway.config import load_config

    config = load_config()
    current_token = request.cookies.get("admin_token")
    new_token, exp_dt = rotate_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        is_superuser,
        config.jwt,
        config.jwt.admin_token_expire_minutes,
        current_token=current_token,
    )
    token_expires_in = format_expires_in(exp_dt)

    response = JSONResponse({"access_token": new_token, "token_expires_in": token_expires_in})
    is_https = (
        request.url.scheme == "https" or
        request.headers.get("x-forwarded-proto") == "https"
    )
    response.set_cookie(
        key="admin_token",
        value=new_token,
        path="/",
        httponly=True,
        secure=is_https,
        samesite="lax",
        max_age=config.jwt.admin_token_expire_minutes * 60
    )
    return response


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

    # Apply all settings to live config immediately
    try:
        jwt_s = body.get("jwt") or {}
        if "access_token_expire_minutes" in jwt_s:
            _config.jwt.access_token_expire_minutes = int(jwt_s["access_token_expire_minutes"])
        if "refresh_token_expire_days" in jwt_s:
            _config.jwt.refresh_token_expire_days = int(jwt_s["refresh_token_expire_days"])
        if "enforce_single_session" in jwt_s:
            _config.jwt.enforce_single_session = bool(jwt_s["enforce_single_session"])

        pw = body.get("password_policy") or {}
        if "min_length" in pw:
            _config.auth.password_min_length = int(pw["min_length"])
        if "require_uppercase" in pw:
            _config.auth.password_require_uppercase = bool(pw["require_uppercase"])
        if "require_lowercase" in pw:
            _config.auth.password_require_lowercase = bool(pw["require_lowercase"])
        if "require_digit" in pw:
            _config.auth.password_require_digit = bool(pw["require_digit"])
        if "require_special" in pw:
            _config.auth.password_require_special = bool(pw["require_special"])

        sys_s = body.get("system") or {}
        if "allow_registration" in sys_s:
            _config.auth.allow_registration = bool(sys_s["allow_registration"])
        if "allow_dcr" in sys_s:
            _config.auth.allow_dcr = bool(sys_s["allow_dcr"])
        if "auth_required" in sys_s:
            _config.auth_required = bool(sys_s["auth_required"])

        rl = body.get("rate_limit") or {}
        if "mcp_limit" in rl:
            _config.rate_limit.mcp_limit = int(rl["mcp_limit"])
        if "mcp_window" in rl:
            _config.rate_limit.mcp_window = int(rl["mcp_window"])
        if "login_limit" in rl:
            _config.rate_limit.login_limit = int(rl["login_limit"])
        if "login_window" in rl:
            _config.rate_limit.login_window = int(rl["login_window"])
        if "register_limit" in rl:
            _config.rate_limit.register_limit = int(rl["register_limit"])
        if "register_window" in rl:
            _config.rate_limit.register_window = int(rl["register_window"])

        logger.info("Dynamic settings applied from admin panel")
    except Exception as e:
        logger.warning(f"Failed to apply some admin settings: {e}")

    return JSONResponse({"success": True, "message": "Settings saved successfully"})


# ============================================================================
# OAUTH CLIENTS MANAGEMENT
# ============================================================================

@api_error_handler
async def api_list_oauth_clients(_: Request) -> JSONResponse:
    """List OAuth clients."""
    from authmcp_gateway.auth.client_store import list_oauth_clients
    clients = list_oauth_clients(_config.auth.sqlite_path)
    return JSONResponse(clients)


@api_error_handler
async def api_rotate_oauth_client_token(request: Request) -> JSONResponse:
    """Rotate registration token for OAuth client."""
    client_id = request.path_params["client_id"]
    from authmcp_gateway.auth.client_store import rotate_registration_token
    new_token = rotate_registration_token(_config.auth.sqlite_path, client_id)
    if not new_token:
        return JSONResponse({"error": "Client not found"}, status_code=404)
    return JSONResponse({"registration_access_token": new_token})


@api_error_handler
async def api_delete_oauth_client(request: Request) -> JSONResponse:
    """Delete OAuth client."""
    client_id = request.path_params["client_id"]
    from authmcp_gateway.auth.client_store import delete_oauth_client
    deleted = delete_oauth_client(_config.auth.sqlite_path, client_id)
    if not deleted:
        return JSONResponse({"error": "Client not found"}, status_code=404)
    return JSONResponse({"success": True})


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
    except Exception as e:
        # Health checker might not be initialized yet; log for visibility.
        logger.debug(f"Health check skipped for new server {server_id}: {e}")

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
                "server": t.get("server_name") or "Unknown"
            }
            for t in top_tools
        ]
    
    return JSONResponse(result)


@api_error_handler
async def api_cleanup_db_logs(request: Request) -> JSONResponse:
    """Cleanup old DB logs (security + MCP)."""
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
