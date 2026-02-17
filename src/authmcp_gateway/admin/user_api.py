"""Admin API: User management."""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from authmcp_gateway.admin.routes import api_error_handler, get_config
from authmcp_gateway.auth.user_store import (
    get_all_users,
    get_user_by_id,
    make_user_superuser,
    update_user_status,
)

logger = logging.getLogger(__name__)

__all__ = [
    "api_stats",
    "api_users",
    "api_get_user_mcp_permissions",
    "api_set_user_mcp_permission",
    "api_create_user",
    "api_update_user_status",
    "api_make_superuser",
    "api_delete_user",
]


async def api_stats(_: Request) -> JSONResponse:
    """Get dashboard statistics."""
    from authmcp_gateway.db import get_db

    _config = get_config()
    with get_db(_config.auth.sqlite_path, row_factory=None) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_superuser = 1")
        superusers = cursor.fetchone()[0]

        day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        cursor.execute(
            "SELECT COUNT(*) FROM auth_audit_log "
            "WHERE event_type IN ('login', 'admin_login') AND success = 1 AND timestamp >= ?",
            (day_ago,),
        )
        recent_logins = cursor.fetchone()[0]

    return JSONResponse(
        {
            "total_users": total_users,
            "active_users": active_users,
            "superusers": superusers,
            "recent_logins": recent_logins,
            "system": {
                "jwt_algorithm": _config.jwt.algorithm,
                "access_token_ttl": f"{_config.jwt.access_token_expire_minutes} min",
                "refresh_token_ttl": f"{_config.jwt.refresh_token_expire_days} days",
                "public_url": _config.mcp_public_url,
            },
        }
    )


@api_error_handler
async def api_users(_: Request) -> JSONResponse:
    """Get all users."""
    users = get_all_users(get_config().auth.sqlite_path)
    return JSONResponse(users)


@api_error_handler
async def api_get_user_mcp_permissions(request: Request) -> JSONResponse:
    """Get MCP server access permissions for a user."""
    _config = get_config()
    user_id = int(request.path_params["user_id"])

    user = get_user_by_id(_config.auth.sqlite_path, user_id)
    if not user:
        return JSONResponse({"error": "User not found"}, status_code=404)

    from authmcp_gateway.mcp.store import get_user_mcp_permissions, list_mcp_servers

    servers = list_mcp_servers(_config.auth.sqlite_path, enabled_only=False)
    permissions = get_user_mcp_permissions(_config.auth.sqlite_path, user_id)
    perm_map = {p["mcp_server_id"]: p for p in permissions}

    response_servers = []
    for server in servers:
        perm = perm_map.get(server["id"])
        can_access = True if perm is None else bool(perm.get("can_access"))
        response_servers.append(
            {
                "server_id": server["id"],
                "name": server["name"],
                "url": server["url"],
                "enabled": bool(server.get("enabled", 1)),
                "can_access": can_access,
                "source": "default" if perm is None else "explicit",
            }
        )

    return JSONResponse(
        {"user": {"id": user["id"], "username": user["username"]}, "servers": response_servers}
    )


@api_error_handler
async def api_set_user_mcp_permission(request: Request) -> JSONResponse:
    """Set MCP server access permission for a user."""
    _config = get_config()
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
        can_access=bool(can_access),
    )

    return JSONResponse(
        {"success": True, "server_id": int(server_id), "can_access": bool(can_access)}
    )


@api_error_handler
async def api_create_user(request: Request) -> JSONResponse:
    """Create new user (admin endpoint - bypasses allow_registration check)."""
    import re

    from authmcp_gateway.auth.password import hash_password
    from authmcp_gateway.auth.user_store import create_user
    from authmcp_gateway.settings_manager import get_settings_manager

    _config = get_config()
    body = await request.json()
    username = body.get("username")
    email = body.get("email")
    password = body.get("password")
    is_superuser = body.get("is_superuser", False)

    # Validate input
    if not username or not email or not password:
        return JSONResponse(
            {"error": "Username, email, and password are required"}, status_code=400
        )

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
        return JSONResponse(
            {"error": f"Password must be at least {min_length} characters long"}, status_code=400
        )

    # Check for uppercase letter
    if require_uppercase and not re.search(r"[A-Z]", password):
        return JSONResponse(
            {"error": "Password must contain at least one uppercase letter"}, status_code=400
        )

    # Check for lowercase letter
    if require_lowercase and not re.search(r"[a-z]", password):
        return JSONResponse(
            {"error": "Password must contain at least one lowercase letter"}, status_code=400
        )

    # Check for digit
    if require_digit and not re.search(r"\d", password):
        return JSONResponse({"error": "Password must contain at least one digit"}, status_code=400)

    # Check for special character
    if require_special and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        return JSONResponse(
            {"error": "Password must contain at least one special character"}, status_code=400
        )

    # Hash password and create user
    password_hash = hash_password(password)

    try:
        user_id = create_user(
            db_path=_config.auth.sqlite_path,
            username=username,
            email=email,
            password_hash=password_hash,
            is_superuser=is_superuser,
        )

        return JSONResponse(
            {"id": user_id, "username": username, "email": email, "is_superuser": is_superuser},
            status_code=201,
        )

    except sqlite3.IntegrityError:
        return JSONResponse({"error": "Username or email already exists"}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@api_error_handler
async def api_update_user_status(request: Request) -> Response:
    """Update user active status."""
    _config = get_config()
    user_id = int(request.path_params["user_id"])
    body = await request.json()
    is_active = body.get("is_active", True)

    # Safety check: prevent deactivating the last active superuser
    if not is_active:
        users = get_all_users(_config.auth.sqlite_path)
        user = next((u for u in users if u["id"] == user_id), None)

        if user and user["is_superuser"]:
            active_superusers = [
                u for u in users if u["is_superuser"] and u["is_active"] and u["id"] != user_id
            ]

            if len(active_superusers) == 0:
                return JSONResponse(
                    {"error": "Cannot deactivate the last active superuser"}, status_code=400
                )

    update_user_status(_config.auth.sqlite_path, user_id, is_active)
    return Response(status_code=200)


@api_error_handler
async def api_make_superuser(request: Request) -> Response:
    """Make user a superuser."""
    user_id = int(request.path_params["user_id"])
    make_user_superuser(get_config().auth.sqlite_path, user_id)
    return Response(status_code=200)


@api_error_handler
async def api_delete_user(request: Request) -> JSONResponse:
    """Delete user."""
    from authmcp_gateway.auth.user_store import delete_user

    _config = get_config()
    user_id = int(request.path_params["user_id"])

    # Safety check: prevent deleting the last active superuser
    users = get_all_users(_config.auth.sqlite_path)
    user = next((u for u in users if u["id"] == user_id), None)

    if user and user["is_superuser"]:
        active_superusers = [
            u for u in users if u["is_superuser"] and u["is_active"] and u["id"] != user_id
        ]

        if len(active_superusers) == 0:
            return JSONResponse(
                {"error": "Cannot delete the last active superuser"}, status_code=400
            )

    # Delete user
    success = delete_user(_config.auth.sqlite_path, user_id)

    if success:
        return JSONResponse({"message": "User deleted successfully"})
    else:
        return JSONResponse({"error": "User not found"}, status_code=404)
