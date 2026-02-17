"""Admin: User portal pages (login, account, token management)."""

import logging

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from authmcp_gateway.admin.routes import get_config, render_template

logger = logging.getLogger(__name__)

__all__ = [
    "user_portal",
    "user_login_page",
    "user_login_api",
    "user_logout",
    "user_account_token",
    "user_account_rotate_token",
    "user_account_info",
]


async def user_portal(request: Request) -> HTMLResponse:
    """User portal page for obtaining access token (non-admin)."""
    from authmcp_gateway.auth.jwt_handler import verify_token
    from authmcp_gateway.auth.user_store import get_user_by_id

    _config = get_config(request)
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


async def user_login_page(request: Request) -> HTMLResponse:
    """User login page (non-admin)."""
    return render_template("user_login.html")


async def user_login_api(request: Request) -> JSONResponse:
    """Login for non-admin users and set user_token cookie."""
    from authmcp_gateway.auth.password import verify_password
    from authmcp_gateway.auth.token_service import get_or_create_admin_token
    from authmcp_gateway.auth.user_store import (
        get_user_by_username,
        log_auth_event,
        update_last_login,
    )

    _config = get_config(request)
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
            details="Invalid credentials",
        )
        return JSONResponse({"detail": "Invalid username or password"}, status_code=401)

    if user.get("is_superuser"):
        return JSONResponse({"detail": "Admin accounts must use the admin panel."}, status_code=403)

    update_last_login(_config.auth.sqlite_path, user["id"])

    access_token, _ = get_or_create_admin_token(
        _config.auth.sqlite_path,
        user["id"],
        user["username"],
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
        current_token=request.cookies.get("user_token"),
    )

    response = JSONResponse({"success": True})
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_logout(request: Request) -> Response:
    """Clear user session cookie."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("user_token")
    return response


async def user_account_token(request: Request) -> JSONResponse:
    """Return access token for authenticated non-admin user."""
    from authmcp_gateway.auth.jwt_handler import decode_token_unsafe, verify_token
    from authmcp_gateway.auth.token_service import get_or_create_admin_token
    from authmcp_gateway.auth.user_store import get_user_by_id, is_token_blacklisted

    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    try:
        payload = verify_token(token, "access", _config.jwt)
        jti = decode_token_unsafe(token).get("jti")
        if jti and is_token_blacklisted(_config.auth.sqlite_path, jti):
            return JSONResponse({"detail": "Token revoked"}, status_code=401)
        if payload.get("is_superuser"):
            return JSONResponse(
                {"detail": "Admin accounts must use the admin panel."}, status_code=403
            )
    except Exception:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    user_id = payload.get("sub")
    username = payload.get("username")
    if not username and user_id:
        user = get_user_by_id(_config.auth.sqlite_path, int(user_id))
        username = user["username"] if user else ""

    access_token, _ = get_or_create_admin_token(
        _config.auth.sqlite_path,
        int(user_id),
        username,
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    response = JSONResponse({"access_token": access_token})
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_account_rotate_token(request: Request) -> JSONResponse:
    """Rotate access token for authenticated non-admin user."""
    from authmcp_gateway.auth.jwt_handler import decode_token_unsafe, verify_token
    from authmcp_gateway.auth.token_service import rotate_admin_token
    from authmcp_gateway.auth.user_store import is_token_blacklisted

    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    try:
        payload = verify_token(token, "access", _config.jwt)
        jti = decode_token_unsafe(token).get("jti")
        if jti and is_token_blacklisted(_config.auth.sqlite_path, jti):
            return JSONResponse({"detail": "Token revoked"}, status_code=401)
        if payload.get("is_superuser"):
            return JSONResponse(
                {"detail": "Admin accounts must use the admin panel."}, status_code=403
            )
    except Exception:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    user_id = int(payload.get("sub"))
    username = payload.get("username")
    new_token, _ = rotate_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    response = JSONResponse({"access_token": new_token})
    response.set_cookie(
        "user_token",
        new_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_account_info(request: Request) -> JSONResponse:
    """Return user info, token expiry, and accessible MCP servers."""
    from datetime import datetime, timezone

    from authmcp_gateway.auth.jwt_handler import decode_token_unsafe, verify_token
    from authmcp_gateway.auth.token_service import get_or_create_admin_token
    from authmcp_gateway.auth.user_store import get_user_by_id, is_token_blacklisted
    from authmcp_gateway.mcp.store import list_mcp_servers

    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    try:
        payload = verify_token(token, "access", _config.jwt)
        jti = decode_token_unsafe(token).get("jti")
        if jti and is_token_blacklisted(_config.auth.sqlite_path, jti):
            return JSONResponse({"detail": "Token revoked"}, status_code=401)
        if payload.get("is_superuser"):
            return JSONResponse(
                {"detail": "Admin accounts must use the admin panel."}, status_code=403
            )
    except Exception:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    user_id = payload.get("sub")
    username = payload.get("username")
    if not username and user_id:
        user = get_user_by_id(_config.auth.sqlite_path, int(user_id))
        username = user["username"] if user else ""

    access_token, exp_dt = get_or_create_admin_token(
        _config.auth.sqlite_path,
        int(user_id),
        username,
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
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

    servers = list_mcp_servers(
        _config.auth.sqlite_path, enabled_only=True, user_id=int(user_id) if user_id else None
    )
    public_base = (_config.mcp_public_url or "").rstrip("/")
    server_list = []
    from authmcp_gateway.mcp.proxy import normalize_server_name

    for s in servers:
        server_slug = normalize_server_name(s["name"])
        server_list.append(
            {
                "id": s["id"],
                "name": s["name"],
                "endpoint": (
                    f"{public_base}/mcp/{server_slug}" if public_base else f"/mcp/{server_slug}"
                ),
            }
        )

    response = JSONResponse(
        {
            "username": username,
            "expires_at": expires_at,
            "expires_in_seconds": expires_in_seconds,
            "servers": server_list,
            "gateway_endpoint": f"{public_base}/mcp" if public_base else "/mcp",
        }
    )
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response
