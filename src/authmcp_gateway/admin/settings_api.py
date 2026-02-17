"""Admin API: Settings and OAuth clients management."""

import logging
from datetime import datetime, timedelta, timezone

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config, render_template

logger = logging.getLogger(__name__)

__all__ = [
    "admin_settings",
    "api_admin_access_token",
    "api_admin_rotate_token",
    "api_get_settings",
    "api_save_settings",
    "api_list_oauth_clients",
    "api_rotate_oauth_client_token",
    "api_delete_oauth_client",
]


async def admin_settings(request: Request) -> HTMLResponse:
    """Admin settings page with current user's access token."""
    _config = get_config(request)
    # Get current user from request state (set by AdminAuthMiddleware)
    user_id = request.state.user_id
    username = request.state.username
    is_superuser = request.state.is_superuser

    # Reuse stored token or rotate if needed
    from authmcp_gateway.auth.token_service import format_expires_in, get_or_create_admin_token

    access_token, exp_dt = get_or_create_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        is_superuser,
        _config.jwt,
        _config.jwt.admin_token_expire_minutes,
        current_token=request.cookies.get("admin_token"),
    )
    token_expires_in = format_expires_in(exp_dt)
    if not token_expires_in:
        token_expires_in = format_expires_in(
            datetime.now(timezone.utc) + timedelta(minutes=_config.jwt.admin_token_expire_minutes)
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
    _config = get_config(request)
    user_id = request.state.user_id
    username = request.state.username
    is_superuser = request.state.is_superuser
    from authmcp_gateway.auth.token_service import format_expires_in, get_or_create_admin_token

    access_token, exp_dt = get_or_create_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        is_superuser,
        _config.jwt,
        _config.jwt.admin_token_expire_minutes,
        current_token=request.cookies.get("admin_token"),
    )
    token_expires_in = format_expires_in(exp_dt)

    return JSONResponse({"access_token": access_token, "token_expires_in": token_expires_in})


@api_error_handler
async def api_admin_rotate_token(request: Request) -> JSONResponse:
    """API: Rotate admin access token."""
    _config = get_config(request)
    user_id = request.state.user_id
    username = request.state.username
    is_superuser = request.state.is_superuser
    from authmcp_gateway.auth.token_service import format_expires_in, rotate_admin_token

    current_token = request.cookies.get("admin_token")
    new_token, exp_dt = rotate_admin_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        is_superuser,
        _config.jwt,
        _config.jwt.admin_token_expire_minutes,
        current_token=current_token,
    )
    token_expires_in = format_expires_in(exp_dt)

    response = JSONResponse({"access_token": new_token, "token_expires_in": token_expires_in})
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        key="admin_token",
        value=new_token,
        path="/",
        httponly=True,
        secure=is_https,
        samesite="lax",
        max_age=_config.jwt.admin_token_expire_minutes * 60,
    )
    return response


async def api_get_settings(request: Request) -> JSONResponse:
    """Get current settings."""
    from authmcp_gateway.settings_manager import get_settings_manager

    settings_manager = get_settings_manager()
    return JSONResponse(settings_manager.get_all())


@api_error_handler
async def api_save_settings(request: Request) -> JSONResponse:
    """Save settings."""
    from authmcp_gateway.settings_manager import get_settings_manager

    _config = get_config(request)
    settings_manager = get_settings_manager()

    body = await request.json()

    # Validate settings values before applying
    errors = []
    jwt_s = body.get("jwt") or {}
    if "access_token_expire_minutes" in jwt_s:
        try:
            val = int(jwt_s["access_token_expire_minutes"])
            if val < 1 or val > 525600:  # 1 min to 1 year
                errors.append("access_token_expire_minutes must be between 1 and 525600")
        except (ValueError, TypeError):
            errors.append("access_token_expire_minutes must be an integer")
    if "refresh_token_expire_days" in jwt_s:
        try:
            val = int(jwt_s["refresh_token_expire_days"])
            if val < 1 or val > 365:
                errors.append("refresh_token_expire_days must be between 1 and 365")
        except (ValueError, TypeError):
            errors.append("refresh_token_expire_days must be an integer")

    pw = body.get("password_policy") or {}
    if "min_length" in pw:
        try:
            val = int(pw["min_length"])
            if val < 4 or val > 128:
                errors.append("min_length must be between 4 and 128")
        except (ValueError, TypeError):
            errors.append("min_length must be an integer")

    rl = body.get("rate_limit") or {}
    for key in ("mcp_limit", "login_limit", "register_limit"):
        if key in rl:
            try:
                val = int(rl[key])
                if val < 1 or val > 10000:
                    errors.append(f"{key} must be between 1 and 10000")
            except (ValueError, TypeError):
                errors.append(f"{key} must be an integer")
    for key in ("mcp_window", "login_window", "register_window"):
        if key in rl:
            try:
                val = int(rl[key])
                if val < 1 or val > 86400:  # 1 sec to 1 day
                    errors.append(f"{key} must be between 1 and 86400")
            except (ValueError, TypeError):
                errors.append(f"{key} must be an integer")

    if errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": errors},
        )

    settings_manager.update(body)
    settings_manager.save()

    # Apply all settings to live config immediately
    try:
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
            # Propagate to middleware global so the change takes effect immediately
            try:
                import authmcp_gateway.middleware as _mw

                _mw._auth_required = _config.auth_required
                logger.info(f"Propagated auth_required={_config.auth_required} to middleware")
            except Exception as e:
                logger.warning(f"Failed to propagate auth_required to middleware: {e}")

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
async def api_list_oauth_clients(request: Request) -> JSONResponse:
    """List OAuth clients."""
    from authmcp_gateway.auth.client_store import list_oauth_clients

    clients = list_oauth_clients(get_config(request).auth.sqlite_path)
    return JSONResponse(clients)


@api_error_handler
async def api_rotate_oauth_client_token(request: Request) -> JSONResponse:
    """Rotate registration token for OAuth client."""
    client_id = request.path_params["client_id"]
    from authmcp_gateway.auth.client_store import rotate_registration_token

    new_token = rotate_registration_token(get_config(request).auth.sqlite_path, client_id)
    if not new_token:
        return JSONResponse({"error": "Client not found"}, status_code=404)
    return JSONResponse({"registration_access_token": new_token})


@api_error_handler
async def api_delete_oauth_client(request: Request) -> JSONResponse:
    """Delete OAuth client."""
    client_id = request.path_params["client_id"]
    from authmcp_gateway.auth.client_store import delete_oauth_client

    deleted = delete_oauth_client(get_config(request).auth.sqlite_path, client_id)
    if not deleted:
        return JSONResponse({"error": "Client not found"}, status_code=404)
    return JSONResponse({"success": True})
