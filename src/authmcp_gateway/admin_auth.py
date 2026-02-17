"""Authentication middleware for admin panel."""

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from authmcp_gateway.auth.jwt_handler import decode_token_unsafe, verify_token
from authmcp_gateway.auth.user_store import (
    get_current_admin_token_jti,
    get_user_by_id,
    is_token_blacklisted,
)
from authmcp_gateway.config import AppConfig
from authmcp_gateway.setup_wizard import is_setup_required

logger = logging.getLogger(__name__)


class AdminAuthMiddleware(BaseHTTPMiddleware):
    """Middleware to protect admin panel routes."""

    def __init__(self, app, config: AppConfig):
        super().__init__(app)
        self.config = config

    async def dispatch(self, request: Request, call_next):
        """Check authentication for admin routes."""
        path = request.url.path

        # Skip auth for setup wizard if setup is required
        if path.startswith("/setup"):
            if is_setup_required(request):
                return await call_next(request)
            # If setup not required, redirect to admin
            if path == "/setup":
                return RedirectResponse(url="/admin", status_code=302)

        # Check if this is an admin route
        if not path.startswith("/admin"):
            return await call_next(request)

        # Skip auth for login page and login API
        if path in ["/admin/login", "/admin/api/login"]:
            return await call_next(request)

        # If setup required, redirect to setup
        if is_setup_required(request):
            if path.startswith("/admin/api/"):
                return JSONResponse(
                    {"detail": "Setup required. Please complete initial setup first."},
                    status_code=403,
                )
            return RedirectResponse(url="/setup", status_code=302)

        # Extract token from Authorization header or cookies
        token = None

        # Try Authorization header
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

        # Try cookie
        if not token:
            token = request.cookies.get("admin_token")

        if not token:
            return self._unauthorized(request, "Authentication required")

        # Verify token
        try:
            payload = verify_token(token, "access", self.config.jwt)

            # Check if token is blacklisted
            jti = decode_token_unsafe(token).get("jti")
            if jti and is_token_blacklisted(self.config.auth.sqlite_path, jti):
                return self._unauthorized(request, "Token has been revoked")

            # Check if user is superuser
            user_id = int(payload.get("sub"))
            is_superuser = payload.get("is_superuser", False)

            # Enforce single active token per user (if enabled)
            if self.config.jwt.enforce_single_session:
                current_jti = get_current_admin_token_jti(self.config.auth.sqlite_path, user_id)
                if current_jti and jti and jti != current_jti:
                    return self._unauthorized(request, "Token has been rotated")

            if not is_superuser:
                # Double-check in database
                user = get_user_by_id(self.config.auth.sqlite_path, user_id)
                if not user or not user.get("is_superuser"):
                    # Redirect non-admin users to account portal instead of 403
                    if not request.url.path.startswith("/admin/api/"):
                        return RedirectResponse(url="/account", status_code=302)
                    return self._forbidden(request)

            # Attach user info to request state
            request.state.user_id = user_id
            request.state.username = payload.get("username")
            request.state.is_superuser = True

            return await call_next(request)

        except Exception as e:
            logger.warning(f"Admin auth failed: {e}")
            return self._unauthorized(request, "Invalid or expired token")

    def _unauthorized(self, request: Request, message: str) -> Response:
        """Return unauthorized response."""
        # For API requests, return JSON
        if request.url.path.startswith("/admin/api/"):
            return JSONResponse({"detail": message}, status_code=401)

        # For HTML requests, redirect to login page
        return RedirectResponse(url="/admin/login", status_code=302)

    def _forbidden(self, request: Request) -> Response:
        """Return forbidden response."""
        if request.url.path.startswith("/admin/api/"):
            return JSONResponse({"detail": "Superuser access required"}, status_code=403)
        return RedirectResponse(url="/account", status_code=302)
