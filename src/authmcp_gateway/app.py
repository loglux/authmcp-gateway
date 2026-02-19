"""AuthMCP Gateway - Main application."""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.staticfiles import StaticFiles

from . import setup_wizard
from .admin import login as admin_login
from .admin import routes as admin_routes
from .admin_auth import AdminAuthMiddleware
from .auth import dcr_endpoints
from .auth import endpoints as auth_endpoints
from .auth.authorize_endpoint import authorize_page
from .auth.oauth_code_flow import create_authorization_code_table
from .auth.user_store import init_database
from .config import load_config
from .csrf import CSRFMiddleware
from .mcp.crypto import initialize_crypto
from .mcp.handler import McpHandler
from .mcp.health import initialize_health_checker
from .mcp.proxy import McpProxy
from .mcp.store import init_mcp_database
from .mcp.token_manager import initialize_token_manager
from .mcp.token_refresher import initialize_token_refresher
from .middleware import (
    ContentTypeFixMiddleware,
    McpAuthMiddleware,
    set_middleware_config,
)
from .rate_limiter import get_rate_limiter
from .settings_manager import initialize_settings

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("authmcp-gateway")


# ============================================================================
# MODULE-LEVEL HELPERS (pure functions, no side effects)
# ============================================================================


def _apply_dynamic_settings(cfg, sm):
    """Apply saved settings from auth_settings.json to live AppConfig."""
    # JWT
    cfg.jwt.access_token_expire_minutes = sm.get(
        "jwt", "access_token_expire_minutes", default=cfg.jwt.access_token_expire_minutes
    )
    cfg.jwt.refresh_token_expire_days = sm.get(
        "jwt", "refresh_token_expire_days", default=cfg.jwt.refresh_token_expire_days
    )
    cfg.jwt.enforce_single_session = sm.get(
        "jwt", "enforce_single_session", default=cfg.jwt.enforce_single_session
    )

    # Password policy
    cfg.auth.password_min_length = sm.get(
        "password_policy", "min_length", default=cfg.auth.password_min_length
    )
    cfg.auth.password_require_uppercase = sm.get(
        "password_policy", "require_uppercase", default=cfg.auth.password_require_uppercase
    )
    cfg.auth.password_require_lowercase = sm.get(
        "password_policy", "require_lowercase", default=cfg.auth.password_require_lowercase
    )
    cfg.auth.password_require_digit = sm.get(
        "password_policy", "require_digit", default=cfg.auth.password_require_digit
    )
    cfg.auth.password_require_special = sm.get(
        "password_policy", "require_special", default=cfg.auth.password_require_special
    )

    # System
    cfg.auth.allow_registration = sm.get(
        "system", "allow_registration", default=cfg.auth.allow_registration
    )
    cfg.auth.allow_dcr = sm.get("system", "allow_dcr", default=cfg.auth.allow_dcr)
    cfg.auth_required = sm.get("system", "auth_required", default=cfg.auth_required)

    # Rate limits
    cfg.rate_limit.mcp_limit = sm.get("rate_limit", "mcp_limit", default=cfg.rate_limit.mcp_limit)
    cfg.rate_limit.mcp_window = sm.get(
        "rate_limit", "mcp_window", default=cfg.rate_limit.mcp_window
    )
    cfg.rate_limit.login_limit = sm.get(
        "rate_limit", "login_limit", default=cfg.rate_limit.login_limit
    )
    cfg.rate_limit.login_window = sm.get(
        "rate_limit", "login_window", default=cfg.rate_limit.login_window
    )
    cfg.rate_limit.register_limit = sm.get(
        "rate_limit", "register_limit", default=cfg.rate_limit.register_limit
    )
    cfg.rate_limit.register_window = sm.get(
        "rate_limit", "register_window", default=cfg.rate_limit.register_window
    )


# ============================================================================
# STATELESS ENDPOINTS (no dependencies on config or MCP components)
# ============================================================================


async def health(_: Request) -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse({"status": "ok"})


async def root_endpoint(_: Request) -> RedirectResponse:
    """Root endpoint - redirect to admin panel."""
    return RedirectResponse(url="/admin", status_code=302)


async def favicon(_: Request) -> Response:
    """Favicon endpoint - return empty 204."""
    return Response(status_code=204)


# ============================================================================
# APPLICATION FACTORY
# ============================================================================


def create_app(config=None):
    """Create and configure the AuthMCP Gateway application.

    Args:
        config: Optional AppConfig instance. If None, loads from environment.

    Returns:
        Configured Starlette application.
    """
    if config is None:
        config = load_config()

    # Initialize database
    init_database(config.auth.sqlite_path)
    create_authorization_code_table(config.auth.sqlite_path)
    init_mcp_database(config.auth.sqlite_path)
    logger.info(f"✓ Database initialized: {config.auth.sqlite_path}")

    # Initialize settings manager
    _settings_path = str(Path(config.auth.sqlite_path).parent / "auth_settings.json")
    settings_manager = initialize_settings(_settings_path)
    logger.info("✓ Settings manager initialized")

    # Apply dynamic settings to config
    try:
        _apply_dynamic_settings(config, settings_manager)
        logger.info("✓ Dynamic settings applied from auth_settings.json")
    except Exception as e:
        logger.warning(f"Failed to apply dynamic settings: {e}")

    # Initialize token encryption
    initialize_crypto(config.jwt.secret_key)
    logger.info("✓ Token encryption initialized")

    # Read timeout settings (per-server overrides are in DB, global defaults here)
    proxy_timeout = settings_manager.get("timeouts", "proxy_timeout", default=30)
    health_check_timeout = settings_manager.get("timeouts", "health_check_timeout", default=10)
    health_check_interval = settings_manager.get("timeouts", "health_check_interval", default=60)

    # Initialize MCP Gateway components
    mcp_proxy = McpProxy(config.auth.sqlite_path, timeout=proxy_timeout)
    mcp_handler = McpHandler(config.auth.sqlite_path)

    # Initialize health checker
    health_checker = initialize_health_checker(
        db_path=config.auth.sqlite_path,
        interval=health_check_interval,
        timeout=health_check_timeout,
        shared_session_ids=mcp_proxy._session_ids,
    )

    # Initialize token manager and refresher
    initialize_token_manager(
        db_path=config.auth.sqlite_path, timeout=config.request_timeout_seconds
    )

    token_refresher = initialize_token_refresher(
        db_path=config.auth.sqlite_path,
        interval=int(os.getenv("MCP_TOKEN_REFRESH_INTERVAL", "300")),
        threshold_minutes=int(os.getenv("MCP_TOKEN_REFRESH_THRESHOLD", "5")),
    )

    # Configure middleware globals
    set_middleware_config(
        static_bearer_tokens=set(config.static_bearer_tokens),
        trusted_ips=config.trusted_ips,
        allowed_origins=config.allowed_origins,
        auth_required=config.auth_required,
        streamable_path="/mcp-internal",
    )

    logger.info("✓ AuthMCP Gateway initialized")
    logger.info(f"  - Auth required: {config.auth_required}")
    logger.info(f"  - JWT algorithm: {config.jwt.algorithm}")

    # ========================================================================
    # ENDPOINT CLOSURES (capture config, mcp_handler, mcp_proxy from scope)
    # ========================================================================

    async def oauth_protected_resource(_: Request) -> JSONResponse:
        """OAuth protected resource metadata."""
        body = {
            "resource": config.mcp_public_url,
            "authorization_servers": [f"{config.mcp_public_url}/"],
            "scopes_supported": ["openid", "profile", "email"],
        }
        return JSONResponse(body)

    async def oauth_authorization_server(_: Request) -> JSONResponse:
        """OAuth authorization server metadata."""
        response = {
            "issuer": config.mcp_public_url,
            "authorization_endpoint": f"{config.mcp_public_url}/authorize",
            "token_endpoint": f"{config.mcp_public_url}/oauth/token",
            "jwks_uri": f"{config.mcp_public_url}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "password", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256", "plain"],
        }
        if config.auth.allow_dcr:
            response["token_endpoint_auth_methods_supported"] = [
                "none",
                "client_secret_basic",
                "client_secret_post",
            ]
            response["registration_endpoint"] = f"{config.mcp_public_url}/oauth/register"
            response["registration_endpoint_auth_methods_supported"] = [
                "bearer" if config.auth.dcr_require_initial_token else "none"
            ]
        return JSONResponse(response)

    async def openid_configuration(_: Request) -> JSONResponse:
        """OpenID Connect configuration."""
        response = {
            "issuer": config.mcp_public_url,
            "token_endpoint": f"{config.mcp_public_url}/oauth/token",
            "userinfo_endpoint": f"{config.mcp_public_url}/auth/me",
            "jwks_uri": f"{config.mcp_public_url}/.well-known/jwks.json",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [config.jwt.algorithm],
        }
        if config.auth.allow_dcr:
            response["registration_endpoint"] = f"{config.mcp_public_url}/oauth/register"
        return JSONResponse(response)

    async def jwks_json(_: Request) -> JSONResponse:
        """JWKS endpoint (for RS256 public key)."""
        if config.jwt.algorithm != "RS256":
            return JSONResponse({"keys": []})
        return JSONResponse({"keys": []})

    def _check_mcp_rate_limit(request: Request):
        """Check per-user rate limit for MCP endpoints."""
        if not config.rate_limit.enabled:
            return None

        limiter = get_rate_limiter()
        user_id = getattr(request.state, "user_id", None)
        client_ip = request.client.host if request.client else "unknown"
        identifier = f"mcp:{user_id or client_ip}"

        allowed, retry_after = limiter.check_limit(
            identifier=identifier,
            limit=config.rate_limit.mcp_limit,
            window=config.rate_limit.mcp_window,
        )
        if not allowed:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Rate limit exceeded",
                        "data": {"retry_after": retry_after},
                    },
                    "id": None,
                },
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return None

    async def mcp_gateway_endpoint(request: Request):
        """MCP Gateway endpoint - routes to backend MCP servers."""
        rate_limit_response = _check_mcp_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response

        if request.method == "GET":
            from authmcp_gateway.mcp.sse_handler import mcp_sse_endpoint

            return await mcp_sse_endpoint(request, mcp_handler, server_name=None)

        return await mcp_handler.handle_request(request)

    async def mcp_server_endpoint(request: Request):
        """MCP Server-specific endpoint."""
        rate_limit_response = _check_mcp_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response

        server_name = request.path_params.get("server_name")

        if request.method == "GET":
            from authmcp_gateway.mcp.sse_handler import mcp_sse_endpoint

            return await mcp_sse_endpoint(request, mcp_handler, server_name)

        return await mcp_handler.handle_request(request, server_name=server_name)

    async def mcp_messages_endpoint(request: Request):
        """MCP SSE message endpoint (POST only)."""
        rate_limit_response = _check_mcp_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response

        from authmcp_gateway.mcp.sse_handler import handle_sse_message

        return await handle_sse_message(request, mcp_handler, server_name=None)

    async def mcp_server_messages_endpoint(request: Request):
        """MCP SSE message endpoint for a specific server (POST only)."""
        rate_limit_response = _check_mcp_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response

        server_name = request.path_params.get("server_name")
        from authmcp_gateway.mcp.sse_handler import handle_sse_message

        return await handle_sse_message(request, mcp_handler, server_name=server_name)

    # ========================================================================
    # LIFESPAN
    # ========================================================================

    @asynccontextmanager
    async def lifespan(app):
        """Application lifespan manager."""
        import asyncio

        # Startup
        health_checker.start()
        logger.info("✓ Health checker started (interval=60s)")

        token_refresher.start()
        logger.info("✓ Token refresher started")

        # Start rate limiter cleanup task
        cleanup_task = None
        if config.rate_limit.enabled:

            async def rate_limit_cleanup():
                """Background task to clean up expired rate limit entries and auth codes."""
                from .auth.oauth_code_flow import cleanup_expired_codes

                while True:
                    try:
                        await asyncio.sleep(config.rate_limit.cleanup_interval)
                        limiter = get_rate_limiter()
                        removed = limiter.cleanup_expired(
                            max_age_seconds=config.rate_limit.cleanup_interval
                        )
                        if removed > 0:
                            logger.debug(f"Rate limiter: cleaned up {removed} expired entries")
                        cleanup_expired_codes(config.auth.sqlite_path)
                    except asyncio.CancelledError:
                        break
                    except Exception as e:
                        logger.error(f"Rate limiter cleanup error: {e}")

            cleanup_task = asyncio.create_task(rate_limit_cleanup())
            logger.info(
                f"✓ Rate limiter cleanup started (interval={config.rate_limit.cleanup_interval}s)"
            )

        yield

        # Shutdown
        if cleanup_task:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("✓ Rate limiter cleanup stopped")

        await token_refresher.stop()
        logger.info("✓ Token refresher stopped")

        await health_checker.stop()
        logger.info("✓ Health checker stopped")

        await mcp_proxy.close()
        logger.info("✓ MCP proxy HTTP client closed")

    # ========================================================================
    # CREATE STARLETTE APP
    # ========================================================================

    app = Starlette(
        debug=False,
        lifespan=lifespan,
        routes=[
            # MCP Gateway
            Route("/mcp/messages", mcp_messages_endpoint, methods=["POST"]),
            Route("/mcp/{server_name}/messages", mcp_server_messages_endpoint, methods=["POST"]),
            Route("/mcp/{server_name}", mcp_server_endpoint, methods=["GET", "POST"]),
            Route("/mcp", mcp_gateway_endpoint, methods=["GET", "POST"]),
            # Auth endpoints
            Route("/auth/register", auth_endpoints.register, methods=["POST"]),
            Route("/auth/login", auth_endpoints.login, methods=["POST"]),
            Route("/auth/refresh", auth_endpoints.refresh, methods=["POST"]),
            Route("/auth/logout", auth_endpoints.logout, methods=["POST"]),
            Route("/auth/me", auth_endpoints.me, methods=["GET"]),
            # OAuth endpoints
            Route("/oauth/token", auth_endpoints.oauth_token, methods=["POST"]),
            Route("/oauth/register", dcr_endpoints.register_client, methods=["POST"]),
            Route("/oauth/register/{client_id}", dcr_endpoints.get_client, methods=["GET"]),
            Route("/oauth/register/{client_id}", dcr_endpoints.update_client, methods=["PUT"]),
            Route("/oauth/register/{client_id}", dcr_endpoints.delete_client, methods=["DELETE"]),
            Route("/authorize", authorize_page, methods=["GET", "POST"]),
            # User portal (non-admin)
            Route("/account", admin_routes.user_portal, methods=["GET"]),
            Route("/account/token", admin_routes.user_account_token, methods=["GET"]),
            Route("/account/rotate", admin_routes.user_account_rotate_token, methods=["POST"]),
            Route("/account/info", admin_routes.user_account_info, methods=["GET"]),
            Route("/account/logout", admin_routes.user_logout, methods=["GET"]),
            Route("/login", admin_routes.user_login_page, methods=["GET"]),
            Route("/api/login", admin_routes.user_login_api, methods=["POST"]),
            # Setup wizard
            Route("/setup", setup_wizard.setup_page, methods=["GET"]),
            Route("/setup/create-admin", setup_wizard.create_admin_user, methods=["POST"]),
            # Admin login
            Route("/admin/login", admin_login.admin_login_page, methods=["GET"]),
            Route("/admin/api/login", admin_login.admin_login_api, methods=["POST"]),
            Route("/admin/logout", admin_login.admin_logout, methods=["GET", "POST"]),
            # Admin panel
            Route("/admin", admin_routes.admin_dashboard, methods=["GET"]),
            Route("/admin/users", admin_routes.admin_users, methods=["GET"]),
            Route("/admin/mcp-servers", admin_routes.admin_mcp_servers, methods=["GET"]),
            Route("/admin/mcp-tokens", admin_routes.admin_mcp_tokens, methods=["GET"]),
            Route("/admin/settings", admin_routes.admin_settings, methods=["GET"]),
            Route("/admin/logs", admin_routes.admin_logs, methods=["GET"]),
            Route("/admin/security-logs", admin_routes.admin_security_logs, methods=["GET"]),
            Route("/admin/mcp-activity", admin_routes.admin_mcp_activity, methods=["GET"]),
            Route("/admin/oauth-clients", admin_routes.admin_oauth_clients, methods=["GET"]),
            # Admin API
            Route("/admin/api/stats", admin_routes.api_stats, methods=["GET"]),
            Route("/admin/api/users", admin_routes.api_users, methods=["GET"]),
            Route("/admin/api/users", admin_routes.api_create_user, methods=["POST"]),
            Route(
                "/admin/api/users/{user_id:int}/status",
                admin_routes.api_update_user_status,
                methods=["PATCH"],
            ),
            Route(
                "/admin/api/users/{user_id:int}/superuser",
                admin_routes.api_make_superuser,
                methods=["PATCH"],
            ),
            Route(
                "/admin/api/users/{user_id:int}",
                admin_routes.api_delete_user,
                methods=["DELETE"],
            ),
            Route(
                "/admin/api/users/{user_id:int}/mcp-permissions",
                admin_routes.api_get_user_mcp_permissions,
                methods=["GET"],
            ),
            Route(
                "/admin/api/users/{user_id:int}/mcp-permissions",
                admin_routes.api_set_user_mcp_permission,
                methods=["PATCH"],
            ),
            Route("/admin/api/mcp-servers", admin_routes.api_list_mcp_servers, methods=["GET"]),
            Route(
                "/admin/api/mcp-servers/token-status",
                admin_routes.api_mcp_servers_token_status,
                methods=["GET"],
            ),
            Route("/admin/api/security-events", admin_routes.api_security_events, methods=["GET"]),
            Route("/admin/api/mcp-stats", admin_routes.api_mcp_stats, methods=["GET"]),
            Route("/admin/api/mcp-requests", admin_routes.admin_mcp_requests_api, methods=["GET"]),
            Route("/admin/api/cleanup-logs", admin_routes.api_cleanup_db_logs, methods=["POST"]),
            Route("/admin/api/oauth-clients", admin_routes.api_list_oauth_clients, methods=["GET"]),
            Route(
                "/admin/api/oauth-clients/{client_id}",
                admin_routes.api_delete_oauth_client,
                methods=["DELETE"],
            ),
            Route(
                "/admin/api/oauth-clients/{client_id}/rotate",
                admin_routes.api_rotate_oauth_client_token,
                methods=["POST"],
            ),
            Route("/admin/api/mcp-servers", admin_routes.api_create_mcp_server, methods=["POST"]),
            Route(
                "/admin/api/mcp-servers/{server_id:int}",
                admin_routes.api_delete_mcp_server,
                methods=["DELETE"],
            ),
            Route(
                "/admin/api/mcp-servers/{server_id:int}",
                admin_routes.api_update_mcp_server,
                methods=["PATCH"],
            ),
            Route(
                "/admin/api/mcp-servers/{server_id:int}/test",
                admin_routes.api_test_mcp_server,
                methods=["POST"],
            ),
            Route(
                "/admin/api/mcp-servers/{server_id:int}/tools",
                admin_routes.api_get_mcp_server_tools,
                methods=["GET"],
            ),
            Route(
                "/admin/api/mcp-servers/token-statuses",
                admin_routes.api_get_token_statuses,
                methods=["GET"],
            ),
            Route(
                "/admin/api/mcp-servers/token-audit-logs",
                admin_routes.api_get_token_audit_logs,
                methods=["GET"],
            ),
            Route(
                "/admin/api/mcp-servers/{server_id:int}/refresh-token",
                admin_routes.api_refresh_server_token,
                methods=["POST"],
            ),
            Route("/admin/api/logs", admin_routes.api_logs, methods=["GET"]),
            Route(
                "/admin/api/logs/cleanup",
                admin_routes.api_cleanup_auth_logs_file,
                methods=["POST"],
            ),
            Route(
                "/admin/api/mcp-auth-events",
                admin_routes.api_mcp_auth_events,
                methods=["GET"],
            ),
            Route("/admin/api/settings", admin_routes.api_get_settings, methods=["GET"]),
            Route("/admin/api/settings", admin_routes.api_save_settings, methods=["PUT"]),
            Route(
                "/admin/api/access-token",
                admin_routes.api_admin_access_token,
                methods=["GET"],
            ),
            Route(
                "/admin/api/access-token/rotate",
                admin_routes.api_admin_rotate_token,
                methods=["POST"],
            ),
            # MCP Security Audit
            Route("/admin/mcp-audit", admin_routes.admin_mcp_audit, methods=["GET"]),
            Route("/admin/api/run-mcp-audit", admin_routes.api_run_mcp_audit, methods=["POST"]),
            Route(
                "/admin/api/export-mcp-audit",
                admin_routes.api_export_mcp_audit,
                methods=["POST"],
            ),
            # Discovery endpoints
            Route(
                "/.well-known/oauth-protected-resource",
                oauth_protected_resource,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                oauth_protected_resource,
                methods=["GET"],
            ),
            Route(
                "/mcp/.well-known/oauth-protected-resource",
                oauth_protected_resource,
                methods=["GET"],
            ),
            Route(
                "/mcp/{server_name}/.well-known/oauth-protected-resource",
                oauth_protected_resource,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp/{server_name}",
                oauth_protected_resource,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-authorization-server",
                oauth_authorization_server,
                methods=["GET"],
            ),
            Route(
                "/mcp/{server_name}/.well-known/oauth-authorization-server",
                oauth_authorization_server,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-authorization-server/mcp/{server_name}",
                oauth_authorization_server,
                methods=["GET"],
            ),
            Route("/.well-known/openid-configuration", openid_configuration, methods=["GET"]),
            Route(
                "/mcp/{server_name}/.well-known/openid-configuration",
                openid_configuration,
                methods=["GET"],
            ),
            Route(
                "/.well-known/openid-configuration/mcp/{server_name}",
                openid_configuration,
                methods=["GET"],
            ),
            Route("/.well-known/jwks.json", jwks_json, methods=["GET"]),
            Route("/mcp/{server_name}/.well-known/jwks.json", jwks_json, methods=["GET"]),
            # Utility endpoints
            Route("/health", health, methods=["GET"]),
            Route("/", root_endpoint, methods=["GET"]),
            Route("/favicon.ico", favicon, methods=["GET"]),
        ],
    )

    # Store config on app.state for dependency injection
    app.state.config = config
    app.state.auth_db_path = config.auth.sqlite_path

    # Mount static files with cache headers
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_dir):

        class CachedStaticFiles(StaticFiles):
            """StaticFiles with Cache-Control headers for browser caching."""

            async def __call__(self, scope, receive, send):
                async def send_with_cache(message):
                    if message.get("type") == "http.response.start":
                        headers = list(message.get("headers", []))
                        headers.append((b"cache-control", b"public, max-age=86400, immutable"))
                        message = {**message, "headers": headers}
                    await send(message)

                await super().__call__(scope, receive, send_with_cache)

        app.mount("/static", CachedStaticFiles(directory=static_dir), name="static")
        logger.info(f"✓ Static files mounted from {static_dir}")

    # Add middleware (order matters: last added = first executed)
    # GZip must be OUTSIDE McpAuth so it compresses the final (modified) body
    class McpAwareGZipMiddleware(GZipMiddleware):
        """Skip gzip for MCP endpoints to avoid Content-Length mismatches."""

        async def __call__(self, scope, receive, send):
            if scope.get("type") == "http":
                path = scope.get("path", "")
                if path == "/mcp" or path.startswith("/mcp/"):
                    await self.app(scope, receive, send)
                    return
            await super().__call__(scope, receive, send)

    app.add_middleware(ContentTypeFixMiddleware)
    app.add_middleware(
        McpAuthMiddleware,
        jwt_config=config.jwt,
        auth_db_path=config.auth.sqlite_path,
        mcp_public_url=config.mcp_public_url,
        oauth_scopes="openid profile email",
    )
    app.add_middleware(AdminAuthMiddleware, config=config)
    app.add_middleware(McpAwareGZipMiddleware, minimum_size=1000)

    # CSRF protection — last added = first executed
    app.add_middleware(CSRFMiddleware, secret_key=config.jwt.secret_key)

    logger.info("✓ Application configured")
    logger.info(
        "  - Auth endpoints: /auth/register, /auth/login, /auth/refresh, /auth/logout, /auth/me"
    )
    logger.info("  - MCP Gateway: /mcp (aggregates all backend servers)")
    logger.info("  - Admin Panel: /admin")

    return app


# Create application instance (backward-compatible with cli.py import)
app = create_app()

# Export app for uvicorn
__all__ = ["app", "create_app"]
