"""AuthMCP Gateway - Main application."""

import logging
import os
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

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
from .mcp.handler import McpHandler
from .mcp.health import initialize_health_checker
from .mcp.proxy import McpProxy
from .mcp.store import init_mcp_database
from .middleware import (
    ContentTypeFixMiddleware,
    McpAuthMiddleware,
    set_middleware_config,
)
from .rate_limiter import get_rate_limiter
from .settings_manager import initialize_settings

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("authmcp-gateway")

# Load configuration
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


# Apply dynamic settings to config (overrides .env with values from admin panel)
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


try:
    _apply_dynamic_settings(config, settings_manager)
    logger.info("✓ Dynamic settings applied from auth_settings.json")
except Exception as e:
    logger.warning(f"Failed to apply dynamic settings: {e}")

# Set global config for auth endpoints
auth_endpoints.set_config(config)
dcr_endpoints.set_config(config)

# Initialize admin routes
admin_routes.initialize(config)
admin_login.set_config(config)

# Initialize setup wizard
setup_wizard.initialize(config)
logger.info("✓ Setup wizard initialized")

# Initialize MCP Gateway components
mcp_proxy = McpProxy(config.auth.sqlite_path, timeout=config.request_timeout_seconds)
mcp_handler = McpHandler(config.auth.sqlite_path)

# Initialize health checker
health_checker = initialize_health_checker(
    db_path=config.auth.sqlite_path,
    interval=60,  # Check every 60 seconds
    timeout=10,  # 10 second timeout per check
)

# Initialize token manager and refresher (NEW)
from .mcp.token_manager import initialize_token_manager
from .mcp.token_refresher import initialize_token_refresher

token_manager = initialize_token_manager(
    db_path=config.auth.sqlite_path, timeout=config.request_timeout_seconds
)

token_refresher = initialize_token_refresher(
    db_path=config.auth.sqlite_path,
    interval=int(os.getenv("MCP_TOKEN_REFRESH_INTERVAL", "300")),  # 5 minutes
    threshold_minutes=int(os.getenv("MCP_TOKEN_REFRESH_THRESHOLD", "5")),  # 5 minutes
)

# Configure middleware globals
set_middleware_config(
    static_bearer_tokens=set(config.static_bearer_tokens),
    trusted_ips=config.trusted_ips,
    allowed_origins=config.allowed_origins,
    auth_required=config.auth_required,
    streamable_path="/mcp-internal",  # Internal path (not used in pure gateway mode)
)

logger.info("✓ AuthMCP Gateway initialized")
logger.info(f"  - Auth required: {config.auth_required}")
logger.info(f"  - JWT algorithm: {config.jwt.algorithm}")

# ============================================================================
# DISCOVERY ENDPOINTS
# ============================================================================


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

    # For RS256, expose public key in JWKS format
    # This would require converting the RSA public key to JWK format
    # For now, return empty (client can use direct JWT verification)
    return JSONResponse({"keys": []})


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
# MCP GATEWAY ENDPOINT
# ============================================================================


def _check_mcp_rate_limit(request: Request):
    """Check per-user rate limit for MCP endpoints.

    Returns JSONResponse with 429 if limit exceeded, None if allowed.
    """
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
    """MCP Gateway endpoint - routes to backend MCP servers.

    Supports both POST (JSON-RPC) and GET (SSE) methods.
    """
    rate_limit_response = _check_mcp_rate_limit(request)
    if rate_limit_response:
        return rate_limit_response

    # GET = SSE transport (Server-Sent Events)
    if request.method == "GET":
        from authmcp_gateway.mcp.sse_handler import mcp_sse_endpoint

        return await mcp_sse_endpoint(request, mcp_handler, server_name=None)

    # POST = JSON-RPC over HTTP
    return await mcp_handler.handle_request(request)


async def mcp_server_endpoint(request: Request):
    """MCP Server-specific endpoint - routes to a single backend MCP server.

    The server_name is extracted from the URL path (/mcp/{server_name}).
    Supports both POST (JSON-RPC) and GET (SSE) methods.
    """
    rate_limit_response = _check_mcp_rate_limit(request)
    if rate_limit_response:
        return rate_limit_response

    server_name = request.path_params.get("server_name")

    # GET = SSE transport (Server-Sent Events)
    if request.method == "GET":
        from authmcp_gateway.mcp.sse_handler import mcp_sse_endpoint

        return await mcp_sse_endpoint(request, mcp_handler, server_name)

    # POST = JSON-RPC over HTTP
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


# ============================================================================
# APPLICATION SETUP
# ============================================================================

# Create Starlette app
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.staticfiles import StaticFiles


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
            """Background task to clean up expired rate limit entries."""
            while True:
                try:
                    await asyncio.sleep(config.rate_limit.cleanup_interval)
                    limiter = get_rate_limiter()
                    removed = limiter.cleanup_expired(
                        max_age_seconds=config.rate_limit.cleanup_interval
                    )
                    if removed > 0:
                        logger.debug(f"Rate limiter: cleaned up {removed} expired entries")
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


app = Starlette(
    debug=False,
    lifespan=lifespan,
    routes=[
        # MCP Gateway
        Route("/mcp/messages", mcp_messages_endpoint, methods=["POST"]),  # SSE message endpoint
        Route(
            "/mcp/{server_name}/messages", mcp_server_messages_endpoint, methods=["POST"]
        ),  # SSE message endpoint
        Route(
            "/mcp/{server_name}", mcp_server_endpoint, methods=["GET", "POST"]
        ),  # Server-specific endpoint (GET for HTTP transport, POST for JSON-RPC)
        Route("/mcp", mcp_gateway_endpoint, methods=["GET", "POST"]),  # Aggregated endpoint
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
        Route("/admin/api/users/{user_id:int}", admin_routes.api_delete_user, methods=["DELETE"]),
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
        Route("/admin/api/logs/cleanup", admin_routes.api_cleanup_auth_logs_file, methods=["POST"]),
        Route("/admin/api/mcp-auth-events", admin_routes.api_mcp_auth_events, methods=["GET"]),
        Route("/admin/api/settings", admin_routes.api_get_settings, methods=["GET"]),
        Route("/admin/api/settings", admin_routes.api_save_settings, methods=["PUT"]),
        Route("/admin/api/access-token", admin_routes.api_admin_access_token, methods=["GET"]),
        Route(
            "/admin/api/access-token/rotate", admin_routes.api_admin_rotate_token, methods=["POST"]
        ),
        # MCP Security Audit
        Route("/admin/mcp-audit", admin_routes.admin_mcp_audit, methods=["GET"]),
        Route("/admin/api/run-mcp-audit", admin_routes.api_run_mcp_audit, methods=["POST"]),
        Route("/admin/api/export-mcp-audit", admin_routes.api_export_mcp_audit, methods=["POST"]),
        # Discovery endpoints
        # Well-known endpoints (global and per-server aliases for client compatibility)
        Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
        Route(
            "/.well-known/oauth-protected-resource/mcp", oauth_protected_resource, methods=["GET"]
        ),
        Route(
            "/mcp/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]
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
            "/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]
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

# Store database path in app state for authorize endpoint
app.state.auth_db_path = config.auth.sqlite_path

# Mount static files for favicon and other assets
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    logger.info(f"✓ Static files mounted from {static_dir}")

# Add middleware (order matters: last added = first executed)
app.add_middleware(ContentTypeFixMiddleware)
app.add_middleware(
    McpAuthMiddleware,
    jwt_config=config.jwt,
    auth_db_path=config.auth.sqlite_path,
    mcp_public_url=config.mcp_public_url,
    oauth_scopes="openid profile email",
)
app.add_middleware(AdminAuthMiddleware, config=config)

logger.info("✓ Application configured")
logger.info(
    "  - Auth endpoints: /auth/register, /auth/login, /auth/refresh, /auth/logout, /auth/me"
)
logger.info("  - MCP Gateway: /mcp (aggregates all backend servers)")
logger.info("  - Admin Panel: /admin")

# Export app for uvicorn
__all__ = ["app"]
