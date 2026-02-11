"""AuthMCP Gateway - Main application."""

import os
import logging
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from .config import load_config
from .middleware import (
    McpAuthMiddleware,
    ContentTypeFixMiddleware,
    set_middleware_config,
)
from .auth.user_store import init_database
from .auth import endpoints as auth_endpoints
from .auth.authorize_endpoint import authorize_page
from .auth.oauth_code_flow import create_authorization_code_table
from .admin import routes as admin_routes
from .admin import login as admin_login
from .admin_auth import AdminAuthMiddleware
from . import setup_wizard
from .mcp.proxy import McpProxy
from .mcp.handler import McpHandler
from .mcp.health import initialize_health_checker
from .mcp.store import init_mcp_database
from .settings_manager import initialize_settings
from .rate_limiter import get_rate_limiter

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
settings_manager = initialize_settings("/app/data/auth_settings.json")
logger.info("✓ Settings manager initialized")

# Set global config for auth endpoints
auth_endpoints.set_config(config)

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
    timeout=10    # 10 second timeout per check
)

# Configure middleware globals
set_middleware_config(
    static_bearer_tokens=set(config.static_bearer_tokens),
    trusted_ips=config.trusted_ips,
    allowed_origins=config.allowed_origins,
    auth_required=config.auth_required,
    streamable_path="/mcp-internal"  # Internal path (not used in pure gateway mode)
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


async def root_endpoint(_: Request) -> JSONResponse:
    """Root endpoint - service info."""
    return JSONResponse({
        "service": "AuthMCP Gateway",
        "version": "1.0.0",
        "endpoints": {
            "mcp": "/mcp",
            "auth": "/auth/*",
            "admin": "/admin",
            "discovery": "/.well-known/*"
        }
    })


async def favicon(_: Request) -> Response:
    """Favicon endpoint - return empty 204."""
    return Response(status_code=204)


# ============================================================================
# MCP GATEWAY ENDPOINT
# ============================================================================


async def mcp_gateway_endpoint(request: Request) -> JSONResponse:
    """MCP Gateway endpoint - routes to backend MCP servers."""
    return await mcp_handler.handle_request(request)


# ============================================================================
# APPLICATION SETUP
# ============================================================================

# Create Starlette app
from contextlib import asynccontextmanager
from starlette.applications import Starlette
from starlette.routing import Route


@asynccontextmanager
async def lifespan(app):
    """Application lifespan manager."""
    import asyncio

    # Startup
    health_checker.start()
    logger.info("✓ Health checker started (interval=60s)")

    # Start rate limiter cleanup task
    cleanup_task = None
    if config.rate_limit.enabled:
        async def rate_limit_cleanup():
            """Background task to clean up expired rate limit entries."""
            while True:
                try:
                    await asyncio.sleep(config.rate_limit.cleanup_interval)
                    limiter = get_rate_limiter()
                    removed = limiter.cleanup_expired(max_age_seconds=config.rate_limit.cleanup_interval)
                    if removed > 0:
                        logger.debug(f"Rate limiter: cleaned up {removed} expired entries")
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Rate limiter cleanup error: {e}")

        cleanup_task = asyncio.create_task(rate_limit_cleanup())
        logger.info(f"✓ Rate limiter cleanup started (interval={config.rate_limit.cleanup_interval}s)")

    yield

    # Shutdown
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        logger.info("✓ Rate limiter cleanup stopped")

    await health_checker.stop()
    logger.info("✓ Health checker stopped")


app = Starlette(
    debug=False,
    lifespan=lifespan,
    routes=[
        # MCP Gateway
        Route("/mcp", mcp_gateway_endpoint, methods=["POST"]),

        # Auth endpoints
        Route("/auth/register", auth_endpoints.register, methods=["POST"]),
        Route("/auth/login", auth_endpoints.login, methods=["POST"]),
        Route("/auth/refresh", auth_endpoints.refresh, methods=["POST"]),
        Route("/auth/logout", auth_endpoints.logout, methods=["POST"]),
        Route("/auth/me", auth_endpoints.me, methods=["GET"]),

        # OAuth endpoints
        Route("/oauth/token", auth_endpoints.oauth_token, methods=["POST"]),
        Route("/authorize", authorize_page, methods=["GET", "POST"]),

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
        Route("/admin/settings", admin_routes.admin_settings, methods=["GET"]),
        Route("/admin/logs", admin_routes.admin_logs, methods=["GET"]),
        Route("/admin/api-test", admin_routes.admin_api_test, methods=["GET"]),

        # Admin API
        Route("/admin/api/stats", admin_routes.api_stats, methods=["GET"]),
        Route("/admin/api/users", admin_routes.api_users, methods=["GET"]),
        Route("/admin/api/users", admin_routes.api_create_user, methods=["POST"]),
        Route("/admin/api/users/{user_id:int}/status", admin_routes.api_update_user_status, methods=["PATCH"]),
        Route("/admin/api/users/{user_id:int}/superuser", admin_routes.api_make_superuser, methods=["PATCH"]),
        Route("/admin/api/users/{user_id:int}", admin_routes.api_delete_user, methods=["DELETE"]),
        Route("/admin/api/mcp-servers", admin_routes.api_list_mcp_servers, methods=["GET"]),
        Route("/admin/api/mcp-servers", admin_routes.api_create_mcp_server, methods=["POST"]),
        Route("/admin/api/mcp-servers/{server_id:int}", admin_routes.api_delete_mcp_server, methods=["DELETE"]),
        Route("/admin/api/mcp-servers/{server_id:int}", admin_routes.api_update_mcp_server, methods=["PATCH"]),
        Route("/admin/api/mcp-servers/{server_id:int}/test", admin_routes.api_test_mcp_server, methods=["POST"]),
        Route("/admin/api/mcp-servers/{server_id:int}/tools", admin_routes.api_get_mcp_server_tools, methods=["GET"]),
        Route("/admin/api/logs", admin_routes.api_logs, methods=["GET"]),
        Route("/admin/api/settings", admin_routes.api_get_settings, methods=["GET"]),
        Route("/admin/api/settings", admin_routes.api_save_settings, methods=["PUT"]),

        # Discovery endpoints
        Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", oauth_protected_resource, methods=["GET"]),
        Route("/mcp/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]),
        Route("/.well-known/openid-configuration", openid_configuration, methods=["GET"]),
        Route("/.well-known/jwks.json", jwks_json, methods=["GET"]),

        # Utility endpoints
        Route("/health", health, methods=["GET"]),
        Route("/", root_endpoint, methods=["GET"]),
        Route("/favicon.ico", favicon, methods=["GET"]),
    ]
)

# Store database path in app state for authorize endpoint
app.state.auth_db_path = config.auth.sqlite_path

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
logger.info("  - Auth endpoints: /auth/register, /auth/login, /auth/refresh, /auth/logout, /auth/me")
logger.info("  - MCP Gateway: /mcp (aggregates all backend servers)")
logger.info("  - Admin Panel: /admin")

# Export app for uvicorn
__all__ = ["app"]
