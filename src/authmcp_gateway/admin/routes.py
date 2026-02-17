"""Admin panel routes.

Shared infrastructure (config, decorators, template helpers) and thin page
renderers live here.  All API logic has been extracted into submodules and is
re-exported via star-imports at the bottom so that ``app.py`` can continue to
use the ``admin_routes.function_name`` pattern unchanged.
"""

import logging
from functools import wraps
from pathlib import Path
from typing import Callable

from jinja2 import Environment, FileSystemLoader
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

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


def get_config(request: Request) -> AppConfig:
    """Return the config instance from app state.

    Submodules call this at *runtime* to access the live AppConfig.
    """
    return request.app.state.config


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
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.exception(f"{func.__name__} failed: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

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
        active_page: The current active page (dashboard, users, mcp-servers, settings, logs)

    Returns:
        HTML string for sidebar navigation (complete <li> elements)
    """
    menu_items = [
        ("dashboard", "/admin", '<i class="bi bi-speedometer2"></i> Dashboard'),
        ("mcp-activity", "/admin/mcp-activity", '<i class="bi bi-activity"></i> MCP Activity'),
        ("mcp-servers", "/admin/mcp-servers", '<i class="bi bi-hdd-network"></i> MCP Servers'),
        (
            "security-logs",
            "/admin/security-logs",
            '<i class="bi bi-shield-exclamation"></i> Security Events',
        ),
        ("mcp-audit", "/admin/mcp-audit", '<i class="bi bi-shield-check"></i> Security Audit'),
        ("settings", "/admin/settings", '<i class="bi bi-gear"></i> Settings'),
        (
            "oauth-clients",
            "/admin/oauth-clients",
            '<i class="bi bi-shield-lock"></i> OAuth Clients',
        ),
        ("users", "/admin/users", '<i class="bi bi-people"></i> Users'),
        ("logs", "/admin/logs", '<i class="bi bi-clock-history"></i> Auth Logs'),
    ]

    nav_html = ""
    for page_id, url, label in menu_items:
        active_class = "active" if page_id == active_page else ""
        nav_html += f"""                    <li class="nav-item mb-2">
                        <a class="nav-link {active_class}" href="{url}">
                            {label}
                        </a>
                    </li>
"""

    # Add external MCP endpoint link
    nav_html += """                    <li class="nav-item mt-4">
                        <a class="nav-link" href="/mcp" target="_blank">
                            <i class="bi bi-box-arrow-up-right"></i> MCP Endpoint
                        </a>
                    </li>
"""

    return nav_html


# ============================================================================
# THIN PAGE RENDERERS (stay in routes.py — 1-3 lines each)
# ============================================================================


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


# ============================================================================
# RE-EXPORTS — keep admin_routes.* API intact for app.py
# ============================================================================

from .logs_api import *  # noqa: E402,F401,F403
from .mcp_activity_api import *  # noqa: E402,F401,F403
from .mcp_servers_api import *  # noqa: E402,F401,F403
from .mcp_tokens_api import *  # noqa: E402,F401,F403
from .settings_api import *  # noqa: E402,F401,F403
from .user_api import *  # noqa: E402,F401,F403
from .user_pages import *  # noqa: E402,F401,F403
