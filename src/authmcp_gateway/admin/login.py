"""Admin login page and endpoint."""

import logging

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from authmcp_gateway.auth.password import verify_password
from authmcp_gateway.auth.user_store import get_user_by_username, log_auth_event, update_last_login
from authmcp_gateway.rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)

_config = None


def set_config(config):
    """Set global config."""
    global _config
    _config = config


async def admin_login_page(request: Request) -> HTMLResponse:
    """Admin login page."""
    html = """
<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - MCP Auth</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .fade-in { animation: fadeIn 0.5s ease-out; }
    </style>
</head>
<body class="h-full bg-gradient-to-br from-blue-600 via-cyan-600 to-cyan-700">
    <div class="min-h-full flex items-center justify-center px-4 py-12">
        <div class="max-w-md w-full bg-white rounded-2xl shadow-2xl p-8 fade-in">
            <!-- Logo/Icon -->
            <div class="flex justify-center mb-6">
                <div class="p-4 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-full">
                    <i data-lucide="shield-check" class="w-12 h-12 text-white"></i>
                </div>
            </div>
            
            <!-- Title -->
            <div class="text-center mb-8">
                <h2 class="text-3xl font-bold text-gray-900 mb-2">Admin Login</h2>
                <p class="text-gray-600">AuthMCP Gateway</p>
            </div>
            
            <!-- Form -->
            <form id="loginForm" class="space-y-6">
                <!-- Username -->
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700 mb-2">
                        Username
                    </label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <i data-lucide="user" class="w-5 h-5 text-gray-400"></i>
                        </div>
                        <input 
                            type="text" 
                            id="username" 
                            required 
                            autofocus
                            class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                            placeholder="Enter your username"
                        >
                    </div>
                </div>
                
                <!-- Password -->
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                        Password
                    </label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <i data-lucide="lock" class="w-5 h-5 text-gray-400"></i>
                        </div>
                        <input 
                            type="password" 
                            id="password" 
                            required
                            class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                            placeholder="Enter your password"
                        >
                    </div>
                </div>
                
                <!-- Submit Button -->
                <button 
                    type="submit" 
                    class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 text-white py-3 px-4 rounded-lg font-semibold hover:from-blue-700 hover:to-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all shadow-lg hover:shadow-xl flex items-center justify-center gap-2"
                >
                    <i data-lucide="log-in" class="w-5 h-5"></i>
                    Login
                </button>
                
                <!-- Error Message -->
                <div id="errorMessage" class="hidden bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-start gap-2">
                    <i data-lucide="alert-circle" class="w-5 h-5 mt-0.5 flex-shrink-0"></i>
                    <span id="errorText"></span>
                </div>
                
                <div class="text-center text-sm text-gray-500">
                    Not an admin? <a href="/account" class="text-blue-600 hover:underline">Go to your account</a>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Initialize Lucide icons
        lucide.createIcons();
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('errorMessage');
            const errorText = document.getElementById('errorText');
            
            // Hide error
            errorDiv.classList.add('hidden');
            
            try {
                const response = await fetch('/admin/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                if (response.ok) {
                    window.location.href = '/admin';
                } else {
                    const data = await response.json();
                    if (response.status === 403) {
                        window.location.href = '/account';
                        return;
                    }
                    errorText.textContent = data.detail || 'Login failed';
                    errorDiv.classList.remove('hidden');
                    lucide.createIcons();
                }
            } catch (err) {
                errorText.textContent = 'Network error. Please try again.';
                errorDiv.classList.remove('hidden');
                lucide.createIcons();
            }
        });
    </script>
</body>
</html>
    """
    return HTMLResponse(html)


async def admin_login_api(request: Request) -> Response:
    """Process admin login."""
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return JSONResponse({"detail": "Username and password required"}, status_code=400)

        # Rate limiting check
        if _config.rate_limit.enabled:
            limiter = get_rate_limiter()
            client_ip = request.client.host if request.client else "unknown"
            identifier = f"admin_login:{client_ip}"

            allowed, retry_after = limiter.check_limit(
                identifier=identifier,
                limit=_config.rate_limit.login_limit,
                window=_config.rate_limit.login_window,
            )

            if not allowed:
                logger.warning(f"Rate limit exceeded for admin login from {client_ip}")
                return JSONResponse(
                    {
                        "detail": "Too many login attempts. Please try again later.",
                        "retry_after": retry_after,
                    },
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )

        # Get user
        user = get_user_by_username(_config.auth.sqlite_path, username)
        if not user:
            logger.warning(f"Admin login failed: invalid credentials - {username}")
            log_auth_event(
                db_path=_config.auth.sqlite_path,
                event_type="admin_login",
                username=username,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                success=False,
                details="Invalid credentials",
            )
            return JSONResponse({"detail": "Invalid credentials"}, status_code=401)

        # Check if superuser
        if not user.get("is_superuser"):
            logger.warning(f"Admin login failed: not superuser - {username}")
            log_auth_event(
                db_path=_config.auth.sqlite_path,
                event_type="admin_login",
                user_id=user["id"],
                username=username,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                success=False,
                details="Not a superuser",
            )
            return JSONResponse(
                {"detail": "Access denied. Admin panel is only available for superuser accounts."},
                status_code=403,
            )

        # Verify password
        if not verify_password(password, user["password_hash"]):
            logger.warning(f"Admin login failed: invalid credentials - {username}")
            log_auth_event(
                db_path=_config.auth.sqlite_path,
                event_type="admin_login",
                user_id=user["id"],
                username=username,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                success=False,
                details="Invalid credentials",
            )
            return JSONResponse({"detail": "Invalid credentials"}, status_code=401)

        # Check if active
        if not user.get("is_active"):
            logger.warning(f"Admin login failed: inactive user - {username}")
            log_auth_event(
                db_path=_config.auth.sqlite_path,
                event_type="admin_login",
                user_id=user["id"],
                username=username,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                success=False,
                details="Account disabled",
            )
            return JSONResponse({"detail": "Account disabled"}, status_code=403)

        from authmcp_gateway.auth.token_service import get_or_create_admin_token

        access_token, _ = get_or_create_admin_token(
            _config.auth.sqlite_path,
            user["id"],
            user["username"],
            True,
            _config.jwt,
            _config.jwt.admin_token_expire_minutes,
            current_token=request.cookies.get("admin_token"),
        )

        # Update last login
        update_last_login(_config.auth.sqlite_path, user["id"])

        # Log successful login
        log_auth_event(
            db_path=_config.auth.sqlite_path,
            event_type="admin_login",
            user_id=user["id"],
            username=username,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=True,
            details="Admin login successful",
        )

        logger.info(f"Admin logged in: {username}")

        # Set cookie and return success
        response = JSONResponse({"success": True, "username": username})

        # Determine if request is HTTPS
        is_https = (
            request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        )

        response.set_cookie(
            key="admin_token",
            value=access_token,
            path="/",
            httponly=True,
            secure=is_https,  # Based on current request, not config
            samesite="lax",
            max_age=_config.jwt.admin_token_expire_minutes * 60,
        )

        return response

    except Exception:
        logger.exception("Admin login error")
        return JSONResponse({"detail": "Login failed"}, status_code=500)


async def admin_logout(request: Request) -> Response:
    """Logout admin."""
    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("admin_token")
    return response
