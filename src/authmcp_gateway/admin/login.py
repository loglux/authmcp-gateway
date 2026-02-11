"""Admin login page and endpoint."""

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from authmcp_gateway.auth.jwt_handler import create_access_token
from authmcp_gateway.auth.password import verify_password
from authmcp_gateway.auth.user_store import get_user_by_username, update_last_login, log_auth_event
from authmcp_gateway.rate_limiter import get_rate_limiter
import logging

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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - FastMCP Auth</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            max-width: 400px;
            width: 100%;
            background: white;
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .login-title {
            color: #764ba2;
            margin-bottom: 1.5rem;
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 0.75rem;
        }
        .error-message {
            display: none;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h2 class="login-title text-center">🔐 Admin Login</h2>
        <p class="text-center text-muted mb-4">AuthMCP Gateway</p>
        
        <form id="loginForm">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" required autofocus>
            </div>
            
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" required>
            </div>
            
            <button type="submit" class="btn btn-login btn-primary w-100 text-white">
                Login
            </button>
            
            <div class="alert alert-danger error-message" id="errorMessage"></div>
        </form>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('errorMessage');
            
            errorDiv.style.display = 'none';
            
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
                    errorDiv.textContent = data.detail || 'Login failed';
                    errorDiv.style.display = 'block';
                }
            } catch (err) {
                errorDiv.textContent = 'Network error';
                errorDiv.style.display = 'block';
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
                window=_config.rate_limit.login_window
            )

            if not allowed:
                logger.warning(f"Rate limit exceeded for admin login from {client_ip}")
                return JSONResponse(
                    {
                        "detail": "Too many login attempts. Please try again later.",
                        "retry_after": retry_after
                    },
                    status_code=429,
                    headers={"Retry-After": str(retry_after)}
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
                details="Invalid credentials"
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
                details="Not a superuser"
            )
            return JSONResponse({"detail": "Access denied. Admin panel is only available for superuser accounts."}, status_code=403)

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
                details="Invalid credentials"
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
                details="Account disabled"
            )
            return JSONResponse({"detail": "Account disabled"}, status_code=403)
        
        # Create JWT token
        access_token = create_access_token(
            user_id=user["id"],
            username=user["username"],
            is_superuser=True,
            config=_config.jwt
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
            details="Admin login successful"
        )

        logger.info(f"Admin logged in: {username}")

        # Set cookie and return success
        response = JSONResponse({"success": True, "username": username})

        # Determine if request is HTTPS
        is_https = (
            request.url.scheme == "https" or
            request.headers.get("x-forwarded-proto") == "https"
        )

        response.set_cookie(
            key="admin_token",
            value=access_token,
            path="/",
            httponly=True,
            secure=is_https,  # Based on current request, not config
            samesite="lax",
            max_age=_config.jwt.access_token_expire_minutes * 60
        )
        
        return response
        
    except Exception as e:
        logger.exception("Admin login error")
        return JSONResponse({"detail": "Login failed"}, status_code=500)


async def admin_logout(request: Request) -> Response:
    """Logout admin."""
    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("admin_token")
    return response
