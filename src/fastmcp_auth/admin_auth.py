"""Authentication middleware for admin panel."""
import logging
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse, JSONResponse
from src.auth.jwt_handler import verify_token, decode_token_unsafe
from src.auth.user_store import is_token_blacklisted, get_user_by_id
from src.config import AppConfig
from src.setup_wizard import is_setup_required

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
            if is_setup_required():
                return await call_next(request)
            # If setup not required, redirect to admin
            if path == "/setup":
                return RedirectResponse(url="/admin", status_code=302)
        
        # Check if this is an admin route
        if not path.startswith("/admin"):
            return await call_next(request)
        
        # If setup required, redirect to setup
        if is_setup_required():
            if path.startswith("/admin/api"):
                return JSONResponse(
                    {"detail": "Setup required. Please complete initial setup first."},
                    status_code=403
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
            
            if not is_superuser:
                # Double-check in database
                user = get_user_by_id(self.config.auth.sqlite_path, user_id)
                if not user or not user.get("is_superuser"):
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
        if request.url.path.startswith("/admin/api"):
            return JSONResponse(
                {"detail": message},
                status_code=401
            )
        
        # For HTML requests, show login page
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - RAG MCP Server</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        body {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .login-card {{
            max-width: 400px;
            width: 100%;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 2rem;
        }}
        .login-header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        .login-header i {{
            font-size: 3rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 12px;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <i class="bi bi-shield-lock"></i>
            <h1 class="h3 mt-3">Admin Login</h1>
            <p class="text-muted">RAG MCP Server</p>
        </div>
        
        <div id="errorAlert" class="alert alert-danger d-none"></div>
        
        <form id="loginForm">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" class="form-control" id="username" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" class="form-control" id="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100" id="loginBtn">
                <i class="bi bi-box-arrow-in-right"></i> Login
            </button>
        </form>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorAlert = document.getElementById('errorAlert');
            const loginBtn = document.getElementById('loginBtn');
            
            errorAlert.classList.add('d-none');
            loginBtn.disabled = true;
            loginBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Logging in...';
            
            try {{
                const response = await fetch('/oauth/token', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
                    body: `grant_type=password&username=${{encodeURIComponent(username)}}&password=${{encodeURIComponent(password)}}`
                }});
                
                const data = await response.json();
                
                if (response.ok) {{
                    // Store token in cookie
                    document.cookie = `admin_token=${{data.access_token}}; path=/; max-age=1800; samesite=strict`;
                    // Redirect to admin
                    window.location.href = '/admin';
                }} else {{
                    errorAlert.textContent = data.detail || 'Login failed';
                    errorAlert.classList.remove('d-none');
                    loginBtn.disabled = false;
                    loginBtn.innerHTML = '<i class="bi bi-box-arrow-in-right"></i> Login';
                }}
            }} catch (error) {{
                errorAlert.textContent = 'Network error: ' + error.message;
                errorAlert.classList.remove('d-none');
                loginBtn.disabled = false;
                loginBtn.innerHTML = '<i class="bi bi-box-arrow-in-right"></i> Login';
            }}
        }});
    </script>
</body>
</html>
        """
        return Response(content=html, media_type="text/html", status_code=401)
    
    def _forbidden(self, request: Request) -> Response:
        """Return forbidden response."""
        if request.url.path.startswith("/admin/api"):
            return JSONResponse(
                {"detail": "Superuser access required"},
                status_code=403
            )
        
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Access Denied</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .error-card { max-width: 400px; background: white; border-radius: 16px; padding: 2rem; text-align: center; }
    </style>
</head>
<body>
    <div class="error-card">
        <h1 class="display-1">403</h1>
        <h2>Access Denied</h2>
        <p class="text-muted">You need superuser privileges to access the admin panel.</p>
        <a href="/" class="btn btn-primary">Go Home</a>
    </div>
</body>
</html>
        """
        return Response(content=html, media_type="text/html", status_code=403)
