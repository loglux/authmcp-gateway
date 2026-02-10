"""Setup wizard for initial configuration."""
import logging
from typing import Optional
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastmcp_auth.auth.user_store import get_all_users, create_user
from fastmcp_auth.auth.password import hash_password, validate_password_strength
from fastmcp_auth.config import AppConfig

logger = logging.getLogger(__name__)

# Global config instance
_config: Optional[AppConfig] = None


def initialize(config: AppConfig) -> None:
    """Initialize setup wizard with config."""
    global _config
    _config = config
    logger.info("Setup wizard initialized")


def is_setup_required() -> bool:
    """Check if initial setup is required (no users exist)."""
    if _config is None:
        return False
    
    try:
        users = get_all_users(_config.auth.sqlite_path)
        return len(users) == 0
    except Exception as e:
        logger.error(f"Failed to check setup status: {e}")
        return False


async def setup_page(_: Request) -> HTMLResponse:
    """Display setup wizard page."""
    if not is_setup_required():
        return RedirectResponse(url="/admin", status_code=302)
    
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Initial Setup - RAG MCP Server</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .setup-card {
            max-width: 500px;
            width: 100%;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .setup-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 16px 16px 0 0;
            text-align: center;
        }
        .setup-body {
            padding: 2rem;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 12px;
            font-weight: 600;
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #5568d3 0%, #6a3f8c 100%);
        }
        .password-requirements {
            font-size: 0.875rem;
            color: #6c757d;
            margin-top: 0.5rem;
        }
        .password-requirements li {
            margin-bottom: 0.25rem;
        }
        .alert {
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="setup-card">
        <div class="setup-header">
            <i class="bi bi-shield-lock" style="font-size: 3rem; margin-bottom: 1rem;"></i>
            <h1 class="h3 mb-2">Welcome to RAG MCP Server</h1>
            <p class="mb-0">Initial Setup - Create Administrator Account</p>
        </div>
        
        <div class="setup-body">
            <div id="errorAlert" class="alert alert-danger d-none" role="alert">
                <i class="bi bi-exclamation-triangle"></i>
                <span id="errorMessage"></span>
            </div>
            
            <form id="setupForm">
                <div class="mb-3">
                    <label class="form-label">
                        <i class="bi bi-person"></i> Username
                    </label>
                    <input type="text" class="form-control" id="username" required 
                           pattern="[a-zA-Z0-9_-]+" minlength="3" maxlength="50"
                           placeholder="admin">
                    <small class="text-muted">3-50 characters, alphanumeric, _ or -</small>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">
                        <i class="bi bi-envelope"></i> Email
                    </label>
                    <input type="email" class="form-control" id="email" required
                           placeholder="admin@example.com">
                </div>
                
                <div class="mb-3">
                    <label class="form-label">
                        <i class="bi bi-key"></i> Password
                    </label>
                    <input type="password" class="form-control" id="password" required
                           minlength="8" placeholder="••••••••">
                    <ul class="password-requirements mt-2">
                        <li>At least 8 characters</li>
                        <li>Contains uppercase letter</li>
                        <li>Contains lowercase letter</li>
                        <li>Contains number</li>
                        <li class="text-warning">⚠️ Avoid special characters (!, @, #) due to known issue</li>
                    </ul>
                </div>
                
                <div class="mb-3">
                    <label class="form-label">
                        <i class="bi bi-key-fill"></i> Confirm Password
                    </label>
                    <input type="password" class="form-control" id="confirmPassword" required
                           minlength="8" placeholder="••••••••">
                </div>
                
                <div class="mb-3">
                    <label class="form-label">
                        <i class="bi bi-person-badge"></i> Full Name (optional)
                    </label>
                    <input type="text" class="form-control" id="fullName"
                           placeholder="Administrator">
                </div>
                
                <button type="submit" class="btn btn-primary w-100" id="submitBtn">
                    <i class="bi bi-check-circle"></i> Create Administrator Account
                </button>
            </form>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('setupForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const fullName = document.getElementById('fullName').value;
            
            // Hide previous errors
            document.getElementById('errorAlert').classList.add('d-none');
            
            // Validate passwords match
            if (password !== confirmPassword) {
                showError('Passwords do not match');
                return;
            }
            
            // Disable submit button
            const submitBtn = document.getElementById('submitBtn');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Creating...';
            
            try {
                const response = await fetch('/setup/create-admin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username,
                        email,
                        password,
                        full_name: fullName || null,
                        is_superuser: true
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Success - redirect to admin login
                    window.location.href = '/admin?setup=success';
                } else {
                    showError(data.detail || 'Failed to create administrator account');
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="bi bi-check-circle"></i> Create Administrator Account';
                }
            } catch (error) {
                showError('Network error: ' + error.message);
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="bi bi-check-circle"></i> Create Administrator Account';
            }
        });
        
        function showError(message) {
            document.getElementById('errorMessage').textContent = message;
            document.getElementById('errorAlert').classList.remove('d-none');
        }
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html)


async def create_admin_user(request: Request) -> JSONResponse:
    """Create initial admin user."""
    if _config is None:
        return JSONResponse({"detail": "Config not initialized"}, status_code=500)
    
    # Check if setup is still required
    if not is_setup_required():
        return JSONResponse(
            {"detail": "Setup already completed. Users exist in database."},
            status_code=403
        )
    
    try:
        body = await request.json()
        username = body.get("username")
        email = body.get("email")
        password = body.get("password")
        full_name = body.get("full_name")
        
        if not username or not email or not password:
            return JSONResponse(
                {"detail": "Username, email, and password are required"},
                status_code=400
            )
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(password, _config.auth)
        if not is_valid:
            return JSONResponse({"detail": error_msg}, status_code=400)
        
        # Hash password
        password_hash = hash_password(password)
        
        # Create admin user
        user_id = create_user(
            db_path=_config.auth.sqlite_path,
            username=username,
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            is_superuser=True  # Always superuser for initial setup
        )
        
        logger.info(f"Initial admin user created: {username} (id={user_id})")
        
        return JSONResponse({
            "success": True,
            "user_id": user_id,
            "username": username,
            "message": "Administrator account created successfully"
        }, status_code=201)
        
    except Exception as e:
        logger.error(f"Failed to create admin user: {e}")
        return JSONResponse(
            {"detail": str(e)},
            status_code=500
        )
