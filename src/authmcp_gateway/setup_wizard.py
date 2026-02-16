"""Setup wizard for initial configuration."""

import logging
from dataclasses import replace
from typing import Optional

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from authmcp_gateway.auth.password import hash_password, validate_password_strength
from authmcp_gateway.auth.user_store import create_user, get_all_users
from authmcp_gateway.config import AppConfig
from authmcp_gateway.settings_manager import get_settings_manager

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
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Initial Setup - AuthMCP Gateway</title>
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <link rel="stylesheet" href="/static/tailwind.css">
    <script src="/static/lucide.min.js"></script>
</head>
<body class="h-full bg-gradient-to-br from-blue-600 via-cyan-600 to-cyan-700">
    <div class="min-h-full flex items-center justify-center px-4 py-12">
        <div class="max-w-md w-full bg-white rounded-2xl shadow-2xl overflow-hidden">
            <!-- Header -->
            <div class="bg-gradient-to-r from-blue-600 to-cyan-600 text-white px-8 py-6 text-center">
                <div class="flex justify-center mb-3">
                    <div class="p-3 bg-white/20 rounded-full">
                        <i data-lucide="shield-check" class="w-10 h-10"></i>
                    </div>
                </div>
                <h1 class="text-2xl font-bold mb-1">Welcome to AuthMCP Gateway</h1>
                <p class="text-white/80 text-sm">Initial Setup &mdash; Create Administrator Account</p>
            </div>

            <!-- Body -->
            <div class="p-8">
                <!-- Error Alert -->
                <div id="errorAlert" class="hidden bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4 flex items-start gap-2 text-sm" role="alert">
                    <i data-lucide="alert-circle" class="w-5 h-5 mt-0.5 flex-shrink-0"></i>
                    <span id="errorMessage"></span>
                </div>

                <form id="setupForm" class="space-y-5">
                    <!-- Username -->
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700 mb-1">Username</label>
                        <input type="text" id="username" required
                               pattern="[a-zA-Z0-9_-]+" minlength="3" maxlength="50"
                               placeholder="admin"
                               class="block w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
                        <p class="text-xs text-gray-500 mt-1">3-50 characters, alphanumeric, _ or -</p>
                    </div>

                    <!-- Email -->
                    <div>
                        <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email</label>
                        <input type="email" id="email" required
                               placeholder="admin@example.com"
                               class="block w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
                    </div>

                    <!-- Password -->
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Password</label>
                        <ul class="text-xs text-gray-500 space-y-0.5 mb-2 ml-1">
                            <li>At least 8 characters</li>
                            <li>Contains uppercase letter</li>
                            <li>Contains lowercase letter</li>
                            <li>Contains number</li>
                            <li>Special characters allowed</li>
                        </ul>
                        <input type="password" id="password" required
                               minlength="8" placeholder="••••••••"
                               class="block w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
                    </div>

                    <!-- Confirm Password -->
                    <div>
                        <label for="confirmPassword" class="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
                        <input type="password" id="confirmPassword" required
                               minlength="8" placeholder="••••••••"
                               class="block w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
                        <p id="passwordMatch" class="hidden text-xs mt-1"></p>
                    </div>

                    <!-- Full Name -->
                    <div>
                        <label for="fullName" class="block text-sm font-medium text-gray-700 mb-1">Full Name <span class="text-gray-400">(optional)</span></label>
                        <input type="text" id="fullName"
                               placeholder="Administrator"
                               class="block w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
                    </div>

                    <!-- Submit -->
                    <button type="submit" id="submitBtn"
                            class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 text-white py-3 px-4 rounded-lg font-semibold hover:from-blue-700 hover:to-cyan-700 transition-all shadow-lg hover:shadow-xl flex items-center justify-center gap-2">
                        <i data-lucide="check-circle" class="w-5 h-5"></i>
                        Create Administrator Account
                    </button>
                </form>
            </div>
        </div>
    </div>

    <script>
        lucide.createIcons();

        document.getElementById('setupForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const fullName = document.getElementById('fullName').value;

            // Hide previous errors
            document.getElementById('errorAlert').classList.add('hidden');

            // Validate passwords match
            if (password !== confirmPassword) {
                showError('Passwords do not match');
                return;
            }

            // Disable submit button
            const submitBtn = document.getElementById('submitBtn');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="inline-block animate-spin rounded-full h-5 w-5 border-b-2 border-white"></span> Creating...';

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
                    window.location.href = '/admin?setup=success';
                } else {
                    showError(data.detail || 'Failed to create administrator account');
                    resetBtn(submitBtn);
                }
            } catch (error) {
                showError('Network error: ' + error.message);
                resetBtn(submitBtn);
            }
        });

        function resetBtn(btn) {
            btn.disabled = false;
            btn.innerHTML = '<i data-lucide="check-circle" class="w-5 h-5"></i> Create Administrator Account';
            lucide.createIcons({ nodes: [btn] });
        }

        function showError(message) {
            document.getElementById('errorMessage').textContent = message;
            document.getElementById('errorAlert').classList.remove('hidden');
        }

        function checkPasswordMatch() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const el = document.getElementById('passwordMatch');

            if (confirmPassword === '') {
                el.classList.add('hidden');
                return;
            }

            el.classList.remove('hidden');
            if (password === confirmPassword) {
                el.textContent = 'Passwords match';
                el.className = 'text-xs mt-1 text-green-600';
            } else {
                el.textContent = 'Passwords do not match';
                el.className = 'text-xs mt-1 text-red-600';
            }
        }

        document.getElementById('password').addEventListener('input', checkPasswordMatch);
        document.getElementById('confirmPassword').addEventListener('input', checkPasswordMatch);
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
            {"detail": "Setup already completed. Users exist in database."}, status_code=403
        )

    try:
        body = await request.json()
        username = body.get("username")
        email = body.get("email")
        password = body.get("password")
        full_name = body.get("full_name")

        if not username or not email or not password:
            return JSONResponse(
                {"detail": "Username, email, and password are required"}, status_code=400
            )

        # Validate password strength against settings (if available)
        policy = _config.auth
        try:
            settings = get_settings_manager()
            policy_data = settings.get("password_policy", default={}) or {}
            policy = replace(
                policy,
                password_min_length=policy_data.get("min_length", policy.password_min_length),
                password_require_uppercase=policy_data.get(
                    "require_uppercase", policy.password_require_uppercase
                ),
                password_require_lowercase=policy_data.get(
                    "require_lowercase", policy.password_require_lowercase
                ),
                password_require_digit=policy_data.get(
                    "require_digit", policy.password_require_digit
                ),
                password_require_special=policy_data.get(
                    "require_special", policy.password_require_special
                ),
            )
        except Exception:
            pass

        is_valid, error_msg = validate_password_strength(password, policy)
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
            is_superuser=True,  # Always superuser for initial setup
        )

        logger.info(f"Initial admin user created: {username} (id={user_id})")

        return JSONResponse(
            {
                "success": True,
                "user_id": user_id,
                "username": username,
                "message": "Administrator account created successfully",
            },
            status_code=201,
        )

    except Exception as e:
        logger.error(f"Failed to create admin user: {e}")
        return JSONResponse({"detail": str(e)}, status_code=500)
