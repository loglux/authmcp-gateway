"""Admin panel routes."""
import logging
from typing import Optional
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from src.auth.user_store import (
    get_all_users,
    get_auth_logs,
    update_user_status,
    make_user_superuser,
)
from src.config import AppConfig

logger = logging.getLogger(__name__)

# Global config instance
_config: Optional[AppConfig] = None


def initialize(config: AppConfig) -> None:
    """Initialize admin routes with config."""
    global _config
    _config = config
    logger.info("Admin routes initialized")


def _get_sidebar_nav(active_page: str = "") -> str:
    """Generate unified sidebar navigation menu.

    Args:
        active_page: The current active page (dashboard, users, mcp-servers, settings, logs, api-test)

    Returns:
        HTML string for sidebar navigation (complete <li> elements)
    """
    menu_items = [
        ("dashboard", "/admin", '<i class="bi bi-speedometer2"></i> Dashboard'),
        ("users", "/admin/users", '<i class="bi bi-people"></i> Users'),
        ("mcp-servers", "/admin/mcp-servers", '<i class="bi bi-hdd-network"></i> MCP Servers'),
        ("settings", "/admin/settings", '<i class="bi bi-gear"></i> Settings'),
        ("logs", "/admin/logs", '<i class="bi bi-clock-history"></i> Auth Logs'),
        ("api-test", "/admin/api-test", '<i class="bi bi-code-square"></i> API Test'),
    ]

    nav_html = ""
    for page_id, url, label in menu_items:
        active_class = "active" if page_id == active_page else ""
        nav_html += f'''                    <li class="nav-item mb-2">
                        <a class="nav-link {active_class}" href="{url}">
                            {label}
                        </a>
                    </li>
'''

    # Add external MCP endpoint link
    nav_html += '''                    <li class="nav-item mt-4">
                        <a class="nav-link" href="/mcp" target="_blank">
                            <i class="bi bi-box-arrow-up-right"></i> MCP Endpoint
                        </a>
                    </li>
'''

    return nav_html


async def admin_dashboard(_: Request) -> HTMLResponse:
    """Admin dashboard page."""
    sidebar_nav = _get_sidebar_nav("dashboard")
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Auth Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
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
        .stat-card {
            border-left: 4px solid #667eea;
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-2 d-md-block sidebar p-3">
                <div class="text-center mb-4">
                    <h4 class="text-white"><i class="bi bi-shield-lock"></i> MCP Auth</h4>
                    <small class="text-white-50">Admin Panel</small>
                </div>
                <ul class="nav flex-column">
{SIDEBAR_NAV}
                </ul>
            </nav>

            <!-- Main content -->
            <main class="col-md-10 ms-sm-auto px-md-4 py-4">
                <h1 class="mb-4">Dashboard</h1>

                <!-- Stats Cards -->
                <div class="row mb-4" id="stats">
                    <div class="col-md-3 mb-3">
                        <div class="card stat-card">
                            <div class="card-body">
                                <h6 class="text-muted">Total Users</h6>
                                <h2 class="mb-0"><span id="totalUsers">-</span></h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card stat-card">
                            <div class="card-body">
                                <h6 class="text-muted">Active Users</h6>
                                <h2 class="mb-0"><span id="activeUsers">-</span></h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card stat-card">
                            <div class="card-body">
                                <h6 class="text-muted">Superusers</h6>
                                <h2 class="mb-0"><span id="superusers">-</span></h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="card stat-card">
                            <div class="card-body">
                                <h6 class="text-muted">Recent Logins (24h)</h6>
                                <h2 class="mb-0"><span id="recentLogins">-</span></h2>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Quick Info -->
                <div class="row">
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <i class="bi bi-info-circle"></i> System Info
                            </div>
                            <div class="card-body">
                                <table class="table table-sm">
                                    <tr>
                                        <td><strong>JWT Algorithm:</strong></td>
                                        <td id="jwtAlgo">-</td>
                                    </tr>
                                    <tr>
                                        <td><strong>Access Token TTL:</strong></td>
                                        <td id="accessTTL">-</td>
                                    </tr>
                                    <tr>
                                        <td><strong>Refresh Token TTL:</strong></td>
                                        <td id="refreshTTL">-</td>
                                    </tr>
                                    <tr>
                                        <td><strong>Public URL:</strong></td>
                                        <td id="publicUrl">-</td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <i class="bi bi-link-45deg"></i> API Endpoints
                            </div>
                            <div class="card-body">
                                <div class="list-group">
                                    <div class="list-group-item">
                                        <code>POST /auth/register</code>
                                        <small class="text-muted d-block">User registration</small>
                                    </div>
                                    <div class="list-group-item">
                                        <code>POST /oauth/token</code>
                                        <small class="text-muted d-block">OAuth2 token endpoint</small>
                                    </div>
                                    <div class="list-group-item">
                                        <code>GET /auth/me</code>
                                        <small class="text-muted d-block">Current user profile</small>
                                    </div>
                                    <div class="list-group-item">
                                        <code>POST /mcp</code>
                                        <small class="text-muted d-block">MCP protocol endpoint</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Load dashboard stats
        async function loadStats() {
            try {
                const response = await fetch('/admin/api/stats');
                const data = await response.json();

                document.getElementById('totalUsers').textContent = data.total_users;
                document.getElementById('activeUsers').textContent = data.active_users;
                document.getElementById('superusers').textContent = data.superusers;
                document.getElementById('recentLogins').textContent = data.recent_logins;

                document.getElementById('jwtAlgo').textContent = data.system.jwt_algorithm;
                document.getElementById('accessTTL').textContent = data.system.access_token_ttl;
                document.getElementById('refreshTTL').textContent = data.system.refresh_token_ttl;
                document.getElementById('publicUrl').textContent = data.system.public_url;
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        loadStats();
        setInterval(loadStats, 30000); // Refresh every 30 seconds
    </script>
</body>
</html>
    """
    html = html.replace("{SIDEBAR_NAV}", sidebar_nav)
    return HTMLResponse(content=html)


async def admin_users(_: Request) -> HTMLResponse:
    """Admin users management page."""
    sidebar_nav = _get_sidebar_nav("users")
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Users - MCP Auth Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
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
        .badge-superuser {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-2 d-md-block sidebar p-3">
                <div class="text-center mb-4">
                    <h4 class="text-white"><i class="bi bi-shield-lock"></i> MCP Auth</h4>
                    <small class="text-white-50">Admin Panel</small>
                </div>
                <ul class="nav flex-column">
{SIDEBAR_NAV}
                </ul>
            </nav>

            <!-- Main content -->
            <main class="col-md-10 ms-sm-auto px-md-4 py-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h1>Users Management</h1>
                    <button class="btn btn-primary" onclick="showCreateUserModal()">
                        <i class="bi bi-plus-circle"></i> Create User
                    </button>
                </div>

                <!-- Users Table -->
                <div class="card">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="usersTable">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Status</th>
                                        <th>Role</th>
                                        <th>Last Login</th>
                                        <th>Created</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="usersTableBody">
                                    <tr>
                                        <td colspan="8" class="text-center">
                                            <div class="spinner-border text-primary" role="status">
                                                <span class="visually-hidden">Loading...</span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- Create User Modal -->
    <div class="modal fade" id="createUserModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create New User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="createUserForm">
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" required>
                            <small class="text-muted">Min 8 characters, no special characters recommended</small>
                        </div>
                        <div class="form-check mb-3">
                            <input type="checkbox" class="form-check-input" id="isSuperuser">
                            <label class="form-check-label" for="isSuperuser">Make Superuser</label>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="createUser()">Create</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let createUserModalInstance;

        document.addEventListener('DOMContentLoaded', function() {
            createUserModalInstance = new bootstrap.Modal(document.getElementById('createUserModal'));
            loadUsers();
        });

        function showCreateUserModal() {
            document.getElementById('createUserForm').reset();
            createUserModalInstance.show();
        }

        async function loadUsers() {
            try {
                const response = await fetch('/admin/api/users');
                const users = await response.json();

                const tbody = document.getElementById('usersTableBody');
                tbody.innerHTML = users.map(user => `
                    <tr>
                        <td>${user.id}</td>
                        <td><strong>${user.username}</strong></td>
                        <td>${user.email}</td>
                        <td>
                            <span class="badge ${user.is_active ? 'bg-success' : 'bg-danger'}">
                                ${user.is_active ? 'Active' : 'Inactive'}
                            </span>
                        </td>
                        <td>
                            ${user.is_superuser ? '<span class="badge badge-superuser">Superuser</span>' : '<span class="badge bg-secondary">User</span>'}
                        </td>
                        <td>${user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never'}</td>
                        <td>${new Date(user.created_at).toLocaleDateString()}</td>
                        <td>
                            <button class="btn btn-sm btn-outline-primary" onclick="toggleUserStatus(${user.id}, ${user.is_active})" title="Toggle Status">
                                <i class="bi bi-power"></i>
                            </button>
                            ${!user.is_superuser ? `
                                <button class="btn btn-sm btn-outline-warning" onclick="makeSuperuser(${user.id})" title="Make Superuser">
                                    <i class="bi bi-star"></i>
                                </button>
                            ` : ''}
                        </td>
                    </tr>
                `).join('');
            } catch (error) {
                console.error('Failed to load users:', error);
                document.getElementById('usersTableBody').innerHTML = '<tr><td colspan="8" class="text-center text-danger">Failed to load users</td></tr>';
            }
        }

        async function createUser() {
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const is_superuser = document.getElementById('isSuperuser').checked;

            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, email, password, is_superuser})
                });

                if (response.ok) {
                    createUserModalInstance.hide();
                    loadUsers();
                    alert('User created successfully!');
                } else {
                    const error = await response.json();
                    alert('Error: ' + (error.detail || 'Failed to create user'));
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function toggleUserStatus(userId, currentStatus) {
            if (!confirm(`Are you sure you want to ${currentStatus ? 'deactivate' : 'activate'} this user?`)) {
                return;
            }

            try {
                const response = await fetch(`/admin/api/users/${userId}/status`, {
                    method: 'PATCH',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({is_active: !currentStatus})
                });

                if (response.ok) {
                    loadUsers();
                } else {
                    alert('Failed to update user status');
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function makeSuperuser(userId) {
            if (!confirm('Are you sure you want to make this user a superuser?')) {
                return;
            }

            try {
                const response = await fetch(`/admin/api/users/${userId}/superuser`, {
                    method: 'PATCH'
                });

                if (response.ok) {
                    loadUsers();
                } else {
                    alert('Failed to update user role');
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
    </script>
</body>
</html>
    """
    html = html.replace("{SIDEBAR_NAV}", sidebar_nav)
    return HTMLResponse(content=html)


async def admin_logs(_: Request) -> HTMLResponse:
    """Admin auth logs page."""
    sidebar_nav = _get_sidebar_nav("logs")
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auth Logs - MCP Auth Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
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
        .log-entry {
            border-left: 3px solid #e0e0e0;
            transition: all 0.3s;
        }
        .log-entry:hover {
            background: #f8f9fa;
            border-left-color: #667eea;
        }
        .log-success { border-left-color: #28a745; }
        .log-failed { border-left-color: #dc3545; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-2 d-md-block sidebar p-3">
                <div class="text-center mb-4">
                    <h4 class="text-white"><i class="bi bi-shield-lock"></i> MCP Auth</h4>
                    <small class="text-white-50">Admin Panel</small>
                </div>
                <ul class="nav flex-column">
{SIDEBAR_NAV}
                </ul>
            </nav>

            <!-- Main content -->
            <main class="col-md-10 ms-sm-auto px-md-4 py-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h1>Authentication Logs</h1>
                    <button class="btn btn-outline-secondary" onclick="loadLogs()">
                        <i class="bi bi-arrow-clockwise"></i> Refresh
                    </button>
                </div>

                <!-- Filters -->
                <div class="card mb-4">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <select class="form-select" id="eventTypeFilter" onchange="loadLogs()">
                                    <option value="">All Events</option>
                                    <option value="login">Login</option>
                                    <option value="register">Register</option>
                                    <option value="logout">Logout</option>
                                    <option value="failed_login">Failed Login</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <select class="form-select" id="limitFilter" onchange="loadLogs()">
                                    <option value="50">Last 50</option>
                                    <option value="100">Last 100</option>
                                    <option value="500">Last 500</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Logs -->
                <div class="card">
                    <div class="card-body" id="logsContainer">
                        <div class="text-center py-5">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', loadLogs);

        async function loadLogs() {
            const eventType = document.getElementById('eventTypeFilter').value;
            const limit = document.getElementById('limitFilter').value;

            try {
                const params = new URLSearchParams();
                if (eventType) params.append('event_type', eventType);
                if (limit) params.append('limit', limit);

                const response = await fetch(`/admin/api/logs?${params}`);
                const logs = await response.json();

                const container = document.getElementById('logsContainer');
                if (logs.length === 0) {
                    container.innerHTML = '<p class="text-center text-muted">No logs found</p>';
                    return;
                }

                container.innerHTML = logs.map(log => `
                    <div class="log-entry ${log.success ? 'log-success' : 'log-failed'} p-3 mb-2">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="mb-1">
                                    <span class="badge ${getEventBadgeClass(log.event_type)}">${log.event_type}</span>
                                    <strong>${log.username || 'Unknown'}</strong>
                                    ${log.success ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>'}
                                </h6>
                                <small class="text-muted">
                                    <i class="bi bi-clock"></i> ${new Date(log.created_at).toLocaleString()}
                                    ${log.ip_address ? `<i class="bi bi-geo-alt ms-3"></i> ${log.ip_address}` : ''}
                                </small>
                                ${log.details ? `<div class="mt-2"><small class="text-muted">${log.details}</small></div>` : ''}
                            </div>
                        </div>
                    </div>
                `).join('');
            } catch (error) {
                console.error('Failed to load logs:', error);
                document.getElementById('logsContainer').innerHTML = '<p class="text-center text-danger">Failed to load logs</p>';
            }
        }

        function getEventBadgeClass(eventType) {
            const classes = {
                'login': 'bg-success',
                'register': 'bg-info',
                'logout': 'bg-secondary',
                'failed_login': 'bg-danger'
            };
            return classes[eventType] || 'bg-secondary';
        }

        // Auto-refresh every 30 seconds
        setInterval(loadLogs, 30000);
    </script>
</body>
</html>
    """
    html = html.replace("{SIDEBAR_NAV}", sidebar_nav)
    return HTMLResponse(content=html)


async def admin_api_test(_: Request) -> HTMLResponse:
    """Admin API testing page."""
    sidebar_nav = _get_sidebar_nav("api-test")
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Test - MCP Auth Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
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
        pre {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 1rem;
            max-height: 400px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-2 d-md-block sidebar p-3">
                <div class="text-center mb-4">
                    <h4 class="text-white"><i class="bi bi-shield-lock"></i> MCP Auth</h4>
                    <small class="text-white-50">Admin Panel</small>
                </div>
                <ul class="nav flex-column">
{SIDEBAR_NAV}
                </ul>
            </nav>

            <!-- Main content -->
            <main class="col-md-10 ms-sm-auto px-md-4 py-4">
                <h1 class="mb-4">API Testing Interface</h1>

                <!-- Test Endpoints -->
                <div class="row">
                    <!-- Register -->
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <i class="bi bi-person-plus"></i> POST /auth/register
                            </div>
                            <div class="card-body">
                                <form id="registerForm">
                                    <div class="mb-2">
                                        <input type="text" class="form-control form-control-sm" placeholder="Username" id="reg_username" value="testuser">
                                    </div>
                                    <div class="mb-2">
                                        <input type="email" class="form-control form-control-sm" placeholder="Email" id="reg_email" value="test@test.com">
                                    </div>
                                    <div class="mb-2">
                                        <input type="password" class="form-control form-control-sm" placeholder="Password" id="reg_password" value="Test1234">
                                    </div>
                                    <button type="button" class="btn btn-primary btn-sm" onclick="testRegister()">Test</button>
                                </form>
                                <pre id="registerResponse" class="mt-3 d-none"></pre>
                            </div>
                        </div>
                    </div>

                    <!-- Login -->
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <i class="bi bi-box-arrow-in-right"></i> POST /oauth/token
                            </div>
                            <div class="card-body">
                                <form id="loginForm">
                                    <div class="mb-2">
                                        <input type="text" class="form-control form-control-sm" placeholder="Username" id="login_username" value="testuser">
                                    </div>
                                    <div class="mb-2">
                                        <input type="password" class="form-control form-control-sm" placeholder="Password" id="login_password" value="Test1234">
                                    </div>
                                    <button type="button" class="btn btn-success btn-sm" onclick="testLogin()">Test</button>
                                </form>
                                <pre id="loginResponse" class="mt-3 d-none"></pre>
                            </div>
                        </div>
                    </div>

                    <!-- Get Profile -->
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-info text-white">
                                <i class="bi bi-person"></i> GET /auth/me
                            </div>
                            <div class="card-body">
                                <div class="mb-2">
                                    <input type="text" class="form-control form-control-sm" placeholder="Access Token" id="me_token">
                                    <small class="text-muted">Get token from login response</small>
                                </div>
                                <button type="button" class="btn btn-info btn-sm" onclick="testGetMe()">Test</button>
                                <pre id="meResponse" class="mt-3 d-none"></pre>
                            </div>
                        </div>
                    </div>

                    <!-- MCP Tool Call -->
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header bg-warning text-dark">
                                <i class="bi bi-tools"></i> POST /mcp (list_knowledge_bases)
                            </div>
                            <div class="card-body">
                                <div class="mb-2">
                                    <input type="text" class="form-control form-control-sm" placeholder="Access Token" id="mcp_token">
                                    <small class="text-muted">Get token from login response</small>
                                </div>
                                <button type="button" class="btn btn-warning btn-sm" onclick="testMCP()">Test</button>
                                <pre id="mcpResponse" class="mt-3 d-none"></pre>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        async function testRegister() {
            const username = document.getElementById('reg_username').value;
            const email = document.getElementById('reg_email').value;
            const password = document.getElementById('reg_password').value;

            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, email, password})
                });

                const data = await response.json();
                const el = document.getElementById('registerResponse');
                el.textContent = JSON.stringify(data, null, 2);
                el.classList.remove('d-none');
            } catch (error) {
                const el = document.getElementById('registerResponse');
                el.textContent = 'Error: ' + error.message;
                el.classList.remove('d-none');
            }
        }

        async function testLogin() {
            const username = document.getElementById('login_username').value;
            const password = document.getElementById('login_password').value;

            try {
                const response = await fetch('/oauth/token', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: `grant_type=password&username=${username}&password=${password}`
                });

                const data = await response.json();
                const el = document.getElementById('loginResponse');
                el.textContent = JSON.stringify(data, null, 2);
                el.classList.remove('d-none');

                // Auto-fill tokens for other tests
                if (data.access_token) {
                    document.getElementById('me_token').value = data.access_token;
                    document.getElementById('mcp_token').value = data.access_token;
                }
            } catch (error) {
                const el = document.getElementById('loginResponse');
                el.textContent = 'Error: ' + error.message;
                el.classList.remove('d-none');
            }
        }

        async function testGetMe() {
            const token = document.getElementById('me_token').value;

            try {
                const response = await fetch('/auth/me', {
                    headers: {'Authorization': `Bearer ${token}`}
                });

                const data = await response.json();
                const el = document.getElementById('meResponse');
                el.textContent = JSON.stringify(data, null, 2);
                el.classList.remove('d-none');
            } catch (error) {
                const el = document.getElementById('meResponse');
                el.textContent = 'Error: ' + error.message;
                el.classList.remove('d-none');
            }
        }

        async function testMCP() {
            const token = document.getElementById('mcp_token').value;

            try {
                const response = await fetch('/mcp', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        jsonrpc: '2.0',
                        id: 1,
                        method: 'tools/call',
                        params: {
                            name: 'list_knowledge_bases',
                            arguments: {}
                        }
                    })
                });

                const data = await response.json();
                const el = document.getElementById('mcpResponse');
                el.textContent = JSON.stringify(data, null, 2);
                el.classList.remove('d-none');
            } catch (error) {
                const el = document.getElementById('mcpResponse');
                el.textContent = 'Error: ' + error.message;
                el.classList.remove('d-none');
            }
        }
    </script>
</body>
</html>
    """
    html = html.replace("{SIDEBAR_NAV}", sidebar_nav)
    return HTMLResponse(content=html)


# API endpoints for admin panel
async def api_stats(_: Request) -> JSONResponse:
    """Get dashboard statistics."""
    if _config is None:
        return JSONResponse({"error": "Config not initialized"}, status_code=500)

    try:
        users = get_all_users(_config.auth.sqlite_path)
        logs = get_auth_logs(_config.auth.sqlite_path, limit=1000)

        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(days=1)

        recent_logins = len([
            log for log in logs
            if log["event_type"] == "login"
            and log["success"]
            and datetime.fromisoformat(log["created_at"]).replace(tzinfo=timezone.utc) > day_ago
        ])

        return JSONResponse({
            "total_users": len(users),
            "active_users": len([u for u in users if u["is_active"]]),
            "superusers": len([u for u in users if u["is_superuser"]]),
            "recent_logins": recent_logins,
            "system": {
                "jwt_algorithm": _config.jwt.algorithm,
                "access_token_ttl": f"{_config.jwt.access_token_expire_minutes} min",
                "refresh_token_ttl": f"{_config.jwt.refresh_token_expire_days} days",
                "public_url": _config.mcp_public_url,
            }
        })
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_users(_: Request) -> JSONResponse:
    """Get all users."""
    if _config is None:
        return JSONResponse({"error": "Config not initialized"}, status_code=500)

    try:
        users = get_all_users(_config.auth.sqlite_path)
        return JSONResponse(users)
    except Exception as e:
        logger.error(f"Failed to get users: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_logs(request: Request) -> JSONResponse:
    """Get auth logs."""
    if _config is None:
        return JSONResponse({"error": "Config not initialized"}, status_code=500)

    try:
        event_type = request.query_params.get("event_type")
        limit = int(request.query_params.get("limit", "100"))

        logs = get_auth_logs(_config.auth.sqlite_path, event_type=event_type, limit=limit)
        return JSONResponse(logs)
    except Exception as e:
        logger.error(f"Failed to get logs: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_update_user_status(request: Request) -> Response:
    """Update user active status."""
    if _config is None:
        return JSONResponse({"error": "Config not initialized"}, status_code=500)

    try:
        user_id = int(request.path_params["user_id"])
        body = await request.json()
        is_active = body.get("is_active", True)

        update_user_status(_config.auth.sqlite_path, user_id, is_active)
        return Response(status_code=200)
    except Exception as e:
        logger.error(f"Failed to update user status: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_make_superuser(request: Request) -> Response:
    """Make user a superuser."""
    if _config is None:
        return JSONResponse({"error": "Config not initialized"}, status_code=500)

    try:
        user_id = int(request.path_params["user_id"])
        make_user_superuser(_config.auth.sqlite_path, user_id)
        return Response(status_code=200)
    except Exception as e:
        logger.error(f"Failed to make superuser: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def admin_settings(_: Request) -> HTMLResponse:
    """Admin settings page."""
    sidebar_nav = _get_sidebar_nav("settings")
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - MCP Auth Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
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
        .settings-card {
            border: none;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 1.5rem;
        }
        .settings-card .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-2 d-md-block sidebar p-3">
                <div class="text-center mb-4">
                    <h4 class="text-white"><i class="bi bi-shield-lock"></i> MCP Auth</h4>
                    <small class="text-white-50">Admin Panel</small>
                </div>
                <ul class="nav flex-column">
{SIDEBAR_NAV}
                </ul>
            </nav>

            <!-- Main content -->
            <main class="col-md-10 ms-sm-auto px-md-4 py-4">
                <h1 class="mb-4"><i class="bi bi-gear"></i> Settings</h1>

                <div id="successAlert" class="alert alert-success d-none" role="alert">
                    <i class="bi bi-check-circle"></i> Settings saved successfully!
                </div>

                <div id="errorAlert" class="alert alert-danger d-none" role="alert">
                    <i class="bi bi-exclamation-triangle"></i>
                    <span id="errorMessage"></span>
                </div>

                <!-- JWT Token Settings -->
                <div class="settings-card card">
                    <div class="card-header">
                        <i class="bi bi-key"></i> JWT Token Settings
                    </div>
                    <div class="card-body">
                        <form id="jwtSettingsForm">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Access Token Lifetime (minutes)</label>
                                    <input type="number" class="form-control" id="accessTokenTTL" 
                                           min="1" max="525600" required>
                                    <small class="text-muted">
                                        Recommended: 1440 (24 hours), 10080 (7 days), 43200 (30 days)
                                    </small>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Refresh Token Lifetime (days)</label>
                                    <input type="number" class="form-control" id="refreshTokenTTL" 
                                           min="1" max="365" required>
                                    <small class="text-muted">
                                        Recommended: 7, 30, or 90 days
                                    </small>
                                </div>
                            </div>
                            <div class="alert alert-info">
                                <i class="bi bi-info-circle"></i>
                                <strong>Note:</strong> For Claude Desktop MCP, longer access token lifetimes (24h - 7d) are recommended 
                                since token auto-refresh is not yet supported by MCP clients.
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Password Policy -->
                <div class="settings-card card">
                    <div class="card-header">
                        <i class="bi bi-shield-check"></i> Password Policy
                    </div>
                    <div class="card-body">
                        <form id="passwordPolicyForm">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Minimum Length</label>
                                    <input type="number" class="form-control" id="passwordMinLength" 
                                           min="4" max="128" required>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-3 mb-3">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="requireUppercase">
                                        <label class="form-check-label" for="requireUppercase">
                                            Require Uppercase
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-3 mb-3">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="requireLowercase">
                                        <label class="form-check-label" for="requireLowercase">
                                            Require Lowercase
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-3 mb-3">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="requireDigit">
                                        <label class="form-check-label" for="requireDigit">
                                            Require Digit
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-3 mb-3">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="requireSpecial">
                                        <label class="form-check-label" for="requireSpecial">
                                            Require Special Char
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- System Settings -->
                <div class="settings-card card">
                    <div class="card-header">
                        <i class="bi bi-sliders"></i> System Settings
                    </div>
                    <div class="card-body">
                        <form id="systemSettingsForm">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <div class="form-check form-switch">
                                        <input type="checkbox" class="form-check-input" id="allowRegistration">
                                        <label class="form-check-label" for="allowRegistration">
                                            Allow User Registration
                                        </label>
                                        <small class="d-block text-muted">
                                            Allow new users to register via /auth/register endpoint
                                        </small>
                                    </div>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <div class="form-check form-switch">
                                        <input type="checkbox" class="form-check-input" id="authRequired">
                                        <label class="form-check-label" for="authRequired">
                                            Authentication Required
                                        </label>
                                        <small class="d-block text-muted">
                                            Require authentication for MCP endpoints
                                        </small>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Save Button -->
                <div class="text-end">
                    <button type="button" class="btn btn-lg btn-primary" onclick="saveSettings()">
                        <i class="bi bi-save"></i> Save All Settings
                    </button>
                </div>
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', loadSettings);

        async function loadSettings() {
            try {
                const response = await fetch('/admin/api/settings');
                const settings = await response.json();

                // JWT Settings
                document.getElementById('accessTokenTTL').value = settings.jwt.access_token_expire_minutes;
                document.getElementById('refreshTokenTTL').value = settings.jwt.refresh_token_expire_days;

                // Password Policy
                document.getElementById('passwordMinLength').value = settings.password_policy.min_length;
                document.getElementById('requireUppercase').checked = settings.password_policy.require_uppercase;
                document.getElementById('requireLowercase').checked = settings.password_policy.require_lowercase;
                document.getElementById('requireDigit').checked = settings.password_policy.require_digit;
                document.getElementById('requireSpecial').checked = settings.password_policy.require_special;

                // System Settings
                document.getElementById('allowRegistration').checked = settings.system.allow_registration;
                document.getElementById('authRequired').checked = settings.system.auth_required;
            } catch (error) {
                console.error('Failed to load settings:', error);
                showError('Failed to load settings');
            }
        }

        async function saveSettings() {
            const settings = {
                jwt: {
                    access_token_expire_minutes: parseInt(document.getElementById('accessTokenTTL').value),
                    refresh_token_expire_days: parseInt(document.getElementById('refreshTokenTTL').value)
                },
                password_policy: {
                    min_length: parseInt(document.getElementById('passwordMinLength').value),
                    require_uppercase: document.getElementById('requireUppercase').checked,
                    require_lowercase: document.getElementById('requireLowercase').checked,
                    require_digit: document.getElementById('requireDigit').checked,
                    require_special: document.getElementById('requireSpecial').checked
                },
                system: {
                    allow_registration: document.getElementById('allowRegistration').checked,
                    auth_required: document.getElementById('authRequired').checked
                }
            };

            try {
                const response = await fetch('/admin/api/settings', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(settings)
                });

                if (response.ok) {
                    showSuccess();
                } else {
                    const error = await response.json();
                    showError(error.detail || 'Failed to save settings');
                }
            } catch (error) {
                showError('Network error: ' + error.message);
            }
        }

        function showSuccess() {
            document.getElementById('errorAlert').classList.add('d-none');
            document.getElementById('successAlert').classList.remove('d-none');
            setTimeout(() => {
                document.getElementById('successAlert').classList.add('d-none');
            }, 3000);
        }

        function showError(message) {
            document.getElementById('errorMessage').textContent = message;
            document.getElementById('successAlert').classList.add('d-none');
            document.getElementById('errorAlert').classList.remove('d-none');
        }
    </script>
</body>
</html>
    """
    html = html.replace("{SIDEBAR_NAV}", sidebar_nav)
    return HTMLResponse(content=html)


async def api_get_settings(_: Request) -> JSONResponse:
    """Get current settings."""
    try:
        from src.settings_manager import get_settings_manager
        settings_manager = get_settings_manager()
        return JSONResponse(settings_manager.get_all())
    except Exception as e:
        logger.error(f"Failed to get settings: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_save_settings(request: Request) -> JSONResponse:
    """Save settings."""
    try:
        from src.settings_manager import get_settings_manager
        settings_manager = get_settings_manager()
        
        body = await request.json()
        settings_manager.update(body)
        settings_manager.save()
        
        return JSONResponse({"success": True, "message": "Settings saved successfully"})
    except Exception as e:
        logger.error(f"Failed to save settings: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================================
# MCP SERVERS MANAGEMENT
# ============================================================================

async def admin_mcp_servers(_: Request) -> HTMLResponse:
    """MCP servers management page."""
    sidebar_nav = _get_sidebar_nav("mcp-servers")
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MCP Servers - Admin Panel</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
        <style>
            body { background-color: #f8f9fa; }
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
            }
            .server-card {
                border-left: 4px solid #dee2e6;
                transition: all 0.3s;
            }
            .server-card:hover {
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
            .server-card.online { border-left-color: #28a745; }
            .server-card.offline { border-left-color: #dc3545; }
            .server-card.error { border-left-color: #ffc107; }
            .tool-badge {
                font-size: 0.85rem;
                padding: 0.25rem 0.5rem;
                margin: 0.15rem;
                display: inline-block;
            }
            .modal-backdrop.show { opacity: 0.5; }
        </style>
    </head>
    <body>
        <div class="container-fluid">
            <div class="row">
                <nav class="col-md-2 d-md-block sidebar p-3">
                    <div class="text-center mb-4">
                        <h4 class="text-white">
                            <i class="bi bi-shield-lock"></i> Admin Panel
                        </h4>
                    </div>
                    <ul class="nav flex-column">
{SIDEBAR_NAV}
                    </ul>
                </nav>

                <main class="col-md-10 ms-sm-auto px-4 py-4">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h1><i class="bi bi-hdd-network"></i> MCP Servers</h1>
                        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addServerModal">
                            <i class="bi bi-plus-circle"></i> Add New Server
                        </button>
                    </div>

                    <!-- Stats Cards -->
                    <div class="row mb-4">
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h6 class="text-muted">Total Servers</h6>
                                    <h2 class="mb-0"><span id="totalServers">-</span></h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h6 class="text-muted">Online</h6>
                                    <h2 class="mb-0 text-success"><span id="onlineServers">-</span></h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h6 class="text-muted">Total Tools</h6>
                                    <h2 class="mb-0"><span id="totalTools">-</span></h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body">
                                    <h6 class="text-muted">Last Check</h6>
                                    <h2 class="mb-0"><small><span id="lastCheck">-</span></small></h2>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Servers List -->
                    <div id="serversList"></div>

                    <!-- Add Server Modal -->
                    <div class="modal fade" id="addServerModal" tabindex="-1">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title">Add MCP Server</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                </div>
                                <div class="modal-body">
                                    <form id="addServerForm">
                                        <div class="mb-3">
                                            <label class="form-label">Server Name *</label>
                                            <input type="text" class="form-control" id="serverName" required>
                                            <small class="text-muted">Unique name for this MCP server</small>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Description</label>
                                            <input type="text" class="form-control" id="serverDescription">
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">URL *</label>
                                            <input type="url" class="form-control" id="serverUrl" required 
                                                   placeholder="http://mcp-server:8000/mcp">
                                            <small class="text-muted">Backend MCP server endpoint</small>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Tool Prefix</label>
                                            <input type="text" class="form-control" id="serverPrefix" 
                                                   placeholder="e.g., rag_, ha_">
                                            <small class="text-muted">Optional prefix for routing (e.g., "rag_")</small>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Routing Strategy</label>
                                            <select class="form-select" id="routingStrategy">
                                                <option value="prefix" selected>Prefix</option>
                                                <option value="explicit">Explicit Mapping</option>
                                                <option value="auto">Auto-discovery</option>
                                            </select>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Auth Type</label>
                                            <select class="form-select" id="authType">
                                                <option value="none" selected>None</option>
                                                <option value="bearer">Bearer Token</option>
                                                <option value="basic">Basic Auth</option>
                                            </select>
                                        </div>
                                        <div class="mb-3" id="authTokenGroup" style="display:none;">
                                            <label class="form-label">Auth Token</label>
                                            <input type="text" class="form-control" id="authToken">
                                        </div>
                                        <div class="form-check mb-3">
                                            <input class="form-check-input" type="checkbox" id="enabled" checked>
                                            <label class="form-check-label" for="enabled">
                                                Enable immediately
                                            </label>
                                        </div>
                                    </form>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="button" class="btn btn-primary" onclick="saveServer()">
                                        <i class="bi bi-check-circle"></i> Save Server
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            // Show/hide auth token field based on auth type
            document.getElementById('authType').addEventListener('change', function() {
                const authTokenGroup = document.getElementById('authTokenGroup');
                authTokenGroup.style.display = this.value !== 'none' ? 'block' : 'none';
            });

            // Load servers on page load
            document.addEventListener('DOMContentLoaded', loadServers);

            async function loadServers() {
                try {
                    const response = await fetch('/admin/api/mcp-servers');
                    const data = await response.json();

                    // Update stats
                    document.getElementById('totalServers').textContent = data.servers.length;
                    document.getElementById('onlineServers').textContent = 
                        data.servers.filter(s => s.status === 'online').length;
                    document.getElementById('totalTools').textContent = 
                        data.servers.reduce((sum, s) => sum + s.tools_count, 0);
                    document.getElementById('lastCheck').textContent = 
                        new Date().toLocaleTimeString();

                    // Render servers
                    renderServers(data.servers);
                } catch (error) {
                    console.error('Failed to load servers:', error);
                    document.getElementById('serversList').innerHTML = 
                        '<div class="alert alert-danger">Failed to load servers</div>';
                }
            }

            function renderServers(servers) {
                const container = document.getElementById('serversList');
                
                if (servers.length === 0) {
                    container.innerHTML = `
                        <div class="alert alert-info">
                            <i class="bi bi-info-circle"></i> No MCP servers added yet. 
                            Click "Add New Server" to get started!
                        </div>
                    `;
                    return;
                }

                container.innerHTML = servers.map(server => `
                    <div class="card server-card ${server.status} mb-3">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start">
                                <div class="flex-grow-1">
                                    <h5 class="card-title">
                                        ${getStatusIcon(server.status)} ${server.name}
                                        ${server.enabled ? '' : '<span class="badge bg-secondary">Disabled</span>'}
                                    </h5>
                                    <p class="text-muted mb-2">${server.description || ''}</p>
                                    <p class="mb-1"><small class="text-muted"><i class="bi bi-link"></i> ${server.url}</small></p>
                                    ${server.tool_prefix ? `<p class="mb-1"><small class="text-muted"><i class="bi bi-tag"></i> Prefix: <code>${server.tool_prefix}</code></small></p>` : ''}
                                    
                                    <div class="mt-2">
                                        <span class="badge bg-${getStatusColor(server.status)}">${server.status}</span>
                                        <span class="badge bg-info">${server.tools_count} tools</span>
                                        ${server.last_health_check ? 
                                            `<small class="text-muted ms-2">Last check: ${formatTime(server.last_health_check)}</small>` 
                                            : ''}
                                    </div>

                                    ${server.last_error ? `
                                        <div class="alert alert-warning mt-2 mb-0">
                                            <small><i class="bi bi-exclamation-triangle"></i> ${server.last_error}</small>
                                        </div>
                                    ` : ''}

                                    <!-- Tools List (collapsible) -->
                                    <div class="mt-3">
                                        <button class="btn btn-sm btn-outline-secondary" type="button" 
                                                data-bs-toggle="collapse" data-bs-target="#tools-${server.id}">
                                            <i class="bi bi-tools"></i> Show Tools (${server.tools_count})
                                        </button>
                                        <div class="collapse mt-2" id="tools-${server.id}">
                                            <div id="tools-list-${server.id}">
                                                <small class="text-muted">Loading tools...</small>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="btn-group-vertical">
                                    <button class="btn btn-sm btn-outline-primary" onclick="testServer(${server.id})">
                                        <i class="bi bi-activity"></i> Test
                                    </button>
                                    <button class="btn btn-sm btn-outline-warning" onclick="editServer(${server.id})">
                                        <i class="bi bi-pencil"></i> Edit
                                    </button>
                                    <button class="btn btn-sm btn-outline-danger" onclick="deleteServer(${server.id}, '${server.name}')">
                                        <i class="bi bi-trash"></i> Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('');

                // Load tools for each server when expanded
                servers.forEach(server => {
                    document.getElementById(`tools-${server.id}`).addEventListener('shown.bs.collapse', () => {
                        loadServerTools(server.id);
                    });
                });
            }

            async function loadServerTools(serverId) {
                try {
                    const response = await fetch(`/admin/api/mcp-servers/${serverId}/tools`);
                    const tools = await response.json();
                    
                    const container = document.getElementById(`tools-list-${serverId}`);
                    if (tools.length === 0) {
                        container.innerHTML = '<small class="text-muted">No tools available</small>';
                    } else {
                        container.innerHTML = tools.map(tool => 
                            `<span class="badge tool-badge bg-light text-dark">${tool}</span>`
                        ).join('');
                    }
                } catch (error) {
                    console.error('Failed to load tools:', error);
                    document.getElementById(`tools-list-${serverId}`).innerHTML = 
                        '<small class="text-danger">Failed to load tools</small>';
                }
            }

            function getStatusIcon(status) {
                const icons = {
                    'online': '<i class="bi bi-check-circle-fill text-success"></i>',
                    'offline': '<i class="bi bi-x-circle-fill text-danger"></i>',
                    'error': '<i class="bi bi-exclamation-triangle-fill text-warning"></i>',
                    'unknown': '<i class="bi bi-question-circle text-secondary"></i>'
                };
                return icons[status] || icons.unknown;
            }

            function getStatusColor(status) {
                const colors = {
                    'online': 'success',
                    'offline': 'danger',
                    'error': 'warning',
                    'unknown': 'secondary'
                };
                return colors[status] || 'secondary';
            }

            function formatTime(timestamp) {
                const date = new Date(timestamp);
                const now = new Date();
                const seconds = Math.floor((now - date) / 1000);
                
                if (seconds < 60) return `${seconds}s ago`;
                if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
                if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
                return date.toLocaleString();
            }

            async function saveServer() {
                const data = {
                    name: document.getElementById('serverName').value,
                    description: document.getElementById('serverDescription').value,
                    url: document.getElementById('serverUrl').value,
                    tool_prefix: document.getElementById('serverPrefix').value,
                    routing_strategy: document.getElementById('routingStrategy').value,
                    auth_type: document.getElementById('authType').value,
                    auth_token: document.getElementById('authToken').value,
                    enabled: document.getElementById('enabled').checked
                };

                try {
                    const response = await fetch('/admin/api/mcp-servers', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(data)
                    });

                    if (response.ok) {
                        bootstrap.Modal.getInstance(document.getElementById('addServerModal')).hide();
                        document.getElementById('addServerForm').reset();
                        loadServers();
                        alert('Server added successfully!');
                    } else {
                        const error = await response.json();
                        alert(`Failed to add server: ${error.detail || 'Unknown error'}`);
                    }
                } catch (error) {
                    console.error('Error saving server:', error);
                    alert('Failed to save server');
                }
            }

            async function testServer(serverId) {
                try {
                    const response = await fetch(`/admin/api/mcp-servers/${serverId}/test`, {
                        method: 'POST'
                    });
                    const result = await response.json();
                    
                    if (result.status === 'online') {
                        alert(`✓ Server is online\\nResponse time: ${result.response_time_ms}ms\\nTools: ${result.tools_count}`);
                    } else {
                        alert(`✗ Server test failed\\nStatus: ${result.status}\\nError: ${result.error || 'Unknown'}`);
                    }
                    
                    loadServers(); // Refresh list
                } catch (error) {
                    alert('Failed to test server: ' + error);
                }
            }

            async function deleteServer(serverId, serverName) {
                if (!confirm(`Are you sure you want to delete "${serverName}"?`)) {
                    return;
                }

                try {
                    const response = await fetch(`/admin/api/mcp-servers/${serverId}`, {
                        method: 'DELETE'
                    });

                    if (response.ok) {
                        loadServers();
                        alert('Server deleted successfully');
                    } else {
                        alert('Failed to delete server');
                    }
                } catch (error) {
                    alert('Error deleting server: ' + error);
                }
            }

            function editServer(serverId) {
                alert('Edit functionality coming soon!');
            }
        </script>
    </body>
    </html>
    """
    html = html.replace("{SIDEBAR_NAV}", sidebar_nav)
    return HTMLResponse(html)


# MCP Servers API Endpoints

async def api_list_mcp_servers(_: Request) -> JSONResponse:
    """API: List all MCP servers."""
    try:
        from src.mcp.store import list_mcp_servers
        
        servers = list_mcp_servers(_config.auth.sqlite_path)
        
        return JSONResponse({"servers": servers})
    except Exception as e:
        logger.error(f"Failed to list MCP servers: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_create_mcp_server(request: Request) -> JSONResponse:
    """API: Create new MCP server."""
    try:
        from src.mcp.store import create_mcp_server
        
        data = await request.json()
        
        server_id = create_mcp_server(
            db_path=_config.auth.sqlite_path,
            name=data["name"],
            url=data["url"],
            description=data.get("description"),
            tool_prefix=data.get("tool_prefix"),
            enabled=data.get("enabled", True),
            auth_type=data.get("auth_type", "none"),
            auth_token=data.get("auth_token"),
            routing_strategy=data.get("routing_strategy", "prefix")
        )
        
        # Trigger health check for new server
        from src.mcp.health import get_health_checker
        try:
            health_checker = get_health_checker()
            from src.mcp.store import get_mcp_server
            server = get_mcp_server(_config.auth.sqlite_path, server_id)
            if server:
                await health_checker.check_server(server)
        except:
            pass  # Health checker might not be initialized yet
        
        return JSONResponse({"id": server_id, "message": "Server created successfully"})
    except Exception as e:
        logger.error(f"Failed to create MCP server: {e}")
        return JSONResponse({"detail": str(e)}, status_code=400)


async def api_delete_mcp_server(request: Request) -> JSONResponse:
    """API: Delete MCP server."""
    try:
        from src.mcp.store import delete_mcp_server
        
        server_id = int(request.path_params["server_id"])
        
        success = delete_mcp_server(_config.auth.sqlite_path, server_id)
        
        if success:
            # Invalidate cache
            from src.mcp.proxy import McpProxy
            proxy = McpProxy(_config.auth.sqlite_path)
            proxy.invalidate_cache(server_id)
            
            return JSONResponse({"message": "Server deleted successfully"})
        else:
            return JSONResponse({"error": "Server not found"}, status_code=404)
    except Exception as e:
        logger.error(f"Failed to delete MCP server: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_test_mcp_server(request: Request) -> JSONResponse:
    """API: Test MCP server connection."""
    try:
        from src.mcp.health import HealthChecker
        from src.mcp.store import get_mcp_server
        
        server_id = int(request.path_params["server_id"])
        server = get_mcp_server(_config.auth.sqlite_path, server_id)
        
        if not server:
            return JSONResponse({"error": "Server not found"}, status_code=404)
        
        # Perform health check
        health_checker = HealthChecker(_config.auth.sqlite_path)
        result = await health_checker.check_server(server)

        # Convert datetime to ISO string for JSON serialization
        if 'checked_at' in result and result['checked_at']:
            result['checked_at'] = result['checked_at'].isoformat()

        return JSONResponse(result)
    except Exception as e:
        logger.error(f"Failed to test MCP server: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_get_mcp_server_tools(request: Request) -> JSONResponse:
    """API: Get tools from MCP server."""
    try:
        from src.mcp.proxy import McpProxy
        from src.mcp.store import get_mcp_server
        
        server_id = int(request.path_params["server_id"])
        server = get_mcp_server(_config.auth.sqlite_path, server_id)
        
        if not server:
            return JSONResponse({"error": "Server not found"}, status_code=404)
        
        # Fetch tools from server
        proxy = McpProxy(_config.auth.sqlite_path)
        tools = await proxy._fetch_tools_from_server(server)
        
        # Extract tool names
        tool_names = [tool.get("name") for tool in tools if "name" in tool]
        
        return JSONResponse(tool_names)
    except Exception as e:
        logger.error(f"Failed to get server tools: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)
