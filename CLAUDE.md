# AuthMCP Gateway

**Secure authentication proxy for Model Context Protocol (MCP) servers**

## Project Overview

AuthMCP Gateway provides centralized authentication, authorization, and monitoring for MCP servers. It acts as a secure proxy between clients and your MCP backends, adding JWT-based authentication, rate limiting, real-time monitoring, and comprehensive security logging.

Features:
- OAuth 2.0 + JWT authentication with refresh tokens
- Dynamic Client Registration (DCR) for MCP clients
- Rate limiting and security event logging
- Real-time MCP activity monitoring
- Admin dashboard with user/server management
- MCP security vulnerability auditing

## Technology Stack

- **Runtime**: Python 3.11+
- **Web Framework**: Starlette (lightweight ASGI)
- **Authentication**: OAuth 2.0, JWT (HS256/RS256)
- **Database**: SQLite (local)
- **HTTP Client**: httpx (async)
- **Templating**: Jinja2 (admin dashboard)
- **Container**: Docker + Docker Compose

## Project Structure

```
authmcp-gateway/
├── src/authmcp_gateway/
│   ├── auth/                    # OAuth2 + JWT authentication
│   │   ├── endpoints.py         # /auth/login, /auth/register, /oauth/token
│   │   ├── jwt_handler.py       # JWT token creation/verification
│   │   ├── user_store.py        # SQLite user database
│   │   ├── password.py          # Password hashing & validation
│   │   ├── oauth_code_flow.py   # Authorization code flow with PKCE
│   │   ├── client_store.py      # OAuth2 client storage
│   │   ├── authorize_endpoint.py # OAuth consent page
│   │   ├── dcr_endpoints.py     # Dynamic Client Registration (RFC 7591)
│   │   ├── token_service.py     # Token utilities
│   │   └── models.py            # Pydantic schemas
│   │
│   ├── mcp/                     # MCP Gateway proxy & routing
│   │   ├── handler.py           # MCP JSON-RPC dispatcher (tools/list, tools/call)
│   │   ├── proxy.py             # Route requests to backend servers
│   │   ├── store.py             # MCP server database & tool mappings
│   │   ├── health.py            # Periodic backend health checks
│   │   ├── token_manager.py     # OAuth2 token refresh orchestration
│   │   ├── token_refresher.py   # Background token refresh daemon
│   │   ├── sse_handler.py       # Server-Sent Events transport
│   │   └── models.py            # Pydantic models
│   │
│   ├── admin/                   # Admin dashboard & API
│   │   ├── routes.py            # Admin endpoints (users, servers, tokens, logs)
│   │   └── login.py             # Admin authentication
│   │
│   ├── security/                # Security features
│   │   ├── logger.py            # Security event logging
│   │   └── mcp_auditor.py       # MCP vulnerability scanner
│   │
│   ├── middleware.py            # HTTP middleware (auth, CORS, rate limiting)
│   ├── admin_auth.py            # Admin route protection
│   ├── app.py                   # Main Starlette application
│   ├── config.py                # Configuration management
│   ├── cli.py                   # CLI entry point (authmcp-gateway command)
│   ├── rate_limiter.py          # Fixed-window rate limiting
│   ├── settings_manager.py      # Dynamic settings with hot-reload
│   ├── logging_config.py        # Logging configuration
│   ├── setup_wizard.py          # First-run setup wizard
│   └── utils.py                 # Utility functions
│
├── templates/                   # Jinja2 HTML templates
│   ├── user_login.html          # User login page
│   ├── user_portal.html         # User token management
│   └── admin/                   # Admin dashboard templates
│       ├── base.html            # Base layout
│       ├── dashboard.html       # Overview & stats
│       ├── users.html           # User management
│       ├── mcp_servers.html     # Server management
│       ├── mcp_tokens.html      # Token status
│       ├── mcp_activity.html    # Live request monitoring
│       ├── mcp_audit.html       # Security audit interface
│       ├── oauth_clients.html   # DCR client management
│       ├── security_logs.html   # Security events
│       ├── settings.html        # System settings
│       ├── logs.html            # Application logs
│       └── api_test.html        # API testing interface
│
├── tests/                       # Test suite (pytest)
│   ├── test_log_cleanup.py
│   ├── test_mcp_logging.py
│   └── test_token_manager.py
│
├── scripts/                     # Utility scripts
│   ├── test_mcp_security.py     # Security testing
│   ├── codex_refresh_mcp.py     # Codex token refresh helper
│   └── migrate_add_refresh_tokens.py
│
├── docs/                        # Documentation
│   └── (screenshots, guides)
│
├── docker-compose.yml           # Production compose
├── Dockerfile                   # Container image
├── pyproject.toml               # Python project config
├── requirements.txt             # Dependencies
├── .env.example                 # Environment variables template
├── .gitignore
├── README.md                    # Project README
├── CLAUDE.md                    # This file
└── AUDIT_REPORT.md              # Code audit findings
```

## Development Workflow

### 1. Initial Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # or: venv\Scripts\activate on Windows

# Install in development mode
pip install -e .

# Verify installation
authmcp-gateway --version
```

### 2. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env if needed (optional - defaults work for dev)
# vim .env

# Run server
authmcp-gateway start
```

The server will:
- Auto-create `.env` with JWT_SECRET_KEY if missing
- Initialize SQLite database at `data/users.db`
- Open setup wizard at `http://localhost:8000/setup`

### 3. First Time Setup

1. Open http://localhost:8000/ in browser
2. Complete setup wizard to create admin user
3. Login to admin dashboard at http://localhost:8000/admin/
4. Add MCP backend servers

### 4. Development Commands

```bash
# Start server (auto-reload on code changes)
authmcp-gateway start

# Start on custom port
authmcp-gateway start --port 9000

# Bind to localhost only
authmcp-gateway start --host 127.0.0.1

# Use custom .env file
authmcp-gateway start --env-file custom.env

# Create admin user via CLI
authmcp-gateway create-admin

# Initialize database
authmcp-gateway init-db

# Show version
authmcp-gateway version

# Show help
authmcp-gateway --help
```

## API Endpoints

### Authentication (Public)

- `POST /auth/login` - User login with credentials
- `POST /auth/register` - User registration (if enabled)
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout and blacklist token
- `GET /auth/me` - Get current user info
- `POST /oauth/token` - OAuth2 token endpoint
- `POST /oauth/register` - Dynamic Client Registration
- `GET /.well-known/oauth-authorization-server` - OAuth discovery

### MCP Gateway (Protected)

- `POST /mcp` - MCP JSON-RPC endpoint (all servers)
- `POST /mcp/{server_name}` - MCP endpoint for specific server
- `GET /mcp` - MCP streamable endpoint (SSE)

### Admin Dashboard (Protected)

- `GET /admin/` - Dashboard overview
- `GET/POST /admin/api/users` - User management
- `GET/POST /admin/api/mcp-servers` - Server management
- `POST /admin/api/mcp-servers/{id}/refresh-token` - Refresh backend token
- `GET /admin/api/security-logs` - Security events
- `GET /admin/mcp-activity` - Live request monitoring
- `GET /admin/api/settings` - System settings

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_ALGORITHM=HS256                           # or RS256
JWT_SECRET_KEY=your-secret-key-min-32-chars
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30            # Access token TTL
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7               # Refresh token TTL

# Gateway Settings
GATEWAY_PORT=9105                             # Docker port (container: 8000)
MCP_PUBLIC_URL=https://mcp.yourdomain.com    # Public HTTPS URL (for Claude.ai)
AUTH_REQUIRED=true                            # Enforce authentication
ALLOW_INSECURE_HTTP=false                     # Block HTTP (dev only)

# Database
AUTH_SQLITE_PATH=/app/data/users.db          # SQLite location

# User Management
ALLOW_REGISTRATION=false                      # Enable user self-registration

# Password Policy
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true

# CORS
ALLOWED_ORIGINS=https://mcp.yourdomain.com,http://localhost:8000

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_LOGIN_MAX=5
RATE_LIMIT_LOGIN_WINDOW=60
RATE_LIMIT_REGISTER_MAX=3
RATE_LIMIT_REGISTER_WINDOW=300

# Logging
LOG_LEVEL=INFO
MCP_LOG_DB_ENABLED=true
```

See `.env.example` for complete list.

## Code Standards

### Python Style

- **Version**: Python 3.11+
- **Formatter**: `black` (line length 100)
- **Imports**: `isort` with black profile
- **Type Hints**: Required for public functions
- **Docstrings**: Google-style for public functions/classes
- **Async**: Use async/await patterns

Example:

```python
from typing import Optional
import logging

logger = logging.getLogger(__name__)


async def refresh_token(
    server_id: int,
    client_id: str,
    client_secret: str
) -> Optional[str]:
    """Refresh OAuth2 token for backend MCP server.

    Args:
        server_id: ID of the MCP server to refresh token for
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret

    Returns:
        New access token if successful, None if refresh failed

    Raises:
        ServerNotFoundError: If server_id doesn't exist
        TokenRefreshError: If OAuth2 server unreachable
    """
    logger.info(f"Refreshing token for server {server_id}")

    try:
        # Implementation
        pass
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise
```

### Pre-commit Checklist

Before each commit:

- [ ] Code formatted: `black src/ tests/`
- [ ] Imports sorted: `isort src/ tests/`
- [ ] Type hints present on public functions
- [ ] No hardcoded secrets or credentials
- [ ] No `print()` statements (use `logger`)
- [ ] Tests pass: `pytest tests/`
- [ ] Coverage check: `pytest --cov=src/authmcp_gateway`
- [ ] Docstrings added/updated
- [ ] No TODO/FIXME without GitHub issue number

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest tests/ --cov=src/authmcp_gateway --cov-report=html

# Run specific test
pytest tests/test_token_manager.py -v

# Run tests matching pattern
pytest tests/ -k "token" -v

# Failed tests only (from last run)
pytest tests/ --lf
```

### Test Structure

Tests use `pytest` with `pytest-asyncio` for async support:

```python
import pytest
from authmcp_gateway.auth.jwt_handler import JWTHandler


@pytest.fixture
def jwt_handler():
    """Fixture providing JWT handler instance."""
    return JWTHandler(secret_key="test-secret-key")


def test_token_creation(jwt_handler):
    """Test JWT token creation."""
    token = jwt_handler.create_access_token(
        subject="test_user",
        expires_in_minutes=30
    )

    assert token is not None
    assert len(token) > 0


@pytest.mark.asyncio
async def test_async_operation():
    """Test async operations."""
    # Test code
    pass
```

## Docker

### Development

```bash
docker-compose -f docker-compose.dev.yml up -d
docker-compose logs -f
docker-compose down -v  # Remove volumes
```

### Production

```bash
docker-compose up -d
docker-compose logs -f authmcp-gateway
docker-compose exec authmcp-gateway authmcp-gateway create-admin  # Create admin user
```

## Architecture Overview

```
┌──────────────────────────────────────────┐
│        Client (Claude, Codex, etc.)      │
│     Sends: Authorization: Bearer JWT     │
└──────────────┬───────────────────────────┘
               │
       ┌───────▼────────────────────────┐
       │    AuthMCP Gateway             │
       │                                │
       │ 1. Validate JWT token          │
       │ 2. Check user permissions      │
       │ 3. Rate limit check            │
       │ 4. Log security events         │
       │ 5. Route to backend            │
       └───────┬────────────────────────┘
               │
    ┌──────────┼──────────┬──────────┐
    ▼          ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌─────────┐
│GitHub  │ │  RAG   │ │Custom  │ │Backend  │
│ MCP    │ │ MCP    │ │ MCP    │ │ MCP     │
└────────┘ └────────┘ └────────┘ └─────────┘
```

## Known Issues & Future Work

### Current Limitations (See AUDIT_REPORT.md)

- [ ] Test coverage: 6% → target 50%+
- [ ] Global state injection → needs refactor to DI
- [ ] Admin routes monolithic (1500+ lines)
- [ ] No input validation on OAuth scopes
- [ ] Backend tokens in plaintext memory
- [ ] No rate limiting on `/mcp` endpoint

### Planned Improvements

- [ ] Refactor global state to dependency injection
- [ ] Expand test suite to 50%+ coverage
- [ ] Split monolithic route files
- [ ] Add input validation framework
- [ ] Encrypt backend token storage
- [ ] Add comprehensive audit logging
- [ ] OpenAPI/Swagger schema generation

## Common Issues & Troubleshooting

**Setup wizard not appearing**:
- Ensure cookies are enabled
- Check browser console for errors
- Verify JWT_SECRET_KEY is set

**MCP server shows offline**:
- Check server URL is correct and reachable
- Verify backend token if required
- Check firewall/network access

**401 Unauthorized errors**:
- Token may have expired → use refresh token
- Verify Authorization header: `Bearer TOKEN`
- Check user permissions for server

**Port already in use**:
```bash
# Find process using port 8000
lsof -i :8000
# Kill process or use different port
authmcp-gateway start --port 9000
```

## Resources

- [MCP Specification](https://modelcontextprotocol.io)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [Starlette Documentation](https://www.starlette.io/)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)

## Contact & Support

- Report issues: GitHub Issues
- See AUDIT_REPORT.md for detailed code analysis
- See README.md for user documentation

---

**Version**: 1.1.0
**Status**: Beta / Production-Ready with Caveats
**Last Updated**: February 15, 2026
