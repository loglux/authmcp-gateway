# AuthMCP Gateway - Audit Report

**Date**: February 15, 2026
**Version**: 1.0.22
**Auditor**: Claude Opus 4.6 (independent code review)

---

## Summary

AuthMCP Gateway - authentication proxy for MCP servers. Codebase: ~12,300 lines Python, ~4,600 lines HTML templates, 3 теста (6% покрытие).

| Category | Rating | Details |
|----------|--------|---------|
| Security | MEDIUM | Crypto and auth solid, but XSS risk in templates, no rate limit on /mcp |
| Code Quality | MEDIUM | Good type hints (~85%), docstrings (~80%), but monolithic files |
| Architecture | ACCEPTABLE | Global state at startup is a known trade-off, no circular imports |
| Testing | CRITICAL | 3 tests, 6% coverage, no integration tests |
| Deployment | GOOD | Docker-ready, CLI tool, health checks, env config |

---

## 1. Security

### 1.1 XSS Risk: Jinja2 autoescape disabled

**Severity**: HIGH

```python
# admin/routes.py:36
jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
```

Jinja2 `Environment` by default has `autoescape=False`. All admin templates render user-controlled data (usernames, server names, error messages) without automatic HTML escaping. Any stored XSS in username/server name will execute in admin panel.

**Fix**: `Environment(loader=..., autoescape=True)`

### 1.2 No rate limiting on /mcp endpoint

**Severity**: MEDIUM

Rate limiting works on `/auth/login`, `/auth/register`, `/oauth/register` (DCR), and `/admin/login`. But the main `/mcp` endpoint has no rate limits. An authenticated user can flood backend MCP servers with unlimited requests.

**Fix**: Add per-user rate limit on `/mcp` (e.g., 100 req/min).

### 1.3 Scope injection in WWW-Authenticate header

**Severity**: LOW

```python
# middleware.py:81
www_auth += f', scope="{scopes}"'
```

The `scopes` value comes from JWT payload (`token_payload.get("scope")`), not directly from user input. Exploitation requires forging a JWT with malicious scope values, which already requires the signing key. Real risk is negligible.

### 1.4 Dynamic SQL with f-strings

**Severity**: LOW (not actual injection)

4 locations use f-strings in SQL, but all for **structure** (table/column names), not values:

| File | Line | Pattern | Risk |
|------|------|---------|------|
| `security/logger.py` | 242 | `f"SELECT * FROM {table_name}"` | table_name is hardcoded internal string |
| `mcp/store.py` | 281 | `f"UPDATE ... SET {set_clause} WHERE id = ?"` | keys from dict, values parameterized |
| `client_store.py` | 67 | `f"ALTER TABLE ... ADD COLUMN {col} {col_type}"` | col/type from hardcoded tuple |
| `admin/routes.py` | 683 | `f"SELECT COUNT(*) FROM auth_audit_log {where_sql}"` | where_sql uses `?` params |

All user-provided values are properly parameterized with `?`. No real SQL injection vector found.

### 1.5 Backend tokens in memory

**Severity**: LOW-MEDIUM

```python
# mcp/token_manager.py
self._refresh_tokens_cache: Dict[int, str] = {}
```

Backend OAuth tokens cached in plaintext in process memory. Risk: memory dump exposes tokens. Acceptable for single-instance deployment, concerning for shared environments.

### 1.6 Positive security findings

- Password hashing: bcrypt via passlib (industry standard)
- JWT: supports HS256/RS256 with configurable expiry
- Token blacklisting: JTI-based logout
- Refresh token hashing: SHA256 in database
- CORS: origin whitelisting
- Rate limiting: on auth endpoints with configurable limits
- PKCE: supported in OAuth code flow
- Authorization codes: `secrets.token_urlsafe()`
- User permissions: per-server MCP access control
- Security event logging: audit trail for auth events

---

## 2. Architecture

### 2.1 Global state pattern

Multiple modules use module-level globals injected at startup:

| Module | Globals |
|--------|---------|
| `middleware.py` | `_static_bearer_tokens`, `_trusted_ips`, `_allowed_origins`, `_auth_required`, `_streamable_path` |
| `auth/endpoints.py` | `_config` |
| `auth/dcr_endpoints.py` | `_config` |
| `admin/routes.py` | `_config` |
| `rate_limiter.py` | `_rate_limiter` |
| `config.py` | `_config_instance` |

**Assessment**: This is a common pattern in Starlette/ASGI apps without a DI container. All globals are set **once at startup** in `app.py` (lines 34-99) before the server starts accepting requests. Not thread-unsafe per se (Python GIL + single-write-at-startup), but makes unit testing harder because you can't easily swap configs per test.

**Note**: The old audit report claimed this is "thread-unsafe" and a "critical" issue. This is **overstated** - for a single-process ASGI server with asyncio (not threading), write-once globals are safe. The real cost is testability.

### 2.2 Circular imports

**Old report claimed**: "Circular import risk" between `app.py` and other modules.

**Verified**: **No circular imports exist**. Module dependency flows cleanly:
- `app.py` imports from `auth.endpoints`, `admin.routes`, `mcp.handler`, etc.
- None of those modules import from `app.py`
- All imports are direct, no lazy import hacks needed

### 2.3 Monolithic files

Files exceeding reasonable size:

| File | Lines | Recommended action |
|------|-------|--------------------|
| `admin/routes.py` | 1,558 | Split into users.py, servers.py, tokens.py, settings.py, security.py |
| `auth/endpoints.py` | 1,293 | Split: user_auth.py, oauth_token.py, registration.py |
| `auth/user_store.py` | 809 | Acceptable for a data access layer |
| `mcp/store.py` | 788 | Acceptable for a data access layer |
| `security/logger.py` | 607 | Could split: logger.py + cleanup.py |

The two largest files (`admin/routes.py` and `auth/endpoints.py`) would benefit from splitting for maintainability and code review.

### 2.4 Module structure

Well-organized:
- `auth/` - Clean separation (JWT, password, OAuth, DCR, user store)
- `mcp/` - Clear proxy/store/handler/health separation
- `security/` - Dedicated logger and auditor

---

## 3. Code Quality

### 3.1 Type hints

~85% of public functions have type hints. Notable:
- `config.py`: comprehensive dataclass types
- `auth/jwt_handler.py`: full type coverage
- `auth/models.py`: Pydantic models with validation
- Gap: some admin route handlers lack return types

### 3.2 Docstrings

~80% coverage with Google-style format. Consistent in core modules. Some admin/utility functions lack docstrings.

### 3.3 Error handling

Mixed patterns:

```python
# Pattern 1: JSONResponse (most common)
return JSONResponse({"error": "message"}, status_code=400)

# Pattern 2: Different error shapes
return JSONResponse({"detail": "message"}, status_code=400)
return JSONResponse({"error": "code", "error_description": "message"}, status_code=400)
```

OAuth endpoints correctly use RFC-compliant error format (`error` + `error_description`). Admin/auth endpoints use a simpler `{"error": "message"}` format. Not a bug, but inconsistent.

### 3.4 Logging

Good use of `logging` module throughout. No `print()` statements in source. Structured security event logging in `security/logger.py`. Log levels used appropriately.

---

## 4. Testing

### 4.1 Current state

**3 tests, 6% coverage (219/4,523 statements)**

| Test | What it covers |
|------|---------------|
| `test_log_cleanup.py` | Security log archiving to JSONL |
| `test_mcp_logging.py` | MCP handler error logging |
| `test_token_manager.py` | Token refresh with invalid expiry date |

All 3 pass. Uses pytest with asyncio_mode=auto.

### 4.2 Coverage by module

| Module | Coverage | Statements |
|--------|----------|------------|
| `config.py` | 48% | 168 |
| `mcp/token_manager.py` | 50% | 120 |
| `mcp/handler.py` | 29% | 115 |
| `security/logger.py` | 24% | 218 |
| `mcp/proxy.py` | 13% | 205 |
| `mcp/store.py` | 11% | 213 |
| Everything else | 0% | ~3,484 |

### 4.3 Critical untested areas

1. **Authentication** (0%): login, register, token refresh, logout, OAuth token endpoint
2. **Admin panel** (0%): user CRUD, server management, settings
3. **Middleware** (0%): JWT validation, CORS, auth bypass for trusted IPs
4. **MCP routing** (0%): tool aggregation, backend proxying
5. **Rate limiting** (0%): limit enforcement, window expiry

### 4.4 Missing test infrastructure

- No `conftest.py` with shared fixtures
- No test database setup/teardown
- No test HTTP client (Starlette TestClient)
- No integration test framework

---

## 5. Dependencies

```
mcp>=1.2.0          starlette>=0.37.2    uvicorn>=0.30.0
httpx>=0.27.0       pyjwt[crypto]>=2.8.0 python-dotenv>=1.0.1
jinja2>=3.1.0       passlib[bcrypt]>=1.7.4  bcrypt<4.2.0
email-validator>=2.1.0
```

`bcrypt<4.2.0` is pinned without comment. This could prevent security updates. Should document the reason or remove the cap.

---

## 6. Deployment

Working well:
- Dockerfile + docker-compose.yml
- CLI tool (`authmcp-gateway start/create-admin/init-db`)
- Environment-based configuration with sane defaults
- Auto-generates JWT_SECRET_KEY on first run
- Setup wizard for initial admin creation
- Health checks for backend MCP servers
- Background token refresh daemon

---

## 7. Corrections to Old Report

The previous AUDIT_REPORT.md contained several inaccuracies:

| Claim | Verdict |
|-------|---------|
| "CLAUDE.md describes wrong project" | **PARTIALLY TRUE** - The parent NeuroStore/CLAUDE.md describes a different project, but `authmcp-gateway/CLAUDE.md` correctly describes this project |
| "Circular import risk" | **FALSE** - No circular imports found. Module dependencies flow cleanly |
| "Thread-unsafe global state" | **OVERSTATED** - Globals are write-once at startup, not mutated during request handling. Safe for single-process asyncio |
| "SQL injection in mcp/store.py" with `f"SELECT * FROM tools WHERE name = '{tool_name}'"` | **FALSE** - This code does not exist. All queries use parameterized `?` placeholders |
| "6% test coverage" | **TRUE** - Confirmed: 3 tests, 219/4,523 statements covered |
| "No rate limiting on /mcp" | **TRUE** - Only auth endpoints are rate-limited |
| "Tokens in plaintext memory" | **TRUE** - Backend OAuth tokens cached in dict |
| "Admin routes monolithic (1,558 lines)" | **TRUE** - Confirmed |
| "Missing docstrings" | **OVERSTATED** - ~80% coverage is reasonable |

---

## 8. Prioritized Recommendations

### HIGH

1. **Enable Jinja2 autoescape** - One-line fix, prevents XSS
2. **Add rate limiting to /mcp** - Prevents abuse of backend servers
3. **Expand test coverage to 50%+** - Focus on auth, middleware, MCP routing
4. **Create conftest.py** with test database, test client, common fixtures

### MEDIUM

5. **Split admin/routes.py** (~1,558 lines) into 4-5 focused modules
6. **Split auth/endpoints.py** (~1,293 lines) into 3 modules
7. **Document bcrypt<4.2.0 version pin** or remove it
8. **Standardize error response format** across endpoints

### LOW

9. **Add type hints** to remaining ~15% of functions
10. **Consider DI container** for better testability (e.g., Starlette's `request.app.state`)

---

**Audit completed**: February 15, 2026
