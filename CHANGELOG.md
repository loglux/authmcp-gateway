# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.72] - 2026-10-08

### Changed
- Centralized the MCP `protocolVersion` string ("2025-03-26") into a
  single constant, `mcp._protocol.MCP_PROTOCOL_VERSION`, used by
  `mcp/proxy.py`, `mcp/health.py`, `mcp/handler.py`, and
  `security/mcp_auditor.py`. Previously it was duplicated as a literal
  in each file — `mcp_auditor.py`'s unauthorized-initialize probe had
  drifted to a stale `"2024-11-05"` in the process. No behavior change
  for proxy/health/handler (same value); the auditor probe now sends
  the same revision the gateway actually negotiates.

## [1.2.71] - 2026-10-07

### Fixed
- `pyproject.toml`: `[build-system] requires` floor raised from
  `setuptools>=68.0` to `setuptools>=77.0.1`. The project declares
  `license = "MIT"` + `license-files` (PEP 639 SPDX-style fields), which
  setuptools only started parsing correctly at 77.0.1 — versions 68.2.2
  through 76.1.0 fail `read_configuration()` on this `pyproject.toml` with
  `project.license must be valid exactly by one definition`. `make build`
  / `make publish` never hit this locally because they run with
  `--no-isolation` and reuse whatever setuptools is already installed, but
  a plain `pip install -e .` in a fresh venv (the documented dev-setup
  path) could fail depending on the resolved setuptools version.
- `mcp/proxy.py` (`_proxy_jsonrpc()`) and `mcp/health.py`
  (`check_server()`): session recovery now also triggers on HTTP 404 when
  the failing request carried an `Mcp-Session-Id` header, not just on
  HTTP 400 with `"session"` in the body. Per the MCP Streamable HTTP spec
  (Session Management, rev 2025-03-26 — the revision this gateway
  negotiates), a backend that terminated a session **must** answer 404 to
  a request still carrying that session id; only the 400 case was
  previously handled. A 404 on a request with no session header is still
  treated as a genuine routing error and passed through unchanged. Thanks
  to @jnloos (#5).

### Added
- 4 new tests covering the 404 recovery path: 2 in
  `tests/integration/test_mcp_proxy_more.py`, 2 in
  `tests/integration/test_mcp_health.py` (one recovery case and one
  negative/no-session case per module).

## [1.2.70] - 2026-05-10

### Fixed
- `rate_limiter.RateLimiter.check_limit()` now accepts an `ip_address`
  keyword argument and writes that as `security_events.ip_address` when
  it logs a `rate_limited` event. Previously the *bucket identifier* —
  callers compose `f"<endpoint>:{client_ip}"` to keep per-endpoint
  counters isolated — was logged verbatim, so the admin Security Logs
  table showed `register:9.9.9.9` / `oauth_login:9.9.9.9` instead of
  the real IP. All seven call sites (auth/endpoints, auth/dcr_endpoints,
  auth/authorize_endpoint, admin/login, app.py) pass `ip_address=client_ip`
  now. Identifier-only callers keep the old behavior (fallback to
  identifier) for backwards compatibility.

### Changed (test infrastructure)
- `tests/conftest.py` gained an autouse `_isolate_global_config` fixture
  that wipes the `config._config_instance` singleton and points
  `AUTH_SQLITE_PATH` at a per-test tmp file. Without this fixture, code
  under test that reaches the AppConfig via `get_config()` (rate limiter,
  security logger) lazy-loaded `.env` from cwd — when pytest ran from
  the project root, that resolved to the same `data/auth.db` mounted
  into the live container, and the test suite silently wrote
  `rate_limited` events with `ip_address=ip1` / `9.9.9.9` and OAuth
  audit-log entries with `username=alice/dave/x` into prod.
- Verified: with the fixture, `pytest tests/unit/test_rate_limiter.py`
  produces zero new rows in `data/auth.db.security_events` (before the
  fix, every limit-exceeded test path added one).

### Operational (one-shot)
- Cleaned existing test pollution from prod state:
  - `data/logs/auth.log`: 283 of 389 entries removed (alice/dave/x users,
    `client.example.com` redirects, `chatgpt.com/callback` test redirect).
  - `data/logs/auth.log.2026-05-09` (rotated): 283 of 533 entries removed.
  - `security_events`: 99 rows deleted (`ip_address` in `{ip1, 9.9.9.9}`
    or `:ip1` / `:9.9.9.9` suffix).
  - `auth_audit_log`: 1 row deleted.
  - Backups stashed under `/tmp/authmcp-cleanup-backup/` on the host.

### Added
- Two regression tests in `tests/unit/test_rate_limiter.py`:
  - `test_security_event_logs_clean_ip_not_composite_identifier`
  - `test_security_event_falls_back_to_identifier_when_ip_not_passed`

## [1.2.69] - 2026-05-10

### Fixed
- `mcp/handler.py`: catch-all branch for unknown `notifications/*` methods
  (any notification other than `notifications/initialized`, sent without
  an `id`) returned `JSONResponse(status_code=204, content={})`. That
  emits an `{}` body with `Content-Length: 2`, but RFC 7230 §3.3.2 forbids
  a body on `204 No Content`. uvicorn/h11 enforces this and raised
  `LocalProtocolError: Too much data for declared Content-Length` on send,
  surfacing as `Exception in ASGI application` in the logs after the
  client had already received its 204. Replaced with `Response(status_code=204)`
  (matches the existing happy-path on line 61 for `notifications/initialized`).
- Reproduced live against the running container with
  `curl POST /mcp -d '{"jsonrpc":"2.0","method":"notifications/cancelled"}'`;
  fix verified by re-running the same request and confirming no exception.

### Added
- Regression test `test_dispatch_other_notification_without_id_returns_204_no_body`
  in `tests/integration/test_mcp_handler.py` — asserts both
  `status_code == 204` and `body == b""` for the catch-all path.

### Notes
- TDD: failing test written first, fix applied, test passes.
- One-line source change; CHANGELOG kept verbose because the failure
  mode (success status to client + ASGI exception in logs) is the kind
  of bug that's easy to misdiagnose later.

## [1.2.68] - 2026-05-10

### Fixed
- `init_mcp_database` now creates the `backend_mcp_token_audit` table.
  Previously the table was created **only** by the one-shot migration
  script `scripts/migrate_add_refresh_tokens.py`, so a fresh deployment
  that never ran the migration would silently swallow every
  `log_token_audit()` call (the function has a broad `except` that
  logs at ERROR and rolls back). Existing installs already have the
  table — `CREATE TABLE IF NOT EXISTS` is a no-op for them.
- The two indexes from the migration (`idx_backend_token_audit_server`,
  `idx_backend_token_audit_timestamp`) are also created in init now.

### Added
- 26 new tests for `mcp/store.py` covering server CRUD, tool mappings,
  user permissions, the token-audit log, and the proactive-refresh
  query. `mcp/store.py`: 0% → 90% coverage.
- Notable assertions:
  - `auth_token` round-trips through Fernet (test reads the raw column
    value back and checks the plaintext is **not** in the ciphertext).
  - `update_mcp_server(...)` rejects column names outside its
    whitelist with `ValueError` (SQL-injection guard).
  - `list_mcp_servers(user_id=...)` respects explicit-deny rows but
    defaults to allowed when no permission row exists.
  - `get_servers_needing_refresh(threshold_minutes=10)` returns only
    servers with both `token_expires_at` within the window AND a
    `refresh_token_hash` (no point waking up a server that can't refresh).
- Bug-discovery story: writing the audit-table tests is what surfaced
  the `init_mcp_database` gap. Tests caught a real defect.

### Notes
- 262 + 26 = 288 tests pass. mypy still 0.

## [1.2.67] - 2026-05-09

### Added
- 18 new pure-ASGI tests for `middleware.py` (`McpAuthMiddleware` +
  `ContentTypeFixMiddleware`). Brings the file from 0% → 83%
  coverage. The middleware is the auth gate every MCP request hits,
  so this is the highest-leverage 244-line file in the codebase.
- Test layout: tests don't spin up Starlette or uvicorn — they invoke
  the middleware's `__call__(scope, receive, send)` directly with
  hand-built ASGI scopes and a `_RecordingApp` inner app that records
  whether it was called. A `_drive` helper collects every `send`
  message so tests can assert on status / headers / body without a
  live event loop.
- `McpAuthMiddleware` coverage:
  - websocket scope passes through (non-HTTP)
  - `/.well-known/...` bypasses auth (OAuth discovery)
  - `/health` bypasses auth
  - `/admin/...` bypasses (its own `AdminAuthMiddleware` handles it)
  - disallowed `Origin` → 403 with no inner-app call
  - global `auth_required=False` toggle bypasses every gate
  - `/mcp` without bearer token → 401 with proper
    `WWW-Authenticate: Bearer resource_metadata="..."` header
  - `/mcp` + valid HS256 JWT → forwards to inner app
  - static bearer token (`STATIC_BEARER_TOKENS`) accepted without
    JWT verification
  - blacklisted JTI in DB → 401
  - garbage JWT → 401
  - server-specific endpoint `/mcp/<server>` `tools/call` without
    token → 401 (but `initialize` passes through pre-auth for
    handshake)
  - `trusted_ips` bypasses `tools/call` token requirement
  - `tools/list` response is buffered and gets `securitySchemes`
    with `oauth2` + parsed scopes injected into every tool
- `ContentTypeFixMiddleware` coverage:
  - POST `/mcp` with `application/octet-stream` is rewritten to
    `application/json` before passthrough
  - non-`/mcp` paths pass through unchanged
  - websocket scopes pass through

### Notes
- 244 + 18 = 262 tests pass. mypy still 0.

## [1.2.66] - 2026-05-09

### Added
- 9 more tests for `auth/endpoints.py`. Covers the rate-limit branches
  and the OAuth `authorization_code` grant flow that 1.2.65 left
  uncovered. `auth/endpoints.py`: 52% → 67% coverage.
- Rate-limit tests (3): each enables `rate_limit.enabled=True` with a
  per-window limit of 1 and asserts the second request returns 429
  with `RATE_LIMIT_EXCEEDED` / `too_many_requests` and a `Retry-After`
  header. Covers `/auth/register`, `/auth/login`, and `/oauth/token`
  password grant. New `fresh_rate_limiter` fixture resets the global
  rate limiter before/after each test so prior requests don't leak.
- `/oauth/token` `authorization_code` grant tests (5):
  - 400 `invalid_request` on missing `code`.
  - 400 `invalid_request` on missing `client_id` or `redirect_uri`.
  - 401 `invalid_client` on a non-DCR + non-URL `client_id` (the
    "unknown client" rejection path).
  - 400 `invalid_grant` when the auth code isn't in the DB
    (URL-based public client, validation passes but verification
    fails).
  - End-to-end happy path with PKCE: register a user, mint an auth
    code via `generate_authorization_code` with an S256 challenge,
    exchange it for an `access_token` + `refresh_token`. New
    `authcode_db` fixture adds `authorization_codes` table.
- `/auth/me` (1): expired-token branch — encode a JWT with `exp` in
  the past via PyJWT, assert the response is 401 `TOKEN_EXPIRED`.

### Notes
- 235 + 9 = 244 tests pass. mypy still 0.
- `auth/endpoints.py` 0% (1.2.64) → 52% (1.2.65) → 67% (this release).

## [1.2.65] - 2026-05-09

### Added
- 18 new integration-style tests for `auth/endpoints.py`. Brings the
  largest still-uncovered file from 0% → 52% coverage. Total
  coverage 46% → 48%.
- Test layout: each test builds a real Starlette `Request` (so
  `request.headers`, `request.scope.client`, `request.app.state.config`
  behave like in production) but stubs `request.json` / `request.form`
  to return fixture payloads — no live ASGI server, no router, no
  middleware indirection.
- Coverage by endpoint:
  - `/auth/register`: blocked when `allow_registration=False`, weak
    password 400, happy path (verifies `is_superuser=False` for
    public registration), 409 on duplicate username.
  - `/auth/login`: invalid credentials 401, happy path returns valid
    JWT signed with the configured secret, account-disabled 403.
  - `/auth/refresh`: invalid token 401, happy path issues a new
    access token (and intentionally omits a new refresh token from
    the response).
  - `/auth/logout`: invalid access token 401, happy path blacklists
    the access token's JTI in the DB.
  - `/auth/me`: missing token 401, valid token returns OIDC-shaped
    payload (`sub`, `preferred_username`, `name`, `email_verified`),
    blacklisted token 401 (`TOKEN_REVOKED`).
  - `/oauth/token`: missing `grant_type` 400, password grant via
    form-data (the OAuth2 standard, what Claude Desktop sends),
    invalid creds → `invalid_grant` 401, refresh-token grant
    happy path.

### Notes
- 217 + 18 = 235 tests pass. mypy still 0.

## [1.2.64] - 2026-05-09

### Added
- 14 new tests for `setup_wizard.py`, the first-run admin-creation flow.
  Brings the file from 0% → 100% coverage. Coverage:
  - `is_setup_required`: empty DB, populated DB, missing config, and
    `sqlite3.OperationalError` (returns False — wizard does not open
    on transient DB failure, which is the safer default).
  - `setup_page`: redirects to `/admin` when setup is done; serves the
    HTML form when an admin still needs to be created.
  - `create_admin_user`:
    - 403 when users already exist.
    - 400 on missing username/email/password.
    - 400 with policy error when password is too weak.
    - 201 happy path: user is persisted with `is_superuser=1`,
      `full_name` carried through, response carries `user_id`.
    - 500 on `sqlite3.Error` from `create_user`, surfaces the error
      message in the body.
    - Password-policy overlay from `SettingsManager` actually tightens
      validation (test forces `min_length=100` and rejects an
      otherwise-strong password).
    - When `SettingsManager` is uninitialized (`RuntimeError`), the
      endpoint falls back to `AppConfig` defaults rather than 500ing.

### Notes
- 203 + 14 = 217 tests pass. mypy still 0.
- Request mocks are hand-rolled `SimpleNamespace` objects rather than
  Starlette `TestClient` — none of the tests need real ASGI routing,
  middleware, or a live event loop, just the `request.app.state.config`
  / `await request.json()` surface.
- File-level coverage:
  - `cli.py` 96% (1.2.63).
  - `setup_wizard.py` 100% (this release).

## [1.2.63] - 2026-05-09

### Added
- P1.4: 17 new tests for `cli.py` (entry point for the
  `authmcp-gateway` command), bringing the file from 0% → 96%
  coverage. The CLI is the only user-facing surface that wasn't
  covered, and a regression there breaks installation silently.
  Tests cover:
  - `main()` argparse dispatch — no-command help/exit-1, plus
    dispatch to `start` / `init-db` / `create-admin` / `version`.
  - `start_server` — `uvicorn.run` arg passthrough (host, port,
    log-level lowercased, reload), `dotenv.load_dotenv` only called
    when `--env-file` exists, `LOG_LEVEL` env propagation, the
    `0.0.0.0 → localhost` cosmetic display.
  - `init_database` — real SQLite schema creation in a temp dir
    plus `sqlite3.OperationalError` → exit 1 with friendly message.
  - `create_admin_user` — DB-missing abort, duplicate-username
    abort, interactive password mismatch, interactive password
    match, non-interactive `--password` happy path producing a
    user with `is_superuser=1`.
  - `show_version` — installed version path and the
    `PackageNotFoundError` → "Version: unknown" fallback.
- External side effects (`uvicorn`, `dotenv`, `getpass.getpass`) are
  mocked via `monkeypatch.setitem(sys.modules, ...)` and
  `monkeypatch.setattr`. DB-touching tests use the real
  `initialized_db` fixture so the SQLite schema and user-creation
  paths are exercised end-to-end.

### Notes
- 186 + 17 new tests = 203 total. mypy still 0.
- Coverage: 44% → ~45% (cli.py was 101 statements / 6053 total).

## [1.2.62] - 2026-05-09

### Security
- **Audit A2 — stop storing plaintext JWTs at rest.** The
  `user_access_tokens.access_token` and
  `admin_access_tokens.access_token` columns held the raw JWT for
  every issued session. The columns were dead storage:
  `get_user_access_token` / `get_admin_access_token` only ever
  selected `(token_jti, expires_at)`, and `_try_reuse_current_token`
  only compared on `token_jti`. The full bearer token in those
  columns was never used by the application — but anyone who got
  read access to the SQLite file would have walked away with valid
  bearer tokens for every active session.
- `upsert_user_access_token` / `upsert_admin_access_token` already
  inserted an empty string for the column (the function still
  accepted the `access_token` parameter for signature stability,
  but discarded it before the `INSERT`). This release adds a one-time
  migration in `init_database` that scrubs any plaintext rows
  written by older builds:
  ```sql
  UPDATE user_access_tokens  SET access_token = ''
   WHERE access_token IS NOT NULL AND access_token != '';
  UPDATE admin_access_tokens SET access_token = ''
   WHERE access_token IS NOT NULL AND access_token != '';
  ```
  Cleared row counts are logged at INFO so operators can tell
  whether legacy plaintext was in their DB. The migration is
  idempotent — subsequent inits do nothing.

### Notes
- 184 + 2 new TDD tests pass (186 total). Tests in
  `tests/test_user_store.py`:
  - `test_upsert_user_access_token_does_not_store_plaintext` —
    asserts the function strips the plaintext even when callers
    pass it.
  - `test_init_database_clears_existing_plaintext_access_tokens` —
    inserts a legacy plaintext row by hand, re-runs init, and
    verifies it was scrubbed.
- mypy: still 0 errors.
- Other token columns reviewed and confirmed safe:
  - `mcp_servers.auth_token` — Fernet-encrypted ✓
  - `mcp_servers.refresh_token_encrypted` — Fernet-encrypted ✓
  - `users.password_hash`, `refresh_tokens.token_hash`,
    `client_secret_hash`, `mcp_servers.refresh_token_hash` — hashes,
    not plaintext ✓

## [1.2.61] - 2026-05-09

### Changed
- mypy cleanup (Admin + misc, **final batch**): cleared the last 8
  errors across 6 files. **mypy: 0 errors across 52 source files.**
- One real defensive hardening: `admin_auth.py` had the same
  `int(payload.get("sub"))` gap as `auth/endpoints.py` and
  `admin/user_pages.py` — would crash on `int(None)` for a
  malformed admin JWT. Now guards with `if not sub:` and returns
  the standard `_unauthorized` response.
- `setup_wizard.py:setup_page` declared `-> HTMLResponse` but already
  returned `RedirectResponse` when setup was complete. Widened to
  `Response` (same fix applied to `user_portal` in 1.2.55).
- `admin/mcp_tokens_api.py:api_get_token_audit_logs` reassigned
  `server_id` from `Optional[str]` → `int` in-place. mypy can't
  type-narrow across reassignment. Renamed the raw value to
  `server_id_raw` and built the `Optional[int]` cleanly.
- `admin/routes.py` `get_config` and the `api_error_handler`
  decorator wrapper had `[no-any-return]` because Starlette's
  `request.app.state` is typed `Any`. Added explicit
  `cast(AppConfig, ...)` and `cast(JSONResponse, ...)`.
- `app.py:_sorted_scopes` declared `extra_excluded: set =
  frozenset()` — `frozenset` is not a `set`. Switched to
  `AbstractSet[str]` so callers can pass either, and the default
  `frozenset()` is type-correct.
- `app.py` JWKS `serialization.load_pem_public_key(...)` —
  cryptography's typeshed stubs don't expose this re-export at the
  module level even though it's part of the public API. Tagged
  with `# type: ignore[attr-defined]`.

### mypy campaign complete
- Started in 1.2.52 at 135 errors across 23 files.
- 10 releases (1.2.52–1.2.61) covering Auth, MCP, Admin, security,
  config, and app boot layers.
- 8 real defensive-coding gaps closed along the way:
  - Three `int(payload.get("sub"))` crash sites (admin_auth,
    auth/endpoints ×2, admin/user_pages).
  - `asyncio.gather(return_exceptions=True)` BaseException leakage
    in 4 fan-out sites (proxy.py + health.py + token_refresher.py).
  - `get_mcp_server` None-deref in proxy.py 401 retry and health.py
    401 retry.
  - `auth/authorize_endpoint.py` accepting `UploadFile` in the
    `username` form field.
  - `mcp/proxy.py:read_resource` declared `-> Dict` but actually
    returned `Tuple` — caller already unpacked.

### Notes
- mypy: 8 -> 0 errors. 184 tests pass.
- `make typecheck` is now part of the green-build set.

## [1.2.60] - 2026-05-09

### Changed
- mypy cleanup (Auth domain): cleared all 16 errors across 6 files.
  Two real defensive-coding hardenings, rest is annotation work.
- Real hardening (same pattern as `admin/user_pages.py` in 1.2.55):
  `auth/endpoints.py` had two `int(payload.get("sub"))` sites
  (refresh-token and `/auth/me`) that would crash on `int(None)`
  for a malformed JWT that slipped past `verify_token` without a
  `sub` claim. Now each guards on `if not sub: return 401` first.
- `auth/authorize_endpoint.py` form parsing accepted Starlette
  `UploadFile | str | None` and passed straight into DB / hashing
  helpers typed `str`. Tightened guard to
  `not isinstance(username, str) or not isinstance(password, str)`
  so file uploads under the `username` field name (which would have
  reached `bcrypt.checkpw` as bytes) now return the standard
  "Username and password are required" error.
- `auth/authorize_endpoint.py` `_show_login_form_with_error` did
  `form_html.body.decode("utf-8")` — `.body` is `bytes |
  memoryview`. Added `bytes(body) if isinstance(body, memoryview)
  else body` so memoryview-backed responses don't crash with
  `AttributeError: 'memoryview' object has no attribute 'decode'`.
- `auth/dcr_endpoints.py` `get_client` had the `(client, error)
  tuple` invariant gap from
  `_require_registration_token` — added `assert client is not None`
  after the error guard.
- Bookkeeping casts:
  - `auth/user_store.py:create_user` — `cast(int, cursor.lastrowid)`.
  - `auth/client_store.py:delete_oauth_client` — `bool(rowcount > 0)`.
  - `auth/cimd.py` `_check_target` — `cast(str, info[4][0])`
    (socket sockaddr[0] is typed `str | int`, but for AF_INET / AF_INET6
    it's always the address string).
  - `auth/cimd.py:fetch_client_metadata` — `cast(Dict[str, Any], metadata)`
    on the json() result before returning into the typed slot.
- `auth/endpoints.py:register_user` — `_error_response(400, error_msg
  or "Password does not meet policy", ...)` so the `Optional[str]`
  from `validate_password_strength` doesn't leak into the `str`-typed
  `detail` arg.

### Notes
- mypy: 25 -> 9 errors. 184 tests pass.

## [1.2.59] - 2026-05-09

### Changed
- mypy cleanup (MCP domain): cleared all 10 errors across `mcp/health.py`,
  `mcp/crypto.py`, and `mcp/token_refresher.py`. One real defensive-coding
  hardening, the rest are annotation work.
- Real bug caught: `mcp/health.py` 401-retry path overwrote `server` with
  the result of `get_mcp_server(self.db_path, server_id)` without a None
  check — the same pattern already fixed in `mcp/proxy.py` in 1.2.53.
  Server can be deleted / lose permissions during the refresh window;
  before this fix, the retry POST would dereference None. Now logs and
  raises `RuntimeError("server vanished mid-refresh")` so the outer
  health-check catch handles it cleanly.
- `mcp/health.py` `asyncio.gather(return_exceptions=True)` filters in
  `check_all_servers` now use `isinstance(r, BaseException)` (not
  `Exception`). Same correction as 1.2.53 — `BaseException` is what
  gather actually returns and what mypy narrows.
- `mcp/token_refresher.py` proactive refresh loop: same gather fix
  (`isinstance(result, BaseException)`).
- `mcp/health.py` `_initialize_session` returned `Any` from
  `httpx.Headers.get(...)` into a `-> str` slot. Wrapped in
  `cast(str, ...)`.
- `mcp/health.py` `_health_checker: HealthChecker = None` →
  `Optional[HealthChecker] = None` (PEP 484 implicit-Optional).
- `mcp/crypto.py` 3 sites: `Fernet.encrypt(...).decode()` /
  `Fernet.decrypt(...).decode()` typed `Any` by the cryptography stubs.
  Wrapped each in `cast(str, ...)` since the chain always yields a
  decoded str on success.

### Notes
- mypy: 35 -> 25 errors. 184 tests pass.

## [1.2.58] - 2026-05-09

### Changed
- mypy cleanup: cleared all 6 errors in `mcp/store.py`. Pure type
  annotations, no behaviour change.
- 4× `cast(int, cursor.lastrowid)` / `cast(int, row[0])` for SQLite
  reads where mypy sees `Any | None` but the call site is right
  after an `INSERT` (so `lastrowid` is guaranteed populated). Sites:
  `create_mcp_server`, `create_tool_mapping`, `set_user_mcp_permission`,
  `get_tool_mapping`.
- `update_server_health` builds a `fields = {...}` dict whose
  initial value type is `str | None` (status, ISO timestamp,
  optional error). It then conditionally adds `tools_count` (int) —
  mypy rejected the int assignment. Annotated `fields: Dict[str,
  Any]`.
- `delete_tool_mapping` returned `cursor.rowcount > 0` which mypy
  inferred as `Any` (rowcount is exposed as `Any` by some sqlite3
  stubs). Wrapped in `bool(...)`.

### Notes
- mypy: 41 -> 35 errors. 184 tests pass.

## [1.2.57] - 2026-05-09

### Changed
- mypy cleanup: cleared all 8 errors in `mcp/handler.py`. Two
  signature corrections that bring the type hints in line with what
  the code already does.
- `handle_request(...) -> JSONResponse` → `-> Response`. The
  notifications branch already returns a 204 plain `Response` (per
  JSON-RPC spec, notifications must not have a body), and the
  top-level dispatcher routes through this method, so widening to
  the `Response` base class matches reality. The docstring spells
  out the two response shapes.
- `_log_mcp(... request_id: Optional[str] = None)` →
  `request_id: Union[int, str, None] = None`. JSON-RPC 2.0 §4 allows
  the `id` field to be a string, number, or null, and all 7 internal
  callers pass `jsonrpc_id` (typed `int`) — the `str(request_id)`
  cast inside the function already handles the conversion. The old
  signature was lying about what callers actually pass.

### Notes
- mypy: 49 -> 41 errors. 184 tests pass. No behaviour change.

## [1.2.56] - 2026-05-09

### Changed
- mypy cleanup: cleared all 14 errors in `security/logger.py`. Pure
  bookkeeping fixes — no behaviour change.
- `cleanup_old_logs(...) -> Dict[str, int]` widened to
  `Dict[str, Any]` because the result mixes `int` (per-table counts)
  with a nested `Dict[str, int]` ("archived") and a `str` ("error").
- `get_security_events` and `get_mcp_requests` SQLite parameter
  lists annotated `params: List[Any]`. mypy was inferring
  `List[str]` from the first `params.append(severity)` and rejecting
  later integer/limit appends.
- `get_mcp_requests` parameter signatures fixed (PEP 484): three
  `: str = None` / `: bool = None` defaults made explicit Optional.
- Return annotation tightened from `-> list` to
  `-> List[Dict[str, Any]]`.
- File-fallback `requests = []` annotated `requests: List[Dict[str,
  Any]]`.

### Notes
- mypy: 66 -> 49 errors. 184 tests pass.

## [1.2.55] - 2026-05-09

### Changed
- mypy cleanup: cleared all 15 errors in `admin/user_pages.py`. Two
  patterns, one of which surfaced a real defensive-coding gap.
- `user_portal` was annotated `-> HTMLResponse` but already returned
  `RedirectResponse` in three branches (no token, admin user, JWT
  failure). Widened to `Response` and added a docstring noting the
  branches. No behaviour change.
- The `_verify_user_token_or_401(token, _config) -> (payload, error)`
  helper carries an undocumented invariant: `error is None ⟹ payload
  is not None`. mypy can't track that across tuple unpacking, so the
  three call sites were `payload.get(...)` on an `Optional[Dict]`,
  and downstream `int(payload.get("sub"))` /
  `username: str = payload.get("username")` were typed `Any | None`.
- Added explicit `assert payload is not None` after each
  `if error: return error` guard, plus proper validation:
  - `sub = payload.get("sub")` + 401 if missing → then `int(sub)`.
  - `username = payload.get("username") or ""` so the type is `str`,
    not `Optional[str]`. The pre-existing DB fallback path
    (`get_user_by_id` to look up username when missing) is preserved.
- This is a real hardening: previously `int(None)` and a `None`
  username could have crashed `get_or_create_user_token` /
  `rotate_user_token` if a malformed JWT slipped past `verify_token`
  with no `sub` claim. Now those return a clean 401.

### Notes
- mypy: 81 -> 66 errors. 184 tests pass.

## [1.2.54] - 2026-05-09

### Changed
- mypy cleanup: cleared all 21 errors in `security/mcp_auditor.py`.
- All 21 errors were a single inference issue: each test method built
  a `result = {...}` dict in multiple branches with mixed value types
  ("details" being `dict | None`, "message" being `str | None`).
  mypy locked in the dict shape from the first branch and rejected
  every later branch with a wider value type, then propagated that
  into the `self.results.append((status, name, message))` tuple-shape
  check.
- Fixed by adding `result: Dict[str, Any]` annotations before the
  first dict literal in each of the six test methods. This is the
  only change in the file — no behaviour difference.

### Notes
- mypy: 102 -> 81 errors. 184 tests pass.
- Same one-line annotation pattern likely fixes a chunk of the
  remaining offenders (`security/logger.py`, `admin/user_pages.py`,
  `mcp/handler.py`).

## [1.2.53] - 2026-05-09

### Changed
- mypy cleanup: cleared all 19 errors in `mcp/proxy.py`.
- Real bugs caught and fixed:
  - 3× `asyncio.gather(return_exceptions=True)` callsites in
    `get_aggregated_capabilities`, `list_tools`, `list_resources`,
    `list_prompts` were filtering with `isinstance(result, Exception)`
    — but `gather` returns `T | BaseException`, so KeyboardInterrupt
    / SystemExit / CancelledError would have leaked into `.items()`,
    `.extend()` and the formatter. Switched to
    `isinstance(result, BaseException)` so the type narrows correctly
    and these never escape into downstream "iterate / merge" code.
  - `read_resource` was annotated `-> Dict[str, Any]` but actually
    returned `Tuple[Dict[str, Any], Dict[str, Any]]` (response, server)
    — its single caller in `mcp/handler.py` already unpacked the tuple.
    Fixed annotation.
  - `_proxy_jsonrpc` 401-retry path overwrote `server` with the result
    of `get_mcp_server(...)` which can return `None`. Added explicit
    None check that aborts the retry instead of dereferencing None.
- `[no-any-return]` pulls cast to declared shapes via `typing.cast`
  (parse_sse_response, fetch tools / resources / prompts /
  resource templates, capabilities discovery, idempotency check).
- `[var-annotated]` locals annotated explicitly:
  - `caps: Dict[str, Any]`
  - `all_tools / all_resources / all_prompts: List[Dict[str, Any]]`
  - `result_keys: Union[List[Any], str]` (the diagnostic log line
    that holds either dict keys or "N/A").

### Notes
- No behaviour change. 184 tests pass.
- mypy: 131 -> 102 errors (proxy.py + downstream caller errors that
  the corrected `read_resource` signature also resolved).

## [1.2.52] - 2026-05-09

### Changed
- mypy cleanup (start of campaign): cleaned all 4 mypy errors in
  `auth/jwt_handler.py` — the foundational JWT module that every
  request flows through.
- 3× implicit Optional defaults made explicit:
  - `create_access_token(expire_minutes: int = None)` ->
    `expire_minutes: int | None = None`.
  - `create_refresh_token(expire_days: int = None)` ->
    `expire_days: int | None = None`.
  - `create_id_token(expire_minutes: int = None)` ->
    `expire_minutes: int | None = None`.
  PEP 484 prohibits implicit Optional and recent mypy enforces it.
- 1× `[no-any-return]`: `get_token_jti` was declared to return `str`
  but pulled out of a `dict[str, Any]`. Now wrapped in
  `typing.cast(str, payload["jti"])` to express that the JWT spec
  guarantees JTI is a string.

### Notes
- No behaviour change. 184 tests pass.
- mypy: 135 -> 131 errors. Per-release cleanup continues.

## [1.2.51] - 2026-05-09

### Changed
- Audit (A1 final batch): narrowed the last 6 broad `except Exception`
  clauses in the CLI surface and the setup wizard. Concludes the
  except-narrowing campaign that started in 1.2.35.
- `cli.py`:
  - `init-db` subcommand catch -> `(sqlite3.Error, OSError)`. Covers
    DB connection / schema-creation errors and missing parent dirs.
  - `create-admin` subcommand catch -> `(sqlite3.Error, ValueError)`.
    Covers DB errors and bcrypt's "password too long" `ValueError`.
  - `version` subcommand catch -> `PackageNotFoundError`. Stops
    masking unrelated import failures as "version: unknown".
- `setup_wizard.py`:
  - `is_setup_required` user-count probe -> `(sqlite3.Error, OSError)`.
    "DB doesn't exist yet" and real DB errors stay handled; a logic
    bug in `get_all_users` no longer silently triggers the setup flow.
  - Inline password-policy override (best-effort) ->
    `(RuntimeError, AttributeError, TypeError, KeyError)`. The block
    is intentionally permissive — it falls back to env-config policy
    on any failure — but stops eating MemoryError / SystemExit etc.
  - Top-level `create_admin_user` handler ->
    `(sqlite3.Error, ValueError, json.JSONDecodeError, TypeError,
    KeyError)`. Covers the request body parse + DB write paths.

### Notes
- No behaviour change on the happy path. 184 tests pass.
- A1 audit campaign complete: 100+ broad excepts narrowed across 17
  files / 17 releases (1.2.35–1.2.51). Remaining broad `except
  Exception` instances in the codebase are intentional boundary
  handlers (JSON-RPC dispatcher, async watchdog loops, security log
  fallbacks) where narrowing would harm correctness.

## [1.2.50] - 2026-05-09

### Changed
- Audit (A1 continued): narrowed broad `except Exception` clauses on
  the application boot / request middleware path so unexpected errors
  no longer hide as "JWKS empty" / "JWT verification failed" with no
  signal of what actually went wrong.
- `app.py` (2 sites narrowed, 1 left intentionally broad):
  - `_apply_dynamic_settings` boot wrapper narrowed to
    `(AttributeError, TypeError, ValueError, KeyError)` — these are the
    only ways a settings JSON can fail to mount onto the dataclass.
  - `/jwks.json` RS256 build narrowed to `(ValueError, TypeError,
    cryptography.exceptions.UnsupportedAlgorithm)` — covers malformed
    PEM, non-bytes encode and unsupported key algorithms; nothing else
    in the block can raise.
  - `rate_limit_cleanup()` async watchdog loop kept as broad
    `Exception` on purpose. Its job is to keep the loop alive on any
    cleanup failure; narrowing risks killing the long-lived task on
    an unforeseen error type.
- `middleware.py:313` JWT verification narrowed to
  `(jwt.PyJWTError, sqlite3.Error, ValueError, KeyError)` — covers
  every failure verifying / blacklist-checking a token.
- `admin_auth.py:107` admin-route auth narrowed to
  `(jwt.PyJWTError, sqlite3.Error, ValueError, KeyError, TypeError)`
  — `TypeError` covers `int(payload.get("sub"))` when `sub` is `None`.

### Notes
- No behaviour change on the happy path. 184 tests pass.
- 8 of the originally-flagged 14 audit-worthy catches have now been
  narrowed across 1.2.49 + 1.2.50; the remaining 6 in `cli.py` and
  `setup_wizard.py` are next.

## [1.2.49] - 2026-05-09

### Changed
- Audit (A1 continued): narrowed 7 broad `except Exception` clauses on
  the configuration / persistence path so unexpected error types are no
  longer silently swallowed.
- `config.py` (3 sites):
  - `JWTConfig.__post_init__` auto-create of `.env` — now `OSError`
    only.
  - `_load_jwt_keys` private/public RSA key file reads — now `OSError`
    only (`FileNotFoundError` was already handled separately above).
- `settings_manager.py` (4 sites):
  - `_load_settings` JSON file read narrowed to `(OSError,
    json.JSONDecodeError, ValueError)`. A corrupt or schema-broken
    `auth_settings.json` still falls back to defaults, but unknown
    runtime errors are no longer masked.
  - `_load_settings` initial-save, `_backfill_defaults` save, and
    public `save()` write paths narrowed to `OSError` only.
- `db.py` `get_db` context manager left as `except Exception`
  intentionally — that catch is a generic safety-net that must rollback
  the transaction for any error raised inside the `with` block (not
  just `sqlite3.Error`), so narrowing would break correctness.

### Notes
- No behaviour change on the happy path. 184 tests pass.
- Continues the broad-except narrowing campaign started in 1.2.35.

## [1.2.48] - 2026-05-09

### Changed
- Refactor: extracted four named exception-class tuples to a new
  module `mcp/_exceptions.py` so the recurring backend-failure catch
  sets are no longer duplicated across `mcp/proxy.py`, `mcp/health.py`,
  and `mcp/handler.py`:
  - `PROXY_TRANSPORT_ERRORS` — `(httpx.HTTPError, json.JSONDecodeError,
    ValueError, KeyError)` — used at 6 per-server fetch / broadcast
    sites in `mcp/proxy.py`.
  - `PROXY_DISCOVERY_ERRORS` — adds `RuntimeError` for backends that
    turn JSON-RPC errors into Python exceptions during initialize.
    2 sites (`proxy._fetch_capabilities_from_server`, health-check
    `_initialize_session`).
  - `PROXY_DISCOVERY_DB_ERRORS` — adds `sqlite3.Error` for paths that
    also cache to SQLite. 2 sites (handler `_handle_initialize`,
    health-check per-server fallback).
  - `PROXY_TOKEN_REFRESH_ERRORS` — `(httpx.HTTPError, sqlite3.Error,
    ValueError, KeyError)` for the OAuth2 refresh-retry block.
    2 sites (`proxy._proxy_jsonrpc`, health-check 401 retry).
- Total: 12 long literal tuples replaced with a single named constant
  per call site. Adding/removing a backend error class now needs one
  edit instead of 12.
- Cleanup: removed now-unused `import httpx` / `import json` /
  `import sqlite3` from `mcp/handler.py` and `mcp/health.py` (they
  were only referenced inside the literal except tuples).

### Notes
- No behaviour change. 184 tests pass. Final of three planned
  helper-extraction releases.

## [1.2.47] - 2026-05-09

### Changed
- Refactor: extracted `try_upgrade_password_hash()` helper in
  `auth/user_store.py`. Five identical try/except blocks across
  `auth/endpoints.py` (login + /oauth/token password grant),
  `auth/authorize_endpoint.py`, `admin/login.py`, and
  `admin/user_pages.py` are now a single call:
  ```python
  try_upgrade_password_hash(db_path, user["id"], upgraded_hash, username)
  ```
  Each call site shrinks from 5 lines to 1.
- Added module-level `logger` to `auth/user_store.py` (separate from
  the file-based audit logger) so the helper can surface DB-write
  failures via the standard logging stack.

### Security (incidental)
- `admin/login.py` admin-portal password-hash upgrade now narrows
  `except Exception:` to `sqlite3.Error` — the last broad catch I
  missed during the A1 pass on this file.

### Notes
- No behaviour change for documented paths. 184 tests pass. Second
  of three planned helper-extraction releases.

## [1.2.46] - 2026-05-09

### Changed
- Refactor: extracted `_verify_user_token_or_401()` helper in
  `admin/user_pages.py`. Three byte-identical try/except blocks
  (the JWT-verify + JTI-blacklist + admin-rejection sequence used
  by `/account/api/get-token`, `/account/api/regenerate`, and
  `/account/api/info`) collapsed into a single helper. Each call site
  now reads:
  ```
  payload, error = _verify_user_token_or_401(token, _config)
  if error:
      return error
  ```
- Hoisted `verify_token`, `decode_token_unsafe`, and
  `is_token_blacklisted` imports to module level (they're now used
  by the shared helper).

### Notes
- No behaviour change. 184 tests pass. This is the first of three
  planned helper-extraction releases motivated by patterns surfaced
  during the A1 narrowing pass.

## [1.2.45] - 2026-05-09

### Changed
- Closed `admin/user_pages.py` for the audit's A1 finding by narrowing
  all seven `except Exception` blocks. No broad catch remains in this
  file:
  - Page-level `verify_token` for `/account` (redirects to /login on
    failure): `jwt.PyJWTError`.
  - User lookup for friendly username (`get_user_by_id` + int conversion
    on `payload["sub"]`): `(sqlite3.Error, ValueError, TypeError)`.
  - Password-hash upgrade after login: `sqlite3.Error`.
  - Three token-verify-and-blacklist combos (`/account/api/profile`,
    `/account/api/get-token`, `/account/api/regenerate`):
    `(jwt.PyJWTError, sqlite3.Error)`.
  - `expires_in_seconds` datetime arithmetic on token-info responses:
    `(TypeError, ValueError, AttributeError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.44] - 2026-05-09

### Changed
- Closed `mcp/token_manager.py` for the audit's A1 finding by narrowing
  all three `except Exception` blocks. No broad catch remains:
  - Encrypt + persist refresh token: `(sqlite3.Error, ValueError)`.
    `encrypt_token` raises `ValueError` on missing/malformed key; the
    DB write surfaces `sqlite3.Error`. Both are non-fatal — the
    in-memory cache keeps refresh working until process restart.
  - Decrypt + cache load on startup: `(sqlite3.Error, ValueError)`.
  - OAuth2 refresh-flow outer wrap: `(httpx.HTTPError,
    json.JSONDecodeError, ValueError, KeyError, sqlite3.Error)` —
    HTTP POST + JSON parse + audit/store DB writes.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.43] - 2026-05-09

### Security
- Closed the silent suppression in `mcp/health.py`: the
  `notifications/initialized` best-effort send during health-check
  initialize previously swallowed all exceptions with `pass`. It now
  catches only `httpx.HTTPError` and logs at DEBUG with the affected
  server name, mirroring the equivalent fix in `mcp/proxy.py` (1.2.38).

### Changed
- Closed `mcp/health.py` for the audit's A1 finding by narrowing the
  remaining `except Exception` blocks:
  - Health-check loop guard (top of `_health_check_loop`): kept broad
    with `# noqa: BLE001` and a comment — this is an intentional
    long-running-loop backstop that must absorb anything to keep the
    checker alive between intervals.
  - Token-refresh attempt during 401 handling: `(httpx.HTTPError,
    sqlite3.Error, ValueError, KeyError)`.
  - Per-server check fallback (after specific TimeoutException /
    HTTPStatusError): `(httpx.HTTPError, json.JSONDecodeError,
    ValueError, KeyError, sqlite3.Error, RuntimeError)`.
  - Initialize attempt outer: `(httpx.HTTPError, json.JSONDecodeError,
    ValueError, KeyError, RuntimeError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.42] - 2026-05-09

### Changed
- Closed `security/logger.py` for the audit's A1 finding by narrowing
  all seven `except Exception` blocks. No broad catch remains in this
  file:
  - `log_security_event` write: `sqlite3.Error`.
  - `log_mcp_request` write: `sqlite3.Error`.
  - MCP DB size-check + auto-cleanup (PRAGMA + cleanup_old_logs):
    `(sqlite3.Error, OSError)` — cleanup also writes a JSONL archive.
  - `cleanup_old_logs`: `(sqlite3.Error, OSError)`.
  - `get_security_events`: `sqlite3.Error`.
  - `get_mcp_request_stats`: `sqlite3.Error`.
  - `get_mcp_requests` (DB → file fallback): `(sqlite3.Error, OSError,
    KeyError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.41] - 2026-05-09

### Changed
- Closed `auth/authorize_endpoint.py` for the audit's A1 finding by
  narrowing all six `except Exception` blocks. No broad catch remains
  in this file:
  - redirect_uri parser → `ValueError` (matches the explicit raise).
  - DCR client lookup outer wrap → `sqlite3.Error` (CIMD failures are
    already caught with a focused 400 inside the URL-client branch).
  - `update_oauth_client_last_seen` post-login → `sqlite3.Error`.
  - Rate-limit-check defensive guard → `(AttributeError, KeyError)`
    so genuine runtime errors propagate but a malformed
    `AppConfig.rate_limit` shape doesn't block /authorize.
  - Password-hash upgrade on /authorize POST → `sqlite3.Error`.
  - Authorization-code generation + audit log outer → `(sqlite3.Error,
    OSError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.40] - 2026-05-09

### Changed
- Closed `auth/endpoints.py` for the audit's A1 finding by narrowing
  the remaining 12 `except Exception` blocks (best-effort logs and
  JWT verify residue paths). All catches in this file now declare
  the specific exception types they handle:
  - Password-hash upgrade in /auth/login and /oauth/token: `sqlite3.Error`.
  - `update_last_login` post-login: `sqlite3.Error`.
  - JWT verify residue catches in /auth/refresh, /auth/logout and
    /auth/me (which sit after `jwt.ExpiredSignatureError` and
    `jwt.InvalidTokenError`): `jwt.PyJWTError` — covers any sibling
    PyJWT subclass while letting non-JWT runtime errors propagate.
  - `revoke_refresh_token` on logout: `sqlite3.Error`.
  - `log_auth_event` (logout audit write): `(sqlite3.Error, OSError)`
    — SQLite write plus rotating file logger.
  - Blacklist short-circuit in /auth/me (decode + DB):
    `(jwt.PyJWTError, sqlite3.Error)`.
  - Three `update_oauth_client_*` post-issue meta updates:
    `sqlite3.Error`.
- The single broad `except Exception` left in the file is the outer
  /oauth/token last-resort wrap, already annotated with
  `# noqa: BLE001` since 1.2.37.

### Notes
- No behaviour change. 184 tests pass. This release is pure narrowing
  of already-logged catches; combined with 1.2.36 (Cat A) and 1.2.37
  (Cat B), `auth/endpoints.py` is now fully audited for the A1
  finding (27 sites total, 26 narrowed + 1 intentional outer wrap).

## [1.2.39] - 2026-05-09

### Changed
- Annotated the nine intentional broad `except Exception` blocks in
  `mcp/handler.py` with `# noqa: BLE001` and explanatory comments.
  These are the JSON-RPC dispatcher backstops (one outer, eight
  per-method) that translate any escaped exception into a JSON-RPC
  `-32603` internal-error response so the MCP client never sees a
  Python traceback. They were already logging via `logger.exception`;
  this release just documents the intent for future reviewers.
- Narrowed the two non-backstop catches:
  - `_handle_initialize` capabilities discovery now catches only
    `(httpx.HTTPError, json.JSONDecodeError, ValueError, KeyError,
    RuntimeError, sqlite3.Error)` — the same exception domain as
    `proxy._fetch_capabilities_from_server`.
  - `_log_mcp` security-log helper now catches only
    `(sqlite3.Error, OSError)` so unrelated runtime errors propagate.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.38] - 2026-05-09

### Security
- Closed four silent-suppression sites in `mcp/proxy.py` that were
  swallowing exceptions with `pass`, `continue`, or `return []` and
  no log line:
  - `notifications/initialized` best-effort send (post-init handshake).
  - Broadcast lookup of a `resource_uri` across backend servers.
  - Per-server `resources/templates/list` fetch.
  - Broadcast lookup of a `prompt_name` across backend servers.

  Each now logs the failure at DEBUG with the affected server and
  identifier, so operators can correlate degraded backend behaviour
  with broadcast iteration.

### Changed
- Narrowed the seven other broad `except Exception` blocks in
  `mcp/proxy.py` to the types that can actually surface from
  `httpx.AsyncClient` calls plus our own JSON parsing:
  `(httpx.HTTPError, json.JSONDecodeError, ValueError, KeyError)`,
  with `sqlite3.Error` added where the block also writes to SQLite
  (token-refresh path, tools-fetch fallback). Truly unexpected errors
  now propagate instead of being relabelled.
- The single intentional broad catch left in place is the one in
  `call_tool` that mirrors any exception onto the dedup-inflight
  Future before re-raising. It now carries `# noqa: BLE001` and a
  comment explaining why a wide catch is required there.
- The capabilities-fetch fallback also accepts `RuntimeError` so
  backends that turn a JSON-RPC "already initialized" response into
  a Python exception continue to be handled gracefully (caught by
  `tests/test_mcp_proxy.py::test_fetch_capabilities_handles_already_initialized_as_non_fatal`).

### Notes
- No behaviour change for any documented happy/error path; the
  184-test suite still passes.

## [1.2.37] - 2026-05-09

### Security
- Narrowed 10 last-resort `except Exception` blocks in
  `auth/endpoints.py` (audit Category B):
  - The four request-body parsers (`/auth/register`, `/auth/login`,
    `/auth/refresh`, `/auth/logout`) now catch only
    `(json.JSONDecodeError, TypeError)` for the post-Pydantic fallback,
    so genuinely unexpected exceptions surface instead of being
    relabelled as "Invalid request body".
  - User creation (`create_user` block) catches only
    `(sqlite3.Error, OSError)`.
  - Login/refresh token issuance and persistence catch only
    `(jwt.PyJWTError, sqlite3.Error)` (login refresh-token save also
    catches `ValueError` for the explicit `raise` on a missing `exp`).
  - Logout blacklist catches only `(sqlite3.Error, ValueError, OSError)`.
- The single broad catch left in place is the outer last-resort wrap
  around `/oauth/token`'s ~570-line grant dispatch. It is now annotated
  with a comment and an explicit `# noqa: BLE001` so reviewers see it
  is intentional.

### Notes
- No behaviour change for any documented happy or error path; the
  existing integration tests for login / refresh / logout / register /
  oauth_token continue to pass unchanged.

## [1.2.36] - 2026-05-09

### Security
- Narrowed silent-fallback helpers in `auth/endpoints.py`. The three
  affected helpers were swallowing every exception class and returning
  defaults with no log line, which masked configuration / parser bugs:
  - `_get_token_ttl` and `_get_password_policy` now catch only
    `RuntimeError` from `get_settings_manager()` and log at DEBUG. Any
    other failure surfaces normally.
  - `_parse_basic_auth` now catches only
    `(binascii.Error, UnicodeDecodeError, ValueError)` and logs at
    DEBUG. Headers without a `:` separator are detected explicitly
    instead of by exception, fixing the previous reliance on
    `str.split(":", 1)` raising on missing separator (which it does
    not — the prior fallback path was effectively dead code).

### Added
- `tests/test_endpoints_helpers.py` with 11 characterization tests
  covering happy/fallback paths for the three helpers, including
  `Basic` auth parsing edge cases (missing/non-Basic scheme,
  malformed base64, invalid UTF-8, no colon, password with embedded
  colons).

## [1.2.35] - 2026-05-09

### Security
- Narrowed broad `except Exception: pass` blocks in `auth/token_service.py`:
  - `verify_token` failures during reuse are now caught only as
    `jwt.PyJWTError` and logged at DEBUG.
  - `is_token_blacklisted` errors are caught only as `sqlite3.Error` and
    logged at WARNING; the caller still rotates safely.
  - Failures of `blacklist_token` (single-session enforcement and
    explicit rotation) are caught only as `sqlite3.Error` and logged at
    ERROR with `exc_info`. Previously they were silently swallowed,
    which meant a transient DB error could leave the previous session
    valid until natural expiry without any operator visibility.
- `_parse_expires_at` now catches `(ValueError, TypeError)` instead of
  bare `Exception`, so unexpected runtime errors no longer surface as
  silent `None`.

### Added
- `tests/test_token_service.py`: 22 characterization tests covering token
  reuse, JTI-mismatch rotation, garbage-input handling, single-session
  enforcement, admin/user store separation, and rotation blacklisting.
  The module previously had 0% coverage.

## [1.2.34] - 2026-05-09

### Security
- **CIMD (Client ID Metadata Documents)**: When `/authorize` receives a
  URL-formatted `client_id`, the gateway now fetches the metadata document
  per the MCP authorization spec and `draft-ietf-oauth-client-id-metadata-document-00`,
  then exact-matches the request's `redirect_uri` against
  `metadata.redirect_uris`. Replaces the previous same-origin fallback,
  closing the path-on-legitimate-host redirect risk.
- SSRF protection on metadata fetch: HTTPS only, non-empty path component,
  refusal of private/loopback/link-local/reserved targets (incl. AWS
  instance-metadata `169.254.169.254` and IPv6 `::1`), 1 MB body cap, 5s
  timeout, no redirects.

### Added
- `auth/cimd.py` module with metadata fetch, validation, and an in-memory
  cache that honours `Cache-Control` `max-age` / `no-store`.
- 22 unit tests for CIMD plus 4 integration tests on `/authorize`.

## [1.2.33] - 2026-05-09

### Security
- **OAuth scope allowlist** (OAuth 2.1 §3.3 / RFC 6749 §3.3): `/authorize`
  and `/oauth/register` now reject any scope outside
  `AuthConfig.allowed_scopes` (default: `openid`, `profile`, `email`,
  `offline_access`). Configurable via `AUTH_ALLOWED_SCOPES`.

### Changed
- `.well-known/oauth-authorization-server` and
  `.well-known/openid-configuration` derive `scopes_supported` from the
  configured allowlist; `code_challenge_methods_supported` is now `["S256"]`
  only (matches the enforcement added in 1.2.32).
- `.well-known/oauth-protected-resource` no longer advertises
  `offline_access` in `scopes_supported` — the MCP authorization spec says
  resource metadata SHOULD NOT include it.

### Added
- `utils.validate_scopes()` helper.

## [1.2.32] - 2026-05-09

### Security
- **PKCE enforcement** (OAuth 2.1 §4.1.1 / RFC 7636 / MCP authorization
  spec): `/authorize` rejects requests without `code_challenge`; only
  `S256` is accepted as `code_challenge_method`. The token endpoint
  refuses to exchange any code that lacks a bound challenge or whose
  method is not `S256` (defense in depth). PKCE comparison switched to
  `hmac.compare_digest`.

### Repository
- Removed `tests/` from `.gitignore`. The full test suite (115 tests
  prior to this release) now ships in the repository instead of living
  only on the maintainer's machine.

## [1.2.31] - 2026-05-09

### Security
- Replaced raw `==` comparisons with `hmac.compare_digest` for the DCR
  initial access token (`auth/dcr_endpoints.py`) and the OAuth client
  secret hash (`auth/client_store.py`), closing two timing-side-channel
  paths.
- The auto-generated `JWT_SECRET_KEY` is no longer printed to `stderr`
  on first run; the operator is pointed to a generation command instead.

### Changed
- Added `.flake8` configuration that defers line length to `black` and
  excludes inline-HTML files. `make lint` now passes with zero warnings.
- Hoisted late imports out of `admin/routes.py` to fix `E402`.

## [1.2.30] - 2026-05-09

### Added
- `Makefile` consolidating dev, build, release, and Docker workflows
  (`make help` for a list). Replaces the ad-hoc `scripts/publish.sh`,
  which has been removed.
- `make docker-release` rebuilds the container with the current
  `GIT_COMMIT` injected so the admin footer reports the right commit.

### Fixed
- Replaced deprecated `datetime.datetime.utcnow()` with timezone-aware
  `datetime.now(timezone.utc)` in `logging_config.py`,
  `admin/logs_api.py`, and `security/mcp_auditor.py`. The previous
  combination of naive `utcnow()` and `+ "Z"` produced ISO timestamps
  that were technically correct but, when compared with timezone-aware
  values, would have raised `TypeError`.

## [1.2.29] - 2026-04-16

### Fixed
- Applied configured backend `tool_prefix` values to tool names returned from the
  aggregated `/mcp` endpoint while preserving raw backend names on per-server
  endpoints.
- Mapped prefixed aggregate tool names back to raw backend tool names for
  `tools/call`, keeping prefixed listings and execution routing consistent.

## [1.2.28] - 2026-04-16

### Changed
- Marked the package as `Production/Stable` in PyPI metadata instead of `Beta`.
- Expanded PyPI classifiers to better reflect the runtime and deployment model:
  `Environment :: Web Environment`, `Framework :: AsyncIO`,
  `Topic :: Internet :: Proxy Servers`, `Topic :: Security :: Cryptography`,
  `Topic :: System :: Monitoring`, and
  `Topic :: System :: Systems Administration :: Authentication/Directory`.

## [1.2.27] - 2026-03-21

### Fixed
- Omitted `null` fields such as `client_secret` and `scope` from Dynamic Client
  Registration responses when those values are not issued, improving strict client
  compatibility.
- Added `id_token` to the authorization code token response when `openid` is
  requested.
- Returned `scope` in the authorization code token response for better OAuth/OIDC
  interoperability.
- Improved `/auth/me` compatibility for OIDC-style userinfo consumers.

### Changed
- Improved ChatGPT connector compatibility for OAuth, DCR, and authorization code
  flows.

[1.2.72]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.72
[1.2.71]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.71
[1.2.70]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.70
[1.2.69]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.69
[1.2.68]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.68
[1.2.67]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.67
[1.2.66]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.66
[1.2.65]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.65
[1.2.64]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.64
[1.2.63]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.63
[1.2.62]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.62
[1.2.61]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.61
[1.2.60]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.60
[1.2.59]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.59
[1.2.58]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.58
[1.2.57]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.57
[1.2.56]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.56
[1.2.55]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.55
[1.2.54]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.54
[1.2.53]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.53
[1.2.52]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.52
[1.2.51]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.51
[1.2.50]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.50
[1.2.49]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.49
[1.2.48]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.48
[1.2.47]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.47
[1.2.46]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.46
[1.2.45]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.45
[1.2.44]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.44
[1.2.43]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.43
[1.2.42]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.42
[1.2.41]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.41
[1.2.40]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.40
[1.2.39]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.39
[1.2.38]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.38
[1.2.37]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.37
[1.2.36]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.36
[1.2.35]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.35
[1.2.34]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.34
[1.2.33]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.33
[1.2.32]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.32
[1.2.31]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.31
[1.2.30]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.30
[1.2.29]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.29
[1.2.28]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.28
[1.2.27]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.27
