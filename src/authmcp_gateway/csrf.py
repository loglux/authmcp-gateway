"""CSRF protection middleware using double-submit cookie pattern."""

import hashlib
import hmac
import logging
import secrets

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

# Methods that require CSRF validation
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"

# Routes exempt from CSRF validation
EXEMPT_PATHS = frozenset({"/admin/api/login", "/api/login", "/authorize"})

EXEMPT_PREFIXES = (
    "/mcp",
    "/auth/",
    "/oauth/",
    "/.well-known/",
    "/health",
    "/static/",
    "/setup",
)


def generate_csrf_token(secret_key: str) -> str:
    """Generate a CSRF token: {nonce}.{hmac_signature}."""
    nonce = secrets.token_hex(16)
    signature = hmac.new(secret_key.encode(), nonce.encode(), hashlib.sha256).hexdigest()
    return f"{nonce}.{signature}"


def verify_csrf_token(token: str, secret_key: str) -> bool:
    """Verify a CSRF token's HMAC signature."""
    try:
        nonce, signature = token.split(".", 1)
        expected = hmac.new(secret_key.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except (ValueError, AttributeError):
        return False


class CSRFMiddleware:
    """Double-submit cookie CSRF protection.

    - Safe methods (GET/HEAD/OPTIONS): set ``csrf_token`` cookie if absent.
    - Unsafe methods (POST/PUT/PATCH/DELETE): validate that
      ``X-CSRF-Token`` header matches the ``csrf_token`` cookie and
      the HMAC signature is valid.
    - Exempt routes (MCP, auth API, login endpoints) skip validation.
    """

    def __init__(self, app: ASGIApp, secret_key: str) -> None:
        self.app = app
        self.secret_key = secret_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        path = request.url.path
        method = request.method

        # --- Exempt routes ---
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        # --- Safe methods: pass through, set cookie on response ---
        if method not in UNSAFE_METHODS:
            # We need to intercept the response to set the CSRF cookie
            existing = request.cookies.get(CSRF_COOKIE_NAME)
            if existing and verify_csrf_token(existing, self.secret_key):
                # Valid token already present, pass through
                await self.app(scope, receive, send)
                return

            # Need to inject Set-Cookie header into response
            token = generate_csrf_token(self.secret_key)
            is_https = (
                request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
            )

            cookie_header = f"{CSRF_COOKIE_NAME}={token}; Path=/; Max-Age=86400; SameSite=Strict"
            if is_https:
                cookie_header += "; Secure"

            async def send_with_cookie(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.append((b"set-cookie", cookie_header.encode()))
                    message = {**message, "headers": headers}
                await send(message)

            await self.app(scope, receive, send_with_cookie)
            return

        # --- Unsafe methods: validate CSRF token ---
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)

        if not cookie_token or not header_token:
            logger.warning("CSRF token missing. path=%s method=%s", path, method)
            response = JSONResponse(
                {"detail": "CSRF token missing", "error": "csrf_validation_failed"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        if not hmac.compare_digest(cookie_token, header_token):
            logger.warning("CSRF token mismatch. path=%s method=%s", path, method)
            response = JSONResponse(
                {"detail": "CSRF token mismatch", "error": "csrf_validation_failed"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        if not verify_csrf_token(cookie_token, self.secret_key):
            logger.warning("CSRF token invalid signature. path=%s method=%s", path, method)
            response = JSONResponse(
                {"detail": "CSRF token invalid", "error": "csrf_validation_failed"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        # Valid — proceed
        await self.app(scope, receive, send)
