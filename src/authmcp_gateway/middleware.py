"""HTTP middleware for AuthMCP Gateway authentication and content handling."""

import json
import logging
from typing import Optional, Set

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from .utils import _parse_scopes, get_request_ip

logger = logging.getLogger(__name__)


# Middleware configuration (injected at startup)
_static_bearer_tokens: Set[str] = set()
_trusted_ips: Set[str] = set()
_allowed_origins: Set[str] = set()
_auth_required: bool = True
_streamable_path: str = "/mcp"


def set_middleware_config(
    static_bearer_tokens: Set[str],
    trusted_ips: Set[str],
    allowed_origins: Set[str],
    auth_required: bool,
    streamable_path: str,
) -> None:
    """Configure middleware globals.

    Args:
        static_bearer_tokens: Set of valid static bearer tokens
        trusted_ips: Set of trusted IP addresses that bypass auth
        allowed_origins: Set of allowed CORS origins
        auth_required: Whether authentication is required
        streamable_path: MCP streamable HTTP path
    """
    global _static_bearer_tokens, _trusted_ips, _allowed_origins, _auth_required, _streamable_path
    _static_bearer_tokens = static_bearer_tokens
    _trusted_ips = trusted_ips
    _allowed_origins = allowed_origins
    _auth_required = auth_required
    _streamable_path = streamable_path


def _is_static_token(token: str) -> bool:
    """Check if token matches any static bearer token.

    Args:
        token: Bearer token string

    Returns:
        True if token is a valid static bearer token
    """
    return token in _static_bearer_tokens


def _auth_challenge_header(
    mcp_public_url: str,
    scopes: Optional[str] = None,
    error: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """Build WWW-Authenticate challenge header for OAuth 2.0.

    Args:
        mcp_public_url: Public URL of the MCP server
        scopes: OAuth scopes (space or comma-separated)
        error: OAuth error code
        description: OAuth error description

    Returns:
        WWW-Authenticate header value
    """
    www_auth = f'Bearer resource_metadata="{mcp_public_url}/.well-known/oauth-protected-resource"'
    if scopes:
        www_auth += f', scope="{scopes}"'
    if error:
        www_auth += f', error="{error}"'
    if description:
        www_auth += f', error_description="{description}"'
    return www_auth


def _unauthorized(mcp_public_url: str, scopes: Optional[str] = None) -> Response:
    """Return 401 Unauthorized response with WWW-Authenticate header.

    Args:
        mcp_public_url: Public URL of the MCP server
        scopes: OAuth scopes for challenge header

    Returns:
        401 Unauthorized response
    """
    return JSONResponse(
        {"detail": "Unauthorized"},
        status_code=401,
        headers={"WWW-Authenticate": _auth_challenge_header(mcp_public_url, scopes)},
    )


def _inject_security_schemes(body: bytes, scopes: Optional[str] = None) -> bytes:
    """Inject OAuth 2.0 security schemes into tools/list response.

    Args:
        body: Original response body (JSON)
        scopes: OAuth scopes (space or comma-separated)

    Returns:
        Modified response body with securitySchemes injected
    """
    try:
        # Handle gzip-compressed responses from backends
        raw = body
        if len(raw) >= 2 and raw[:2] == b"\x1f\x8b":
            import gzip

            raw = gzip.decompress(raw)
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        logger.warning(
            "Failed to parse tools/list JSON for securitySchemes injection: %s",
            e,
        )
        return body

    result = data.get("result")
    if not isinstance(result, dict):
        return body
    tools = result.get("tools")
    if not isinstance(tools, list):
        return body

    parsed_scopes = _parse_scopes(scopes or "")
    schemes = (
        [{"type": "oauth2", "scopes": parsed_scopes}] if parsed_scopes else [{"type": "oauth2"}]
    )

    for tool in tools:
        if isinstance(tool, dict) and "securitySchemes" not in tool:
            tool["securitySchemes"] = schemes

    return json.dumps(data).encode("utf-8")


class McpAuthMiddleware:
    """Pure ASGI authentication middleware for MCP server.

    Handles:
    - CORS origin validation
    - Static bearer token authentication
    - JWT bearer token authentication with blacklist checking
    - Trusted IP bypass
    - OAuth 2.0 security schemes injection into tools/list responses
    """

    def __init__(
        self,
        app,
        jwt_config,
        auth_db_path: str,
        mcp_public_url: str,
        oauth_scopes: Optional[str] = None,
    ):
        self.app = app
        self.jwt_config = jwt_config
        self.auth_db_path = auth_db_path
        self.mcp_public_url = mcp_public_url
        self.oauth_scopes = oauth_scopes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Build a Request object for header access
        request = Request(scope, receive)

        # CORS origin validation
        if _allowed_origins and request.headers.get("origin"):
            origin = request.headers.get("origin")
            if origin not in _allowed_origins:
                logger.warning("Origin not allowed: %s", origin)
                resp = PlainTextResponse("Forbidden", status_code=403)
                await resp(scope, receive, send)
                return

        # Skip auth if not required
        if not _auth_required:
            await self.app(scope, receive, send)
            return

        # Allow well-known and health endpoints
        path = scope.get("path", "")
        if path.startswith("/.well-known/") or path.startswith("/health"):
            await self.app(scope, receive, send)
            return

        # Skip auth for admin endpoints (they have their own middleware)
        if path.startswith("/admin"):
            await self.app(scope, receive, send)
            return

        # Only authenticate MCP endpoints
        is_gateway = path == "/mcp"
        is_server_specific = path.startswith("/mcp/") and path != "/mcp/"
        is_internal = path == _streamable_path

        if not is_gateway and not is_server_specific and not is_internal:
            await self.app(scope, receive, send)
            return

        # Read request body to get MCP method.
        # We must buffer it to replay for downstream handlers.
        body = await request.body()
        method = None
        request_id = None
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
            method = payload.get("method")
            request_id = payload.get("id")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            payload = {}
            logger.warning("Invalid JSON payload for MCP request: %s", e)

        # Create a replay receive so downstream can read the body again
        body_sent = False

        async def replay_receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            # After body is sent, delegate to original receive (for disconnect etc.)
            return await receive()

        # Check trusted IP
        client_host = None
        trusted_ip = False
        if request.client:
            client_host = request.client.host
        if client_host:
            logger.info("MCP client host=%s trusted=%s", client_host, client_host in _trusted_ips)
            trusted_ip = client_host in _trusted_ips

        # Extract bearer token from Authorization header
        auth_header = request.headers.get("authorization", "")
        token = None
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        if auth_header:
            logger.info(
                "Auth header present. scheme=%s token_len=%s",
                auth_header.split(" ", 1)[0],
                len(token) if token else 0,
            )
        else:
            logger.info("Auth header missing.")

        # Verify token (static or JWT)
        token_payload = None
        if token:
            if _is_static_token(token):
                token_payload = {"sub": "static-bearer"}
                logger.info("Static bearer token accepted")
            else:
                # Verify JWT token
                try:
                    from .auth.jwt_handler import get_token_jti, verify_token
                    from .auth.user_store import get_current_user_token_jti, is_token_blacklisted

                    token_payload = verify_token(token, "access", self.jwt_config)

                    # Check blacklist
                    jti = get_token_jti(token)
                    if jti and is_token_blacklisted(self.auth_db_path, jti):
                        logger.warning("Token is blacklisted. jti=%s", jti)
                        resp = _unauthorized(self.mcp_public_url, self.oauth_scopes)
                        await resp(scope, receive, send)
                        return

                    # Enforce single active token per user (if enabled)
                    if self.jwt_config.enforce_single_session and "sub" in token_payload:
                        try:
                            user_id_int = int(token_payload["sub"])
                            current_jti = get_current_user_token_jti(self.auth_db_path, user_id_int)
                            if current_jti and jti and jti != current_jti:
                                logger.warning(
                                    "Token is not current. jti=%s expected=%s", jti, current_jti
                                )
                                resp = _unauthorized(self.mcp_public_url, self.oauth_scopes)
                                await resp(scope, receive, send)
                                return
                        except (ValueError, TypeError):
                            pass

                    scopes = token_payload.get("scope") or token_payload.get("scp")
                    if scopes:
                        logger.info("JWT token scopes=%s", scopes)

                    # Extract user_id from token and store in request state
                    if "sub" in token_payload:
                        try:
                            scope.setdefault("state", {})["user_id"] = int(token_payload["sub"])
                        except (ValueError, TypeError):
                            logger.warning("Invalid user_id in token: %s", token_payload.get("sub"))
                    # Extract client_id (OAuth) from token if present
                    if "client_id" in token_payload:
                        scope.setdefault("state", {})["client_id"] = token_payload.get("client_id")

                    logger.info("JWT token verified successfully")
                except Exception:
                    logger.exception("JWT verification failed.")
                    token_payload = None

        # Authorization checks
        if is_gateway:
            if not token_payload:
                logger.info(
                    "Unauthorized gateway call (JWT required). method=%s id=%s", method, request_id
                )
                self._log_security_event(
                    get_request_ip(request),
                    path,
                    method,
                    request_id,
                    request.headers.get("user-agent"),
                    auth_header,
                )
                resp = _unauthorized(self.mcp_public_url, self.oauth_scopes)
                await resp(scope, receive, send)
                return
        else:
            if method in {"tools/call"} and not token_payload and not trusted_ip:
                logger.info("Unauthorized tools/call (missing or invalid token). id=%s", request_id)
                self._log_security_event(
                    get_request_ip(request),
                    path,
                    method,
                    request_id,
                    request.headers.get("user-agent"),
                    auth_header,
                )
                resp = _unauthorized(self.mcp_public_url, self.oauth_scopes)
                await resp(scope, receive, send)
                return

            if (
                method not in {None, "initialize", "notifications/initialized"}
                and not token_payload
                and not trusted_ip
            ):
                logger.info("Unauthorized MCP call. method=%s id=%s", method, request_id)
                self._log_security_event(
                    get_request_ip(request),
                    path,
                    method,
                    request_id,
                    request.headers.get("user-agent"),
                    auth_header,
                )
                resp = _unauthorized(self.mcp_public_url, self.oauth_scopes)
                await resp(scope, receive, send)
                return

        # For non-tools/list requests, pass through directly
        if method != "tools/list":
            await self.app(scope, replay_receive, send)
            return

        # For tools/list: intercept response to inject securitySchemes
        response_started = False
        initial_message = None
        body_chunks = []

        async def intercept_send(message):
            nonlocal response_started, initial_message

            if message["type"] == "http.response.start":
                # Buffer the start message — we may need to modify headers
                initial_message = message
                response_started = True
                return

            if message["type"] == "http.response.body":
                body_chunks.append(message.get("body", b""))
                more_body = message.get("more_body", False)

                if not more_body:
                    # All body received — now inject securitySchemes
                    full_body = b"".join(body_chunks)

                    # Check content-type from initial_message
                    headers = dict(
                        (k.lower(), v) for k, v in (initial_message.get("headers") or [])
                    )
                    ct = headers.get(b"content-type", b"").decode("utf-8", errors="ignore")

                    if "application/json" in ct:
                        modified_body = _inject_security_schemes(full_body, self.oauth_scopes)
                    else:
                        modified_body = full_body

                    # Rebuild headers: remove old content-length/encoding,
                    # set correct content-length for modified body
                    new_headers = []
                    skip = {b"content-length", b"content-encoding", b"transfer-encoding"}
                    for k, v in initial_message.get("headers") or []:
                        if k.lower() not in skip:
                            new_headers.append((k, v))
                    new_headers.append((b"content-length", str(len(modified_body)).encode()))

                    # Send start with corrected headers
                    await send(
                        {
                            "type": "http.response.start",
                            "status": initial_message.get("status", 200),
                            "headers": new_headers,
                        }
                    )
                    # Send body in one shot
                    await send(
                        {
                            "type": "http.response.body",
                            "body": modified_body,
                            "more_body": False,
                        }
                    )
                # If more_body is True, just keep buffering
                return

        await self.app(scope, replay_receive, intercept_send)

    def _log_security_event(self, client_host, path, method, request_id, user_agent, auth_header):
        """Log unauthorized access security event."""
        try:
            from .security.logger import log_security_event

            auth_scheme = None
            if auth_header:
                auth_scheme = auth_header.split(" ", 1)[0]

            log_security_event(
                db_path=self.auth_db_path,
                event_type="unauthorized_access",
                severity="medium",
                ip_address=client_host,
                endpoint=path,
                method=method,
                details={
                    "request_id": request_id,
                    "mcp_method": method,
                    "user_agent": user_agent,
                    "auth_header_present": bool(auth_header),
                    "auth_scheme": auth_scheme,
                },
            )
        except Exception as log_err:
            logger.error(f"Failed to log security event: {log_err}")


class ContentTypeFixMiddleware:
    """Middleware to fix Content-Type header from octet-stream to JSON.

    Some MCP clients send application/octet-stream instead of application/json.
    This middleware rewrites the header to application/json for MCP endpoints.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("method") != "POST" or scope.get("path") != _streamable_path:
            await self.app(scope, receive, send)
            return

        headers = list(scope.get("headers", []))
        content_type = None
        for k, v in headers:
            if k.lower() == b"content-type":
                content_type = v.decode()
                break

        if content_type and content_type.startswith("application/octet-stream"):
            new_headers = []
            for k, v in headers:
                if k.lower() == b"content-type":
                    new_headers.append((k, b"application/json"))
                else:
                    new_headers.append((k, v))
            scope = dict(scope)
            scope["headers"] = new_headers

        await self.app(scope, receive, send)
