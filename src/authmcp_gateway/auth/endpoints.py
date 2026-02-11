"""Authentication API endpoints."""

import logging
import sqlite3
from typing import Optional, Tuple

import jwt
from starlette.requests import Request
from starlette.responses import JSONResponse

from authmcp_gateway.config import AppConfig
from authmcp_gateway.settings_manager import get_settings_manager
from authmcp_gateway.rate_limiter import get_rate_limiter

from .jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token_unsafe,
    get_token_jti,
    verify_token,
)
from .models import (
    ErrorResponse,
    LogoutRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from .password import hash_password, validate_password_strength, verify_password
from .user_store import (
    blacklist_token,
    create_user,
    get_user_by_id,
    get_user_by_username,
    hash_token,
    is_token_blacklisted,
    log_auth_event,
    revoke_refresh_token,
    save_refresh_token,
    update_last_login,
    verify_refresh_token,
)

logger = logging.getLogger(__name__)

# Global config - will be injected at startup
_config: Optional[AppConfig] = None


def set_config(config: AppConfig):
    """Set global config for endpoints.

    Args:
        config: Application configuration
    """
    global _config
    _config = config


def _get_token_ttl() -> Tuple[int, int]:
    """Get token TTL values from settings manager.

    Returns:
        Tuple[int, int]: (access_token_expire_minutes, refresh_token_expire_days)
    """
    try:
        settings = get_settings_manager()
        access_ttl = settings.get("jwt", "access_token_expire_minutes", default=1440)
        refresh_ttl = settings.get("jwt", "refresh_token_expire_days", default=7)
        return access_ttl, refresh_ttl
    except Exception:
        # Fallback to config if settings manager not available
        config = _get_config()
        return config.jwt.access_token_expire_minutes, config.jwt.refresh_token_expire_days


def _get_config() -> AppConfig:
    """Get the global config or raise error if not set.

    Returns:
        AppConfig: The application configuration

    Raises:
        RuntimeError: If config has not been set
    """
    if _config is None:
        raise RuntimeError("Config not initialized. Call set_config() first.")
    return _config


def _get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP from request.

    Args:
        request: Starlette request

    Returns:
        Optional[str]: Client IP address or None
    """
    if request.client:
        return request.client.host
    return None


def _get_user_agent(request: Request) -> Optional[str]:
    """Extract user agent from request.

    Args:
        request: Starlette request

    Returns:
        Optional[str]: User agent string or None
    """
    return request.headers.get("user-agent")


def _extract_token(request: Request) -> Optional[str]:
    """Extract bearer token from Authorization header.

    Args:
        request: Starlette request

    Returns:
        Optional[str]: Extracted token or None
    """
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return None


def _error_response(status_code: int, detail: str, error_code: Optional[str] = None) -> JSONResponse:
    """Create error response.

    Args:
        status_code: HTTP status code
        detail: Error message
        error_code: Optional machine-readable error code

    Returns:
        JSONResponse: Error response
    """
    error = ErrorResponse(detail=detail, error_code=error_code)
    return JSONResponse(
        status_code=status_code,
        content=error.model_dump()
    )


async def register(request: Request) -> JSONResponse:
    """POST /auth/register - Register new user.

    Args:
        request: Starlette request containing UserRegisterRequest JSON

    Returns:
        JSONResponse: 201 with UserResponse on success, error response otherwise
    """
    config = _get_config()
    db_path = config.auth.sqlite_path

    # Check if registration is allowed
    if not config.auth.allow_registration:
        logger.warning("Registration attempt blocked: registration disabled")
        return _error_response(403, "Registration is disabled", "REGISTRATION_DISABLED")

    # Parse request body
    try:
        body = await request.json()
        user_data = UserRegisterRequest(**body)
    except ValueError as e:
        logger.warning("Registration validation error: %s", str(e))
        return _error_response(400, f"Validation error: {str(e)}", "VALIDATION_ERROR")
    except Exception as e:
        logger.error("Failed to parse registration request: %s", str(e))
        return _error_response(400, "Invalid request body", "INVALID_REQUEST")

    # Rate limiting check
    if config.rate_limit.enabled:
        limiter = get_rate_limiter()
        client_ip = _get_client_ip(request) or "unknown"
        identifier = f"register:{client_ip}"

        allowed, retry_after = limiter.check_limit(
            identifier=identifier,
            limit=config.rate_limit.register_limit,
            window=config.rate_limit.register_window
        )

        if not allowed:
            logger.warning(f"Rate limit exceeded for registration from {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many registration attempts. Please try again later.",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "retry_after": retry_after
                },
                headers={"Retry-After": str(retry_after)}
            )

    # Validate password strength
    is_valid, error_msg = validate_password_strength(user_data.password, config.auth)
    if not is_valid:
        logger.warning("Registration failed: weak password for %s", user_data.username)
        return _error_response(400, error_msg, "WEAK_PASSWORD")

    # Check if username or email already exists
    existing_user = get_user_by_username(db_path, user_data.username)
    if existing_user:
        logger.warning("Registration failed: username '%s' already exists", user_data.username)
        return _error_response(409, "Username already exists", "USERNAME_EXISTS")

    # Note: We don't check email uniqueness here since get_user_by_username only checks username
    # In production, you'd add get_user_by_email function

    # Hash password
    password_hash = hash_password(user_data.password)

    # Create user
    try:
        user_id = create_user(
            db_path=db_path,
            username=user_data.username,
            email=user_data.email,
            password_hash=password_hash,
            full_name=user_data.full_name,
            is_superuser=user_data.is_superuser
        )
    except sqlite3.IntegrityError as e:
        error_msg = str(e).lower()
        if "username" in error_msg:
            logger.warning("Registration failed: username '%s' already exists", user_data.username)
            return _error_response(409, "Username already exists", "USERNAME_EXISTS")
        elif "email" in error_msg:
            logger.warning("Registration failed: email '%s' already exists", user_data.email)
            return _error_response(409, "Email already exists", "EMAIL_EXISTS")
        else:
            logger.error("Registration failed with IntegrityError: %s", str(e))
            return _error_response(500, "Failed to create user", "DATABASE_ERROR")
    except Exception as e:
        logger.exception("Unexpected error during user creation")
        return _error_response(500, "Internal server error", "INTERNAL_ERROR")

    # Log event
    log_auth_event(
        db_path=db_path,
        event_type="register",
        user_id=user_id,
        username=user_data.username,
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        success=True
    )

    # Get created user
    user = get_user_by_id(db_path, user_id)
    if not user:
        logger.error("Failed to retrieve newly created user %d", user_id)
        return _error_response(500, "Internal server error", "INTERNAL_ERROR")

    # Return user response
    response = UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        full_name=user.get("full_name"),
        is_active=bool(user["is_active"]),
        is_superuser=bool(user["is_superuser"]),
        created_at=user["created_at"],
        last_login_at=user.get("last_login_at")
    )

    logger.info("User registered successfully: %s (id=%d)", user_data.username, user_id)
    return JSONResponse(
        status_code=201,
        content=response.model_dump(mode="json")
    )


async def login(request: Request) -> JSONResponse:
    """POST /auth/login - Login and get tokens.

    Args:
        request: Starlette request containing UserLoginRequest JSON

    Returns:
        JSONResponse: 200 with TokenResponse on success, error response otherwise
    """
    config = _get_config()
    db_path = config.auth.sqlite_path

    # Parse request body
    try:
        body = await request.json()
        login_data = UserLoginRequest(**body)
    except ValueError as e:
        logger.warning("Login validation error: %s", str(e))
        return _error_response(400, f"Validation error: {str(e)}", "VALIDATION_ERROR")
    except Exception as e:
        logger.error("Failed to parse login request: %s", str(e))
        return _error_response(400, "Invalid request body", "INVALID_REQUEST")

    # Rate limiting check
    if config.rate_limit.enabled:
        limiter = get_rate_limiter()
        client_ip = _get_client_ip(request) or "unknown"
        identifier = f"login:{client_ip}"

        allowed, retry_after = limiter.check_limit(
            identifier=identifier,
            limit=config.rate_limit.login_limit,
            window=config.rate_limit.login_window
        )

        if not allowed:
            logger.warning(f"Rate limit exceeded for login from {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many login attempts. Please try again later.",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "retry_after": retry_after
                },
                headers={"Retry-After": str(retry_after)}
            )

    # Get user by username
    user = get_user_by_username(db_path, login_data.username)
    if not user:
        logger.warning("Login failed: invalid credentials - '%s'", login_data.username)
        log_auth_event(
            db_path=db_path,
            event_type="login",
            username=login_data.username,
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            success=False,
            details="Invalid credentials"
        )
        return _error_response(401, "Invalid username or password", "INVALID_CREDENTIALS")

    # Verify password
    if not verify_password(login_data.password, user["password_hash"]):
        logger.warning("Login failed: invalid credentials - '%s'", login_data.username)
        log_auth_event(
            db_path=db_path,
            event_type="login",
            user_id=user["id"],
            username=user["username"],
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            success=False,
            details="Invalid credentials"
        )
        return _error_response(401, "Invalid username or password", "INVALID_CREDENTIALS")

    # Check if user is active
    if not user["is_active"]:
        logger.warning("Login failed: user '%s' is disabled", login_data.username)
        log_auth_event(
            db_path=db_path,
            event_type="login",
            user_id=user["id"],
            username=user["username"],
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            success=False,
            details="Account disabled"
        )
        return _error_response(403, "Account is disabled", "ACCOUNT_DISABLED")

    # Create access and refresh tokens with dynamic TTL from settings
    access_ttl, refresh_ttl = _get_token_ttl()
    try:
        access_token = create_access_token(
            user_id=user["id"],
            username=user["username"],
            is_superuser=bool(user["is_superuser"]),
            config=config.jwt,
            expire_minutes=access_ttl
        )
        refresh_token = create_refresh_token(
            user_id=user["id"],
            config=config.jwt,
            expire_days=refresh_ttl
        )
    except Exception as e:
        logger.exception("Failed to create tokens for user '%s'", login_data.username)
        return _error_response(500, "Failed to create tokens", "TOKEN_CREATION_ERROR")

    # Hash and save refresh token
    refresh_token_hash = hash_token(refresh_token)
    try:
        # Calculate expiration from token
        refresh_payload = decode_token_unsafe(refresh_token)
        if not refresh_payload or "exp" not in refresh_payload:
            raise ValueError("Invalid refresh token payload")

        from datetime import datetime, timezone
        expires_at = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)

        save_refresh_token(
            db_path=db_path,
            user_id=user["id"],
            token_hash=refresh_token_hash,
            expires_at=expires_at
        )
    except Exception as e:
        logger.exception("Failed to save refresh token for user '%s'", login_data.username)
        return _error_response(500, "Failed to save refresh token", "TOKEN_SAVE_ERROR")

    # Update last login timestamp
    try:
        update_last_login(db_path, user["id"])
    except Exception as e:
        logger.warning("Failed to update last_login for user '%s': %s", login_data.username, str(e))
        # Non-critical, continue

    # Log successful login
    log_auth_event(
        db_path=db_path,
        event_type="login",
        user_id=user["id"],
        username=user["username"],
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        success=True
    )

    # Return token response
    response = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=config.jwt.access_token_expire_minutes * 60
    )

    logger.info("User logged in successfully: %s (id=%d)", user["username"], user["id"])
    return JSONResponse(
        status_code=200,
        content=response.model_dump()
    )


async def refresh(request: Request) -> JSONResponse:
    """POST /auth/refresh - Refresh access token.

    Args:
        request: Starlette request containing RefreshTokenRequest JSON

    Returns:
        JSONResponse: 200 with TokenResponse on success, error response otherwise
    """
    config = _get_config()
    db_path = config.auth.sqlite_path

    # Parse request body
    try:
        body = await request.json()
        refresh_data = RefreshTokenRequest(**body)
    except ValueError as e:
        logger.warning("Refresh validation error: %s", str(e))
        return _error_response(400, f"Validation error: {str(e)}", "VALIDATION_ERROR")
    except Exception as e:
        logger.error("Failed to parse refresh request: %s", str(e))
        return _error_response(400, "Invalid request body", "INVALID_REQUEST")

    # Hash refresh token
    refresh_token_hash = hash_token(refresh_data.refresh_token)

    # Verify refresh token exists in DB and not expired/revoked
    user_id = verify_refresh_token(db_path, refresh_token_hash)
    if not user_id:
        logger.warning("Refresh failed: invalid or expired token")
        return _error_response(401, "Invalid or expired refresh token", "INVALID_REFRESH_TOKEN")

    # Decode and verify JWT
    try:
        payload = verify_token(refresh_data.refresh_token, "refresh", config.jwt)
    except jwt.ExpiredSignatureError:
        logger.warning("Refresh failed: token expired")
        return _error_response(401, "Refresh token expired", "TOKEN_EXPIRED")
    except jwt.InvalidTokenError as e:
        logger.warning("Refresh failed: invalid token - %s", str(e))
        return _error_response(401, "Invalid refresh token", "INVALID_TOKEN")
    except Exception as e:
        logger.error("Refresh token verification failed: %s", str(e))
        return _error_response(401, "Token verification failed", "VERIFICATION_ERROR")

    # Get user_id from token
    token_user_id = int(payload.get("sub"))
    if token_user_id != user_id:
        logger.error("Refresh token user_id mismatch: token=%d, db=%d", token_user_id, user_id)
        return _error_response(401, "Invalid refresh token", "TOKEN_MISMATCH")

    # Get user
    user = get_user_by_id(db_path, user_id)
    if not user:
        logger.error("Refresh failed: user %d not found", user_id)
        return _error_response(401, "User not found", "USER_NOT_FOUND")

    # Check if user is active
    if not user["is_active"]:
        logger.warning("Refresh failed: user %s is disabled", user["username"])
        return _error_response(403, "Account is disabled", "ACCOUNT_DISABLED")

    # Create new access token with dynamic TTL from settings
    access_ttl, _ = _get_token_ttl()
    try:
        access_token = create_access_token(
            user_id=user["id"],
            username=user["username"],
            is_superuser=bool(user["is_superuser"]),
            config=config.jwt,
            expire_minutes=access_ttl
        )
    except Exception as e:
        logger.exception("Failed to create access token for user %d", user_id)
        return _error_response(500, "Failed to create token", "TOKEN_CREATION_ERROR")

    # Log event
    log_auth_event(
        db_path=db_path,
        event_type="token_refresh",
        user_id=user["id"],
        username=user["username"],
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        success=True
    )

    # Return new access token
    response = TokenResponse(
        access_token=access_token,
        refresh_token=None,  # Don't issue new refresh token
        token_type="bearer",
        expires_in=config.jwt.access_token_expire_minutes * 60
    )

    logger.info("Token refreshed successfully for user %s (id=%d)", user["username"], user["id"])
    return JSONResponse(
        status_code=200,
        content=response.model_dump(exclude_none=True)
    )


async def logout(request: Request) -> JSONResponse:
    """POST /auth/logout - Logout and blacklist tokens.

    Args:
        request: Starlette request containing LogoutRequest JSON

    Returns:
        JSONResponse: 200 with success message on success, error response otherwise
    """
    config = _get_config()
    db_path = config.auth.sqlite_path

    # Parse request body
    try:
        body = await request.json()
        logout_data = LogoutRequest(**body)
    except ValueError as e:
        logger.warning("Logout validation error: %s", str(e))
        return _error_response(400, f"Validation error: {str(e)}", "VALIDATION_ERROR")
    except Exception as e:
        logger.error("Failed to parse logout request: %s", str(e))
        return _error_response(400, "Invalid request body", "INVALID_REQUEST")

    # Decode access token (unsafe) to get JTI and exp
    access_payload = decode_token_unsafe(logout_data.access_token)
    if not access_payload:
        logger.warning("Logout failed: unable to decode access token")
        return _error_response(400, "Invalid access token", "INVALID_TOKEN")

    access_jti = access_payload.get("jti")
    access_exp = access_payload.get("exp")
    user_id = access_payload.get("sub")

    if not access_jti or not access_exp:
        logger.warning("Logout failed: missing jti or exp in access token")
        return _error_response(400, "Invalid token format", "INVALID_TOKEN_FORMAT")

    # Add access token JTI to blacklist
    try:
        from datetime import datetime, timezone
        expires_at = datetime.fromtimestamp(access_exp, tz=timezone.utc)
        blacklist_token(db_path, access_jti, expires_at)
    except Exception as e:
        logger.exception("Failed to blacklist access token")
        return _error_response(500, "Failed to blacklist token", "BLACKLIST_ERROR")

    # If refresh token provided, revoke it
    if logout_data.refresh_token:
        refresh_token_hash = hash_token(logout_data.refresh_token)
        try:
            revoke_refresh_token(db_path, refresh_token_hash)
        except Exception as e:
            logger.warning("Failed to revoke refresh token: %s", str(e))
            # Non-critical, continue

    # Log event
    try:
        user_id_int = int(user_id) if user_id else None
        log_auth_event(
            db_path=db_path,
            event_type="logout",
            user_id=user_id_int,
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            success=True
        )
    except Exception as e:
        logger.warning("Failed to log logout event: %s", str(e))
        # Non-critical, continue

    logger.info("User logged out successfully (user_id=%s)", user_id)
    return JSONResponse(
        status_code=200,
        content={"detail": "Logged out successfully"}
    )


async def me(request: Request) -> JSONResponse:
    """GET /auth/me - Get current user info.

    Args:
        request: Starlette request with Authorization header

    Returns:
        JSONResponse: 200 with UserResponse on success, error response otherwise
    """
    config = _get_config()
    db_path = config.auth.sqlite_path

    # Extract token from Authorization header
    token = _extract_token(request)
    if not token:
        logger.warning("Me endpoint called without token")
        return _error_response(401, "Missing authorization token", "NO_TOKEN")

    # Check if token is blacklisted
    try:
        token_jti = get_token_jti(token)
        if token_jti and is_token_blacklisted(db_path, token_jti):
            logger.warning("Me endpoint called with blacklisted token")
            return _error_response(401, "Token has been revoked", "TOKEN_REVOKED")
    except Exception as e:
        logger.warning("Failed to check token blacklist: %s", str(e))
        # Continue with verification

    # Verify token
    try:
        payload = verify_token(token, "access", config.jwt)
    except jwt.ExpiredSignatureError:
        logger.warning("Me endpoint called with expired token")
        return _error_response(401, "Token expired", "TOKEN_EXPIRED")
    except jwt.InvalidTokenError as e:
        logger.warning("Me endpoint called with invalid token: %s", str(e))
        return _error_response(401, "Invalid token", "INVALID_TOKEN")
    except Exception as e:
        logger.error("Token verification failed: %s", str(e))
        return _error_response(401, "Token verification failed", "VERIFICATION_ERROR")

    # Get user_id from token
    user_id = int(payload.get("sub"))

    # Get user from DB
    user = get_user_by_id(db_path, user_id)
    if not user:
        logger.warning("Me endpoint: user %d not found", user_id)
        return _error_response(401, "User not found", "USER_NOT_FOUND")

    # Check if user is active
    if not user["is_active"]:
        logger.warning("Me endpoint: user %s is disabled", user["username"])
        return _error_response(403, "Account is disabled", "ACCOUNT_DISABLED")

    # Return user response
    response = UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        full_name=user.get("full_name"),
        is_active=bool(user["is_active"]),
        is_superuser=bool(user["is_superuser"]),
        created_at=user["created_at"],
        last_login_at=user.get("last_login_at")
    )

    return JSONResponse(
        status_code=200,
        content=response.model_dump(mode="json")
    )


async def oauth_token(request: Request) -> JSONResponse:
    """OAuth2-compatible token endpoint.

    Supports:
    - grant_type=password (login)
    - grant_type=refresh_token (token refresh)

    Accepts both:
    - application/x-www-form-urlencoded (OAuth2 standard, Claude Desktop)
    - application/json (easier for special characters in passwords)
    """
    # Check if config is initialized
    if _config is None:
        logger.error("OAuth token endpoint called but config not initialized")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": "Server configuration not initialized"
            }
        )

    try:
        # Parse request data (support both form-data and JSON)
        content_type = request.headers.get("content-type", "").lower()

        if "application/json" in content_type:
            # Parse JSON
            data = await request.json()
            grant_type = data.get("grant_type")
        else:
            # Parse form data (default for OAuth2)
            form_data = await request.form()
            data = dict(form_data)
            grant_type = form_data.get("grant_type")

        logger.info(f"OAuth token request: grant_type={grant_type}")
        logger.debug(f"DB path: {_config.auth.sqlite_path}")

        if not grant_type:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "Missing grant_type parameter"
                }
            )

        # Handle password grant (login)
        if grant_type == "password":
            username = data.get("username")
            password = data.get("password")

            logger.debug(f"OAuth login attempt: username={username}")

            if not username or not password:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "Missing username or password"
                    }
                )

            # Rate limiting check
            if _config.rate_limit.enabled:
                limiter = get_rate_limiter()
                client_ip = request.client.host if request.client else "unknown"
                identifier = f"oauth_login:{client_ip}"

                allowed, retry_after = limiter.check_limit(
                    identifier=identifier,
                    limit=_config.rate_limit.login_limit,
                    window=_config.rate_limit.login_window
                )

                if not allowed:
                    logger.warning(f"Rate limit exceeded for OAuth login from {client_ip}")
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "too_many_requests",
                            "error_description": "Too many login attempts. Please try again later.",
                            "retry_after": retry_after
                        },
                        headers={"Retry-After": str(retry_after)}
                    )

            # Get user from database
            user = get_user_by_username(_config.auth.sqlite_path, username)
            if not user:
                logger.warning(f"OAuth login failed: invalid credentials - {username}")
                log_auth_event(
                    _config.auth.sqlite_path,
                    "failed_login",
                    None,
                    username,
                    request.client.host if request.client else None,
                    request.headers.get("user-agent"),
                    False,
                    "Invalid credentials"
                )
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Invalid username or password"
                    }
                )

            # Verify password
            if not verify_password(password, user["password_hash"]):
                logger.warning(f"OAuth login failed: invalid credentials - {username}")
                log_auth_event(
                    _config.auth.sqlite_path,
                    "failed_login",
                    user["id"],
                    username,
                    request.client.host if request.client else None,
                    request.headers.get("user-agent"),
                    False,
                    "Invalid credentials"
                )
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Invalid username or password"
                    }
                )

            # Check if user is active
            if not user["is_active"]:
                logger.warning(f"Login failed: user inactive - {username}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "invalid_grant",
                        "error_description": "User account is disabled"
                    }
                )

            # Create tokens with dynamic TTL from settings
            access_ttl, refresh_ttl = _get_token_ttl()
            access_token = create_access_token(
                user["id"],
                user["username"],
                bool(user["is_superuser"]),
                _config.jwt,
                expire_minutes=access_ttl
            )
            refresh_token = create_refresh_token(user["id"], _config.jwt, expire_days=refresh_ttl)

            # Save refresh token
            refresh_jti = get_token_jti(refresh_token)
            refresh_hash = hash_password(refresh_jti)

            # Calculate expiration from token
            from datetime import datetime, timezone
            refresh_payload = decode_token_unsafe(refresh_token)
            expires_at = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)

            save_refresh_token(
                _config.auth.sqlite_path,
                user["id"],
                refresh_hash,
                expires_at
            )

            # Update last login
            update_last_login(_config.auth.sqlite_path, user["id"])

            # Log success
            log_auth_event(
                _config.auth.sqlite_path,
                "login",
                user["id"],
                username,
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
                True,
                None
            )

            logger.info(f"OAuth login successful: {username}")

            # Return OAuth2-compatible response
            return JSONResponse(
                status_code=200,
                content={
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expires_in": _config.jwt.access_token_expire_minutes * 60,
                    "refresh_token": refresh_token
                }
            )

        # Handle refresh_token grant
        elif grant_type == "refresh_token":
            refresh_token_value = data.get("refresh_token")

            logger.debug(f"OAuth refresh: got refresh_token={bool(refresh_token_value)}, data_keys={list(data.keys())}")

            if not refresh_token_value:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "Missing refresh_token parameter"
                    }
                )

            # Verify refresh token
            try:
                payload = verify_token(refresh_token_value, "refresh", _config.jwt)
            except jwt.ExpiredSignatureError:
                logger.warning("OAuth refresh failed: token expired")
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Refresh token expired"
                    }
                )
            except jwt.InvalidTokenError as e:
                logger.error(f"OAuth refresh failed: {e}")
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Invalid refresh token"
                    }
                )

            # Verify refresh token is not revoked
            refresh_jti = get_token_jti(refresh_token_value)
            refresh_hash = hash_password(refresh_jti)
            user_id = verify_refresh_token(_config.auth.sqlite_path, refresh_hash)

            if not user_id:
                logger.warning("OAuth refresh failed: token revoked or not found")
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Refresh token revoked or invalid"
                    }
                )

            # Get user info
            user = get_user_by_id(_config.auth.sqlite_path, user_id)
            if not user or not user["is_active"]:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "invalid_grant",
                        "error_description": "User not found or inactive"
                    }
                )

            # Create new access token with dynamic TTL from settings
            access_ttl, _ = _get_token_ttl()
            new_access_token = create_access_token(
                user["id"],
                user["username"],
                bool(user["is_superuser"]),
                _config.jwt,
                expire_minutes=access_ttl
            )

            logger.info(f"OAuth token refreshed for user: {user['username']}")

            # Return OAuth2-compatible response
            return JSONResponse(
                status_code=200,
                content={
                    "access_token": new_access_token,
                    "token_type": "bearer",
                    "expires_in": _config.jwt.access_token_expire_minutes * 60
                }
            )

        # Handle authorization_code grant (OAuth Authorization Code Flow)
        elif grant_type == "authorization_code":
            from .oauth_code_flow import verify_authorization_code

            code = data.get("code")
            client_id = data.get("client_id")
            redirect_uri = data.get("redirect_uri")
            code_verifier = data.get("code_verifier")  # PKCE

            if not code:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "Missing code parameter"
                    }
                )

            # Note: client_id and redirect_uri might be optional depending on OAuth implementation
            # For PKCE flow, they should be validated

            # Verify authorization code and get user info
            code_info = verify_authorization_code(
                db_path=_config.auth.sqlite_path,
                code=code,
                client_id=client_id or "",
                redirect_uri=redirect_uri or "",
                code_verifier=code_verifier
            )

            if not code_info:
                logger.warning("Invalid or expired authorization code")
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": "Invalid or expired authorization code"
                    }
                )

            # Get user
            user = get_user_by_id(_config.auth.sqlite_path, code_info['user_id'])
            if not user:
                logger.error(f"User not found for id {code_info['user_id']}")
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_grant",
                        "error_description": "User not found"
                    }
                )

            # Generate tokens
            access_token = create_access_token(
                user_id=user["id"],
                username=user["username"],
                is_superuser=user["is_superuser"],
                config=_config.jwt
            )

            refresh_token = create_refresh_token(
                user_id=user["id"],
                config=_config.jwt
            )

            # Save refresh token
            from datetime import datetime, timezone
            refresh_jti = get_token_jti(refresh_token)
            refresh_hash = hash_password(refresh_jti)
            refresh_payload = decode_token_unsafe(refresh_token)
            expires_at = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)

            save_refresh_token(
                _config.auth.sqlite_path,
                user["id"],
                refresh_hash,
                expires_at
            )

            # Update last login
            update_last_login(_config.auth.sqlite_path, user["id"])

            # Log success
            log_auth_event(
                _config.auth.sqlite_path,
                "login",
                user["id"],
                user["username"],
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
                True,
                "Authorization code flow"
            )

            logger.info(f"OAuth authorization code flow successful: {user['username']}")

            # Return OAuth2-compatible response
            return JSONResponse(
                status_code=200,
                content={
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expires_in": _config.jwt.access_token_expire_minutes * 60,
                    "refresh_token": refresh_token
                }
            )

        else:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "unsupported_grant_type",
                    "error_description": f"Grant type '{grant_type}' is not supported"
                }
            )

    except Exception as e:
        logger.exception(f"OAuth token endpoint error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": "Internal server error"
            }
        )
