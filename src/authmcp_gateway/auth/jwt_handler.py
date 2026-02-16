"""JWT token creation and verification."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt

from authmcp_gateway.config import JWTConfig


def create_access_token(
    user_id: int, username: str, is_superuser: bool, config: JWTConfig, expire_minutes: int = None
) -> str:
    """Create JWT access token.

    Args:
        user_id: User ID
        username: Username
        is_superuser: Whether user has superuser privileges
        config: JWT configuration
        expire_minutes: Optional override for token expiration in minutes

    Returns:
        str: Encoded JWT access token
    """
    now = datetime.now(timezone.utc)
    ttl = expire_minutes if expire_minutes is not None else config.access_token_expire_minutes
    expire = now + timedelta(minutes=ttl)

    payload = {
        "sub": str(user_id),
        "username": username,
        "is_superuser": is_superuser,
        "type": "access",
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),
    }

    return _encode_token(payload, config)


def create_refresh_token(user_id: int, config: JWTConfig, expire_days: int = None) -> str:
    """Create JWT refresh token.

    Args:
        user_id: User ID
        config: JWT configuration
        expire_days: Optional override for token expiration in days

    Returns:
        str: Encoded JWT refresh token
    """
    now = datetime.now(timezone.utc)
    ttl = expire_days if expire_days is not None else config.refresh_token_expire_days
    expire = now + timedelta(days=ttl)

    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),
    }

    return _encode_token(payload, config)


def verify_token(token: str, token_type: str, config: JWTConfig) -> Dict[str, Any]:
    """Verify and decode JWT token.

    Args:
        token: JWT token to verify
        token_type: Expected token type ("access" or "refresh")
        config: JWT configuration

    Returns:
        Dict[str, Any]: Decoded token payload

    Raises:
        jwt.ExpiredSignatureError: If token has expired
        jwt.InvalidTokenError: If token is invalid
        ValueError: If token type doesn't match expected type
    """
    payload = _decode_token(token, config)

    # Validate token type
    if payload.get("type") != token_type:
        raise ValueError(
            f"Invalid token type. Expected '{token_type}', got '{payload.get('type')}'"
        )

    return payload


def decode_token_unsafe(token: str) -> Dict[str, Any]:
    """Decode token without verification (for blacklist check).

    WARNING: This does not verify the signature. Only use for extracting
    the JTI for blacklist checking before full verification.

    Args:
        token: JWT token to decode

    Returns:
        Dict[str, Any]: Decoded token payload (unverified)

    Raises:
        jwt.DecodeError: If token cannot be decoded
    """
    return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})


def get_token_jti(token: str) -> str:
    """Extract JTI (JWT ID) from token without verification.

    Args:
        token: JWT token

    Returns:
        str: Token JTI

    Raises:
        jwt.DecodeError: If token cannot be decoded
        KeyError: If JTI is not present in token
    """
    payload = decode_token_unsafe(token)
    return payload["jti"]


def _encode_token(payload: Dict[str, Any], config: JWTConfig) -> str:
    """Encode JWT token using configured algorithm.

    Args:
        payload: Token payload
        config: JWT configuration

    Returns:
        str: Encoded JWT token
    """
    if config.algorithm == "HS256":
        return jwt.encode(payload, config.secret_key, algorithm="HS256")
    elif config.algorithm == "RS256":
        return jwt.encode(payload, config.private_key, algorithm="RS256")
    else:
        raise ValueError(f"Unsupported JWT algorithm: {config.algorithm}")


def _decode_token(token: str, config: JWTConfig) -> Dict[str, Any]:
    """Decode and verify JWT token using configured algorithm.

    Args:
        token: JWT token to decode
        config: JWT configuration

    Returns:
        Dict[str, Any]: Decoded and verified token payload

    Raises:
        jwt.ExpiredSignatureError: If token has expired
        jwt.InvalidTokenError: If token is invalid
    """
    if config.algorithm == "HS256":
        return jwt.decode(
            token, config.secret_key, algorithms=["HS256"], options={"verify_exp": True}
        )
    elif config.algorithm == "RS256":
        return jwt.decode(
            token, config.public_key, algorithms=["RS256"], options={"verify_exp": True}
        )
    else:
        raise ValueError(f"Unsupported JWT algorithm: {config.algorithm}")
