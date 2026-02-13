"""Helpers for single active access token per user."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Tuple

from authmcp_gateway.auth.jwt_handler import create_access_token, decode_token_unsafe
from authmcp_gateway.auth.user_store import (
    get_user_access_token,
    upsert_user_access_token,
    is_token_blacklisted,
    blacklist_token,
)
from authmcp_gateway.config import JWTConfig


def _parse_expires_at(expires_at) -> Optional[datetime]:
    if not expires_at:
        return None
    if isinstance(expires_at, datetime):
        return expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    try:
        exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return exp_dt
    except Exception:
        return None


def format_expires_in(exp_dt: Optional[datetime]) -> str:
    if not exp_dt:
        return ""
    now = datetime.now(timezone.utc)
    minutes = max(1, int((exp_dt - now).total_seconds() // 60))
    if minutes >= 1440:
        days = minutes // 1440
        return f"{days} day{'s' if days > 1 else ''}"
    if minutes >= 60:
        hours = minutes // 60
        return f"{hours} hour{'s' if hours > 1 else ''}"
    return f"{minutes} minute{'s' if minutes > 1 else ''}"


def get_or_create_user_token(
    db_path: str,
    user_id: int,
    username: str,
    is_superuser: bool,
    config: JWTConfig,
    expire_minutes: int,
) -> Tuple[str, datetime]:
    """Return valid token if exists, otherwise rotate and return new one."""
    existing = get_user_access_token(db_path, user_id)
    if existing:
        token = existing.get("access_token")
        token_jti = existing.get("token_jti")
        exp_dt = _parse_expires_at(existing.get("expires_at"))
        expired = exp_dt is None or exp_dt <= datetime.now(timezone.utc)
        if token and not expired and not (token_jti and is_token_blacklisted(db_path, token_jti)):
            return token, exp_dt
        if token_jti and exp_dt and not is_token_blacklisted(db_path, token_jti):
            try:
                blacklist_token(db_path, token_jti, exp_dt)
            except Exception:
                pass

    token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=is_superuser,
        config=config,
        expire_minutes=expire_minutes,
    )
    payload = decode_token_unsafe(token)
    token_jti = payload.get("jti") or ""
    exp = payload.get("exp")
    exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc) if exp else datetime.now(timezone.utc)
    upsert_user_access_token(db_path, user_id, token, token_jti, exp_dt)
    return token, exp_dt


def rotate_user_token(
    db_path: str,
    user_id: int,
    username: str,
    is_superuser: bool,
    config: JWTConfig,
    expire_minutes: int,
    current_token: Optional[str] = None,
) -> Tuple[str, datetime]:
    """Blacklist current token (if provided) and issue a new one."""
    if current_token:
        try:
            payload = decode_token_unsafe(current_token)
            jti = payload.get("jti")
            exp = payload.get("exp")
            exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc) if exp else datetime.now(timezone.utc)
            if jti:
                blacklist_token(db_path, jti, exp_dt)
        except Exception:
            pass

    token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=is_superuser,
        config=config,
        expire_minutes=expire_minutes,
    )
    payload = decode_token_unsafe(token)
    token_jti = payload.get("jti") or ""
    exp = payload.get("exp")
    exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc) if exp else datetime.now(timezone.utc)
    upsert_user_access_token(db_path, user_id, token, token_jti, exp_dt)
    return token, exp_dt
