"""OAuth 2.0 Authorization Code Flow with PKCE implementation."""

import base64
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from authmcp_gateway.db import get_db

logger = logging.getLogger(__name__)


def create_authorization_code_table(db_path: str):
    """Create authorization_codes table if not exists.

    Args:
        db_path: Path to SQLite database
    """
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS authorization_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT,
                code_challenge_method TEXT,
                scope TEXT,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
    logger.info("Authorization codes table initialized")


def generate_authorization_code(
    db_path: str,
    user_id: int,
    client_id: str,
    redirect_uri: str,
    code_challenge: Optional[str],
    code_challenge_method: Optional[str],
    scope: Optional[str],
    expires_in_seconds: int = 600,  # 10 minutes
) -> str:
    """Generate and store authorization code.

    Args:
        db_path: Path to SQLite database
        user_id: User ID
        client_id: OAuth client ID
        redirect_uri: Redirect URI
        code_challenge: PKCE code challenge
        code_challenge_method: PKCE challenge method (S256 or plain)
        scope: OAuth scope
        expires_in_seconds: Code expiration time in seconds

    Returns:
        Authorization code
    """
    code = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)

    with get_db(db_path, row_factory=None) as conn:
        conn.execute(
            """
            INSERT INTO authorization_codes
            (code, user_id, client_id, redirect_uri, code_challenge,
             code_challenge_method, scope, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                code,
                user_id,
                client_id,
                redirect_uri,
                code_challenge,
                code_challenge_method,
                scope,
                expires_at,
            ),
        )

    logger.info(f"Generated authorization code for user {user_id}, client {client_id}")
    return code


def verify_authorization_code(
    db_path: str, code: str, client_id: str, redirect_uri: str, code_verifier: Optional[str]
) -> Optional[Dict[str, Any]]:
    """Verify authorization code and return user info.

    Args:
        db_path: Path to SQLite database
        code: Authorization code
        client_id: OAuth client ID
        redirect_uri: Redirect URI
        code_verifier: PKCE code verifier

    Returns:
        Dict with user_id and scope if valid, None otherwise
    """
    with get_db(db_path) as conn:
        # Atomically mark code as used to prevent race conditions.
        # UPDATE ... WHERE used = 0 ensures only one concurrent request succeeds.
        cursor = conn.execute(
            """
            UPDATE authorization_codes SET used = 1
            WHERE code = ? AND client_id = ? AND redirect_uri = ? AND used = 0
        """,
            (code, client_id, redirect_uri),
        )

        if cursor.rowcount == 0:
            logger.warning("Authorization code not found, mismatched, or already used")
            return None

        # Now read the row to verify expiration and PKCE
        cursor = conn.execute(
            """
            SELECT * FROM authorization_codes
            WHERE code = ? AND client_id = ? AND redirect_uri = ?
        """,
            (code, client_id, redirect_uri),
        )

        row = cursor.fetchone()
        if not row:
            logger.warning("Authorization code disappeared after atomic update")
            return None

        # Check expiration
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            logger.warning(f"Authorization code expired: {code}")
            return None

        # Verify PKCE if present
        if row["code_challenge"]:
            if not code_verifier:
                logger.warning("PKCE challenge present but no verifier provided")
                return None

            # Verify code_verifier matches code_challenge
            if row["code_challenge_method"] == "S256":
                # SHA256 hash of verifier, then base64url encode
                verifier_hash = hashlib.sha256(code_verifier.encode()).digest()
                verifier_challenge = base64.urlsafe_b64encode(verifier_hash).decode().rstrip("=")

                if verifier_challenge != row["code_challenge"]:
                    logger.warning("PKCE verification failed")
                    return None
            elif row["code_challenge_method"] == "plain":
                if code_verifier != row["code_challenge"]:
                    logger.warning("PKCE verification failed (plain)")
                    return None

    logger.info(f"Authorization code verified for user {row['user_id']}")

    return {"user_id": row["user_id"], "scope": row["scope"]}


def cleanup_expired_codes(db_path: str):
    """Delete expired authorization codes.

    Args:
        db_path: Path to SQLite database
    """
    with get_db(db_path, row_factory=None) as conn:
        cursor = conn.execute(
            """
            DELETE FROM authorization_codes
            WHERE expires_at < ? OR used = 1
        """,
            (datetime.now(timezone.utc).isoformat(),),
        )

        deleted = cursor.rowcount

    if deleted > 0:
        logger.info(f"Cleaned up {deleted} expired/used authorization codes")
