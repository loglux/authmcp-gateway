"""SQLite database operations for OAuth clients (Dynamic Client Registration)."""

import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .user_store import get_db_connection, hash_token


def init_oauth_clients_table(db_path: str) -> None:
    """Create oauth_clients table if not exists."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT UNIQUE NOT NULL,
                client_secret_hash TEXT,
                client_name TEXT,
                redirect_uris TEXT NOT NULL,
                token_endpoint_auth_method TEXT DEFAULT 'none',
                grant_types TEXT,
                response_types TEXT,
                scope TEXT,
                client_uri TEXT,
                logo_uri TEXT,
                tos_uri TEXT,
                policy_uri TEXT,
                contacts TEXT,
                jwks_uri TEXT,
                jwks TEXT,
                software_id TEXT,
                software_version TEXT,
                registration_access_token_hash TEXT,
                registration_client_uri TEXT,
                last_seen_at TIMESTAMP,
                last_seen_ip TEXT,
                last_seen_user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id)"
        )
        _ensure_oauth_client_columns(conn)


def _ensure_oauth_client_columns(conn: sqlite3.Connection) -> None:
    """Add new columns to oauth_clients if missing."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(oauth_clients)")
    existing = {row[1] for row in cursor.fetchall()}
    for col, col_type in [
        ("last_seen_at", "TIMESTAMP"),
        ("last_seen_ip", "TEXT"),
        ("last_seen_user_agent", "TEXT"),
    ]:
        if col not in existing:
            cursor.execute(f"ALTER TABLE oauth_clients ADD COLUMN {col} {col_type}")


def _json_dumps(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _json_loads(value: Optional[str]) -> Optional[Any]:
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def create_oauth_client(
    db_path: str,
    metadata: Dict[str, Any],
    registration_client_uri_base: str,
) -> Dict[str, Any]:
    """Create a new OAuth client from registration metadata."""
    client_id = secrets.token_urlsafe(24)
    token_auth_method = metadata.get("token_endpoint_auth_method") or "none"
    client_secret = None
    if token_auth_method in {"client_secret_basic", "client_secret_post"}:
        client_secret = secrets.token_urlsafe(32)
        client_secret_hash = hash_token(client_secret)
    else:
        client_secret_hash = None

    registration_access_token = secrets.token_urlsafe(32)
    registration_access_token_hash = hash_token(registration_access_token)
    registration_client_uri = f"{registration_client_uri_base}/{client_id}"

    now = datetime.now(timezone.utc).isoformat()

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO oauth_clients (
                client_id,
                client_secret_hash,
                client_name,
                redirect_uris,
                token_endpoint_auth_method,
                grant_types,
                response_types,
                scope,
                client_uri,
                logo_uri,
                tos_uri,
                policy_uri,
                contacts,
                jwks_uri,
                jwks,
                software_id,
                software_version,
                registration_access_token_hash,
                registration_client_uri,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                client_secret_hash,
                metadata.get("client_name"),
                _json_dumps(metadata.get("redirect_uris")),
                token_auth_method,
                _json_dumps(metadata.get("grant_types")),
                _json_dumps(metadata.get("response_types")),
                metadata.get("scope"),
                metadata.get("client_uri"),
                metadata.get("logo_uri"),
                metadata.get("tos_uri"),
                metadata.get("policy_uri"),
                _json_dumps(metadata.get("contacts")),
                metadata.get("jwks_uri"),
                _json_dumps(metadata.get("jwks")),
                metadata.get("software_id"),
                metadata.get("software_version"),
                registration_access_token_hash,
                registration_client_uri,
                now,
                now,
            )
        )

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "registration_access_token": registration_access_token,
        "registration_client_uri": registration_client_uri,
        "client_id_issued_at": int(datetime.now(timezone.utc).timestamp()),
        "client_secret_expires_at": 0,
    }


def get_oauth_client_by_client_id(db_path: str, client_id: str) -> Optional[Dict[str, Any]]:
    """Get OAuth client by client_id."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return _row_to_client_dict(dict(row))


def get_oauth_client_by_registration_token(
    db_path: str, client_id: str, registration_access_token: str
) -> Optional[Dict[str, Any]]:
    """Get OAuth client by client_id and registration access token."""
    token_hash = hash_token(registration_access_token)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM oauth_clients
            WHERE client_id = ? AND registration_access_token_hash = ?
            """,
            (client_id, token_hash),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return _row_to_client_dict(dict(row))


def update_oauth_client(
    db_path: str,
    client_id: str,
    metadata: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Replace OAuth client metadata."""
    now = datetime.now(timezone.utc).isoformat()
    token_auth_method = metadata.get("token_endpoint_auth_method") or "none"

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE oauth_clients
            SET client_name = ?,
                redirect_uris = ?,
                token_endpoint_auth_method = ?,
                grant_types = ?,
                response_types = ?,
                scope = ?,
                client_uri = ?,
                logo_uri = ?,
                tos_uri = ?,
                policy_uri = ?,
                contacts = ?,
                jwks_uri = ?,
                jwks = ?,
                software_id = ?,
                software_version = ?,
                updated_at = ?
            WHERE client_id = ?
            """,
            (
                metadata.get("client_name"),
                _json_dumps(metadata.get("redirect_uris")),
                token_auth_method,
                _json_dumps(metadata.get("grant_types")),
                _json_dumps(metadata.get("response_types")),
                metadata.get("scope"),
                metadata.get("client_uri"),
                metadata.get("logo_uri"),
                metadata.get("tos_uri"),
                metadata.get("policy_uri"),
                _json_dumps(metadata.get("contacts")),
                metadata.get("jwks_uri"),
                _json_dumps(metadata.get("jwks")),
                metadata.get("software_id"),
                metadata.get("software_version"),
                now,
                client_id,
            ),
        )

    return get_oauth_client_by_client_id(db_path, client_id)


def delete_oauth_client(db_path: str, client_id: str) -> bool:
    """Delete OAuth client by client_id."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM oauth_clients WHERE client_id = ?", (client_id,))
        return cursor.rowcount > 0


def verify_client_secret(client: Dict[str, Any], client_secret: Optional[str]) -> bool:
    """Verify client_secret against stored hash."""
    if client.get("token_endpoint_auth_method") == "none":
        return True
    if not client_secret:
        return False
    return hash_token(client_secret) == client.get("client_secret_hash")


def is_redirect_uri_allowed(client: Dict[str, Any], redirect_uri: str) -> bool:
    """Check if redirect_uri is registered for the client."""
    redirect_uris = client.get("redirect_uris") or []
    return redirect_uri in redirect_uris


def list_oauth_clients(db_path: str) -> list[Dict[str, Any]]:
    """List all OAuth clients."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                client_id,
                client_name,
                redirect_uris,
                token_endpoint_auth_method,
                scope,
                client_uri,
                contacts,
                registration_client_uri,
                last_seen_at,
                last_seen_ip,
                last_seen_user_agent,
                created_at,
                updated_at,
                is_active
            FROM oauth_clients
            ORDER BY created_at DESC
            """
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            data = dict(row)
            data["redirect_uris"] = _json_loads(data.get("redirect_uris")) or []
            data["contacts"] = _json_loads(data.get("contacts")) or []
            results.append(data)
        return results


def rotate_registration_token(db_path: str, client_id: str) -> Optional[str]:
    """Rotate registration_access_token for a client and return new token."""
    new_token = secrets.token_urlsafe(32)
    token_hash = hash_token(new_token)
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE oauth_clients
            SET registration_access_token_hash = ?, updated_at = ?
            WHERE client_id = ?
            """,
            (token_hash, now, client_id),
        )
        if cursor.rowcount <= 0:
            return None
    return new_token


def update_oauth_client_last_seen(
    db_path: str,
    client_id: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> None:
    """Update last seen metadata for a client."""
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE oauth_clients
            SET last_seen_at = ?,
                last_seen_ip = ?,
                last_seen_user_agent = ?,
                updated_at = ?
            WHERE client_id = ?
            """,
            (now, ip_address, user_agent, now, client_id),
        )


def _row_to_client_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    row["redirect_uris"] = _json_loads(row.get("redirect_uris")) or []
    row["grant_types"] = _json_loads(row.get("grant_types")) or None
    row["response_types"] = _json_loads(row.get("response_types")) or None
    row["contacts"] = _json_loads(row.get("contacts")) or None
    row["jwks"] = _json_loads(row.get("jwks")) or None
    return row
