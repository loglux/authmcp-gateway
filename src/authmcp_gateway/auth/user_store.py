"""SQLite database operations for user authentication."""

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@contextmanager
def get_db_connection(db_path: str):
    """Context manager for database connections.

    Args:
        db_path: Path to SQLite database file

    Yields:
        sqlite3.Connection: Database connection with row factory enabled

    Usage:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database(db_path: str):
    """Initialize database with schema.

    Args:
        db_path: Path to SQLite database file
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                is_active BOOLEAN DEFAULT 1,
                is_superuser BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login_at TIMESTAMP
            )
        """)

        # Refresh tokens table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                revoked BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Token blacklist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_jti TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Auth audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                username TEXT,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN DEFAULT 1,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        # Create indexes for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_token_blacklist_jti ON token_blacklist(token_jti)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_audit_log_user_id ON auth_audit_log(user_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_audit_log_timestamp ON auth_audit_log(timestamp)
        """)

        # Security events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_id INTEGER,
                username TEXT,
                ip_address TEXT,
                endpoint TEXT,
                method TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)
        """)

        # MCP requests log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mcp_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                mcp_server_id INTEGER,
                method TEXT NOT NULL,
                tool_name TEXT,
                success BOOLEAN NOT NULL,
                error_message TEXT,
                response_time_ms INTEGER,
                ip_address TEXT,
                is_suspicious BOOLEAN DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE SET NULL
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mcp_requests_user_id ON mcp_requests(user_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mcp_requests_server_id ON mcp_requests(mcp_server_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mcp_requests_timestamp ON mcp_requests(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mcp_requests_suspicious ON mcp_requests(is_suspicious)
        """)


def create_user(
    db_path: str,
    username: str,
    email: str,
    password_hash: str,
    full_name: Optional[str] = None,
    is_superuser: bool = False
) -> int:
    """Create a new user.

    Args:
        db_path: Path to SQLite database file
        username: Unique username
        email: Unique email address
        password_hash: Bcrypt hashed password
        full_name: Optional full name
        is_superuser: Whether user has superuser privileges

    Returns:
        int: User ID of created user

    Raises:
        sqlite3.IntegrityError: If username or email already exists
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, full_name, is_superuser)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, email, password_hash, full_name, is_superuser)
        )
        return cursor.lastrowid


def get_user_by_username(db_path: str, username: str) -> Optional[Dict[str, Any]]:
    """Get user by username.

    Args:
        db_path: Path to SQLite database file
        username: Username to look up

    Returns:
        Optional[Dict[str, Any]]: User data as dictionary, or None if not found
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(db_path: str, user_id: int) -> Optional[Dict[str, Any]]:
    """Get user by ID.

    Args:
        db_path: Path to SQLite database file
        user_id: User ID to look up

    Returns:
        Optional[Dict[str, Any]]: User data as dictionary, or None if not found
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def update_last_login(db_path: str, user_id: int):
    """Update last_login_at timestamp for user.

    Args:
        db_path: Path to SQLite database file
        user_id: User ID to update
    """
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (now, user_id)
        )


def save_refresh_token(db_path: str, user_id: int, token_hash: str, expires_at: datetime):
    """Save refresh token hash.

    Args:
        db_path: Path to SQLite database file
        user_id: User ID
        token_hash: SHA256 hash of refresh token
        expires_at: Token expiration datetime
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
            """,
            (user_id, token_hash, expires_at.isoformat())
        )


def verify_refresh_token(db_path: str, token_hash: str) -> Optional[int]:
    """Verify refresh token and return user_id.

    Args:
        db_path: Path to SQLite database file
        token_hash: SHA256 hash of refresh token

    Returns:
        Optional[int]: User ID if token is valid and not expired/revoked, None otherwise
    """
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT user_id FROM refresh_tokens
            WHERE token_hash = ?
            AND expires_at > ?
            AND revoked = 0
            """,
            (token_hash, now)
        )
        row = cursor.fetchone()
        return row["user_id"] if row else None


def revoke_refresh_token(db_path: str, token_hash: str):
    """Revoke refresh token.

    Args:
        db_path: Path to SQLite database file
        token_hash: SHA256 hash of refresh token
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
            (token_hash,)
        )


def revoke_all_user_tokens(db_path: str, user_id: int):
    """Revoke all refresh tokens for a user.

    Args:
        db_path: Path to SQLite database file
        user_id: User ID
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
            (user_id,)
        )


def blacklist_token(db_path: str, token_jti: str, expires_at: datetime):
    """Add token to blacklist.

    Args:
        db_path: Path to SQLite database file
        token_jti: JWT ID (jti claim)
        expires_at: Token expiration datetime
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO token_blacklist (token_jti, expires_at)
            VALUES (?, ?)
            """,
            (token_jti, expires_at.isoformat())
        )


def is_token_blacklisted(db_path: str, token_jti: str) -> bool:
    """Check if token is blacklisted.

    Args:
        db_path: Path to SQLite database file
        token_jti: JWT ID (jti claim)

    Returns:
        bool: True if token is blacklisted, False otherwise
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM token_blacklist WHERE token_jti = ?",
            (token_jti,)
        )
        return cursor.fetchone() is not None


def cleanup_expired_tokens(db_path: str):
    """Delete expired tokens and blacklist entries.

    Args:
        db_path: Path to SQLite database file
    """
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()

        # Delete expired refresh tokens
        cursor.execute(
            "DELETE FROM refresh_tokens WHERE expires_at <= ?",
            (now,)
        )

        # Delete expired blacklist entries
        cursor.execute(
            "DELETE FROM token_blacklist WHERE expires_at <= ?",
            (now,)
        )


def log_auth_event(
    db_path: str,
    event_type: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    success: bool = True,
    details: Optional[str] = None
):
    """Log authentication event to audit table.

    Args:
        db_path: Path to SQLite database file
        event_type: Type of event (e.g., "login", "logout", "token_refresh", "failed_login")
        user_id: Optional user ID
        username: Optional username (useful when user_id not available)
        ip_address: Optional client IP address
        user_agent: Optional client user agent
        success: Whether the event was successful
        details: Optional additional details
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO auth_audit_log
            (event_type, user_id, username, ip_address, user_agent, success, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_type, user_id, username, ip_address, user_agent, success, details)
        )


def hash_token(token: str) -> str:
    """Hash a token using SHA256.

    Args:
        token: Token to hash

    Returns:
        str: Hex digest of SHA256 hash
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_all_users(db_path: str) -> list[Dict[str, Any]]:
    """Get all users from the database.

    Args:
        db_path: Path to SQLite database file

    Returns:
        list: List of user dictionaries
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, email, full_name, is_active, is_superuser,
                   created_at, updated_at, last_login_at
            FROM users
            ORDER BY created_at DESC
            """
        )
        return [dict(row) for row in cursor.fetchall()]


def get_auth_logs(
    db_path: str,
    event_type: Optional[str] = None,
    limit: int = 100
) -> list[Dict[str, Any]]:
    """Get authentication logs.

    Args:
        db_path: Path to SQLite database file
        event_type: Optional filter by event type
        limit: Maximum number of logs to return

    Returns:
        list: List of log entry dictionaries
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()

        if event_type:
            cursor.execute(
                """
                SELECT id, event_type, user_id, username, ip_address, user_agent,
                       success, details, timestamp as created_at
                FROM auth_audit_log
                WHERE event_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (event_type, limit)
            )
        else:
            cursor.execute(
                """
                SELECT id, event_type, user_id, username, ip_address, user_agent,
                       success, details, timestamp as created_at
                FROM auth_audit_log
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,)
            )

        return [dict(row) for row in cursor.fetchall()]


def update_user_status(db_path: str, user_id: int, is_active: bool):
    """Update user active status.

    Args:
        db_path: Path to SQLite database file
        user_id: User ID to update
        is_active: New active status
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET is_active = ?, updated_at = ?
            WHERE id = ?
            """,
            (is_active, datetime.now(timezone.utc).isoformat(), user_id)
        )


def make_user_superuser(db_path: str, user_id: int):
    """Make user a superuser.

    Args:
        db_path: Path to SQLite database file
        user_id: User ID to promote
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET is_superuser = 1, updated_at = ?
            WHERE id = ?
            """,
            (datetime.now(timezone.utc).isoformat(), user_id)
        )


def delete_user(db_path: str, user_id: int) -> bool:
    """Delete user from database.

    Args:
        db_path: Path to SQLite database file
        user_id: User ID to delete

    Returns:
        bool: True if user was deleted, False if user not found
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            return False

        # Delete user (CASCADE will delete related records)
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

        return True
