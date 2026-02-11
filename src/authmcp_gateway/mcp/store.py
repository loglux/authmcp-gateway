"""Database operations for MCP servers."""

import sqlite3
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


def init_mcp_database(db_path: str) -> None:
    """Initialize MCP-related database tables.

    Creates:
    - mcp_servers: Backend MCP server configurations
    - tool_mappings: Explicit tool-to-server mappings
    - user_mcp_permissions: User access permissions to servers
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # MCP servers table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mcp_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            url TEXT NOT NULL,
            tool_prefix TEXT,
            enabled INTEGER DEFAULT 1,
            auth_type TEXT DEFAULT 'none',
            auth_token TEXT,
            routing_strategy TEXT DEFAULT 'prefix',
            status TEXT DEFAULT 'unknown',
            last_health_check TIMESTAMP,
            last_error TEXT,
            tools_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            refresh_token_hash TEXT,
            token_expires_at TIMESTAMP,
            token_last_refreshed TIMESTAMP,
            refresh_endpoint TEXT DEFAULT '/oauth/token'
        )
    """)

    # Tool mappings for explicit routing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT UNIQUE NOT NULL,
            mcp_server_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
        )
    """)

    # User permissions for MCP servers
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_mcp_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mcp_server_id INTEGER NOT NULL,
            can_access INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, mcp_server_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
        )
    """)

    # Create indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_servers_enabled ON mcp_servers(enabled)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_servers_status ON mcp_servers(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mcp_servers_tool_prefix ON mcp_servers(tool_prefix)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_mappings_tool_name ON tool_mappings(tool_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_mappings_mcp_server_id ON tool_mappings(mcp_server_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_mcp_permissions_user_id ON user_mcp_permissions(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_mcp_permissions_mcp_server_id ON user_mcp_permissions(mcp_server_id)")

    conn.commit()
    conn.close()
    logger.info("✓ MCP database tables initialized")


def create_mcp_server(
    db_path: str,
    name: str,
    url: str,
    description: Optional[str] = None,
    tool_prefix: Optional[str] = None,
    enabled: bool = True,
    auth_type: str = "none",
    auth_token: Optional[str] = None,
    routing_strategy: str = "prefix"
) -> int:
    """Create a new MCP server entry.

    Args:
        db_path: Path to SQLite database
        name: Server name (unique)
        url: Backend MCP server URL
        description: Optional description
        tool_prefix: Tool prefix for routing (e.g., "rag_")
        enabled: Whether server is enabled
        auth_type: Auth method for backend ("none", "bearer", "basic")
        auth_token: Token for backend auth
        routing_strategy: Routing strategy ("prefix", "explicit", "auto")

    Returns:
        int: Created server ID

    Raises:
        sqlite3.IntegrityError: If name already exists
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO mcp_servers (
            name, description, url, tool_prefix, enabled,
            auth_type, auth_token, routing_strategy, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            name,
            description,
            url,
            tool_prefix,
            1 if enabled else 0,
            auth_type,
            auth_token,
            routing_strategy,
            datetime.now(timezone.utc).isoformat()
        )
    )

    server_id = cursor.lastrowid
    conn.commit()
    conn.close()

    logger.info(f"Created MCP server: {name} (id={server_id})")
    return server_id


def get_mcp_server(db_path: str, server_id: int) -> Optional[Dict[str, Any]]:
    """Get MCP server by ID.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID

    Returns:
        Dict with server data or None if not found
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM mcp_servers WHERE id = ?",
        (server_id,)
    )

    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None


def get_mcp_server_by_name(db_path: str, name: str) -> Optional[Dict[str, Any]]:
    """Get MCP server by name.

    Args:
        db_path: Path to SQLite database
        name: Server name

    Returns:
        Dict with server data or None if not found
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM mcp_servers WHERE name = ?",
        (name,)
    )

    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None


def list_mcp_servers(
    db_path: str,
    enabled_only: bool = False,
    user_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    """List all MCP servers.

    Args:
        db_path: Path to SQLite database
        enabled_only: Filter only enabled servers
        user_id: Filter by user permissions (if provided)

    Returns:
        List of server dicts
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if user_id:
        # Get servers with user permissions
        query = """
            SELECT s.* FROM mcp_servers s
            LEFT JOIN user_mcp_permissions p ON s.id = p.mcp_server_id AND p.user_id = ?
            WHERE (p.can_access = 1 OR p.id IS NULL)
        """
        params = [user_id]

        if enabled_only:
            query += " AND s.enabled = 1"

        query += " ORDER BY s.name"

    else:
        query = "SELECT * FROM mcp_servers"
        params = []

        if enabled_only:
            query += " WHERE enabled = 1"

        query += " ORDER BY name"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def update_mcp_server(
    db_path: str,
    server_id: int,
    **fields
) -> bool:
    """Update MCP server fields.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID
        **fields: Fields to update

    Returns:
        bool: True if updated, False if not found
    """
    if not fields:
        return False

    # Add updated_at timestamp
    fields["updated_at"] = datetime.now(timezone.utc).isoformat()

    # Build SET clause
    set_clause = ", ".join([f"{key} = ?" for key in fields.keys()])
    values = list(fields.values()) + [server_id]

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        f"UPDATE mcp_servers SET {set_clause} WHERE id = ?",
        values
    )

    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()

    if rows_affected > 0:
        logger.info(f"Updated MCP server {server_id}: {fields}")
        return True

    return False


def update_server_health(
    db_path: str,
    server_id: int,
    status: str,
    tools_count: Optional[int] = None,
    error: Optional[str] = None
):
    """Update server health status.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID
        status: Status ("online", "offline", "error")
        tools_count: Number of tools available
        error: Error message if any
    """
    fields = {
        "status": status,
        "last_health_check": datetime.now(timezone.utc).isoformat(),
        "last_error": error
    }

    if tools_count is not None:
        fields["tools_count"] = tools_count

    update_mcp_server(db_path, server_id, **fields)


def delete_mcp_server(db_path: str, server_id: int) -> bool:
    """Delete MCP server.

    Args:
        db_path: Path to SQLite database
        server_id: Server ID

    Returns:
        bool: True if deleted, False if not found
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM mcp_servers WHERE id = ?",
        (server_id,)
    )

    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()

    if rows_affected > 0:
        logger.info(f"Deleted MCP server {server_id}")
        return True

    return False


# Tool mappings

def create_tool_mapping(
    db_path: str,
    tool_name: str,
    mcp_server_id: int
) -> int:
    """Create explicit tool to MCP server mapping.

    Args:
        db_path: Path to SQLite database
        tool_name: Tool name
        mcp_server_id: MCP server ID

    Returns:
        int: Mapping ID
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO tool_mappings (tool_name, mcp_server_id, created_at)
        VALUES (?, ?, ?)
        """,
        (tool_name, mcp_server_id, datetime.now(timezone.utc).isoformat())
    )

    mapping_id = cursor.lastrowid
    conn.commit()
    conn.close()

    logger.info(f"Created tool mapping: {tool_name} -> server {mcp_server_id}")
    return mapping_id


def get_tool_mapping(db_path: str, tool_name: str) -> Optional[int]:
    """Get MCP server ID for a tool.

    Args:
        db_path: Path to SQLite database
        tool_name: Tool name

    Returns:
        MCP server ID or None
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT mcp_server_id FROM tool_mappings WHERE tool_name = ?",
        (tool_name,)
    )

    row = cursor.fetchone()
    conn.close()

    if row:
        return row[0]
    return None


def list_tool_mappings(db_path: str, mcp_server_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """List tool mappings.

    Args:
        db_path: Path to SQLite database
        mcp_server_id: Filter by MCP server ID (optional)

    Returns:
        List of mapping dicts
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if mcp_server_id:
        cursor.execute(
            "SELECT * FROM tool_mappings WHERE mcp_server_id = ? ORDER BY tool_name",
            (mcp_server_id,)
        )
    else:
        cursor.execute("SELECT * FROM tool_mappings ORDER BY tool_name")

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def delete_tool_mapping(db_path: str, tool_name: str) -> bool:
    """Delete tool mapping.

    Args:
        db_path: Path to SQLite database
        tool_name: Tool name

    Returns:
        bool: True if deleted
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM tool_mappings WHERE tool_name = ?",
        (tool_name,)
    )

    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()

    return rows_affected > 0


# User permissions

def set_user_mcp_permission(
    db_path: str,
    user_id: int,
    mcp_server_id: int,
    can_access: bool = True
) -> int:
    """Set user permission for MCP server.

    Args:
        db_path: Path to SQLite database
        user_id: User ID
        mcp_server_id: MCP server ID
        can_access: Whether user can access this server

    Returns:
        int: Permission ID
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        """
        INSERT INTO user_mcp_permissions (user_id, mcp_server_id, can_access, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id, mcp_server_id) DO UPDATE SET
            can_access = excluded.can_access,
            updated_at = excluded.updated_at
        """,
        (user_id, mcp_server_id, 1 if can_access else 0, now, now)
    )

    permission_id = cursor.lastrowid
    conn.commit()
    conn.close()

    logger.info(f"Set MCP permission: user {user_id} -> server {mcp_server_id} = {can_access}")
    return permission_id


def get_user_mcp_permissions(db_path: str, user_id: int) -> List[Dict[str, Any]]:
    """Get all MCP permissions for a user.

    Args:
        db_path: Path to SQLite database
        user_id: User ID

    Returns:
        List of permission dicts
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT p.*, s.name as server_name
        FROM user_mcp_permissions p
        JOIN mcp_servers s ON p.mcp_server_id = s.id
        WHERE p.user_id = ?
        ORDER BY s.name
        """,
        (user_id,)
    )

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def check_user_mcp_access(db_path: str, user_id: int, mcp_server_id: int) -> bool:
    """Check if user has access to MCP server.

    Args:
        db_path: Path to SQLite database
        user_id: User ID
        mcp_server_id: MCP server ID

    Returns:
        bool: True if user has access (or no explicit permission exists)
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT can_access FROM user_mcp_permissions WHERE user_id = ? AND mcp_server_id = ?",
        (user_id, mcp_server_id)
    )

    row = cursor.fetchone()
    conn.close()

    # If no explicit permission, default to True (allow access)
    if row is None:
        return True

    return bool(row[0])


# Token Management & Audit (NEW)

def log_token_audit(
    db_path: str,
    mcp_server_id: int,
    event_type: str,
    success: bool = True,
    error_message: Optional[str] = None,
    old_expires_at: Optional[datetime] = None,
    new_expires_at: Optional[datetime] = None,
    triggered_by: str = "manual"
) -> None:
    """Log token refresh operation to audit table.

    Args:
        db_path: Path to SQLite database
        mcp_server_id: MCP server ID
        event_type: Event type ('refresh', 'manual_refresh', 'refresh_failed')
        success: Whether operation succeeded
        error_message: Error message if failed
        old_expires_at: Previous expiration time
        new_expires_at: New expiration time
        triggered_by: What triggered refresh ('proactive', 'reactive_401', 'manual', 'startup')
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO backend_mcp_token_audit
            (mcp_server_id, event_type, success, error_message,
             old_expires_at, new_expires_at, triggered_by, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mcp_server_id,
                event_type,
                1 if success else 0,
                error_message,
                old_expires_at.isoformat() if old_expires_at else None,
                new_expires_at.isoformat() if new_expires_at else None,
                triggered_by,
                datetime.now(timezone.utc).isoformat()
            )
        )

        conn.commit()
        logger.debug(
            f"Token audit logged: server={mcp_server_id}, "
            f"event={event_type}, success={success}, triggered_by={triggered_by}"
        )

    except Exception as e:
        logger.error(f"Failed to log token audit: {e}")
        conn.rollback()

    finally:
        conn.close()


def get_token_audit_logs(
    db_path: str,
    mcp_server_id: Optional[int] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Get token audit logs.

    Args:
        db_path: Path to SQLite database
        mcp_server_id: Filter by MCP server ID (optional)
        limit: Maximum number of logs to return

    Returns:
        List of audit log dicts with server name joined
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if mcp_server_id:
        cursor.execute(
            """
            SELECT a.*, s.name as server_name
            FROM backend_mcp_token_audit a
            JOIN mcp_servers s ON a.mcp_server_id = s.id
            WHERE a.mcp_server_id = ?
            ORDER BY a.timestamp DESC
            LIMIT ?
            """,
            (mcp_server_id, limit)
        )
    else:
        cursor.execute(
            """
            SELECT a.*, s.name as server_name
            FROM backend_mcp_token_audit a
            JOIN mcp_servers s ON a.mcp_server_id = s.id
            ORDER BY a.timestamp DESC
            LIMIT ?
            """,
            (limit,)
        )

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def update_mcp_server_token(
    db_path: str,
    server_id: int,
    access_token: str,
    token_expires_at: datetime,
    refresh_token_hash: Optional[str] = None
) -> None:
    """Update MCP server tokens after refresh.

    Args:
        db_path: Path to SQLite database
        server_id: MCP server ID
        access_token: New access token
        token_expires_at: New expiration time
        refresh_token_hash: New refresh token hash if backend rotated it
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    now = datetime.now(timezone.utc).isoformat()

    try:
        if refresh_token_hash:
            # Backend rotated refresh token - update both
            cursor.execute(
                """
                UPDATE mcp_servers
                SET auth_token = ?,
                    token_expires_at = ?,
                    refresh_token_hash = ?,
                    token_last_refreshed = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (access_token, token_expires_at.isoformat(), refresh_token_hash, now, now, server_id)
            )
        else:
            # Only update access token
            cursor.execute(
                """
                UPDATE mcp_servers
                SET auth_token = ?,
                    token_expires_at = ?,
                    token_last_refreshed = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (access_token, token_expires_at.isoformat(), now, now, server_id)
            )

        rows_affected = cursor.rowcount
        conn.commit()

        if rows_affected > 0:
            logger.info(
                f"Updated tokens for server {server_id}: "
                f"expires_at={token_expires_at.isoformat()}, "
                f"rotated_refresh={refresh_token_hash is not None}"
            )
        else:
            logger.warning(f"No server found with id {server_id} to update tokens")

    except Exception as e:
        logger.error(f"Failed to update server tokens: {e}")
        conn.rollback()
        raise

    finally:
        conn.close()


def get_servers_needing_refresh(
    db_path: str,
    threshold_minutes: int = 5
) -> List[Dict[str, Any]]:
    """Get MCP servers whose tokens will expire soon.

    Args:
        db_path: Path to SQLite database
        threshold_minutes: Refresh if expires within N minutes

    Returns:
        List of server dicts with expiring tokens
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Calculate threshold timestamp
    from datetime import timedelta
    threshold = datetime.now(timezone.utc) + timedelta(minutes=threshold_minutes)

    cursor.execute(
        """
        SELECT * FROM mcp_servers
        WHERE enabled = 1
          AND refresh_token_hash IS NOT NULL
          AND token_expires_at IS NOT NULL
          AND datetime(token_expires_at) <= datetime(?)
        ORDER BY token_expires_at ASC
        """,
        (threshold.isoformat(),)
    )

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]
