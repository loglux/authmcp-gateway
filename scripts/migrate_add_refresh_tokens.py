"""Migration: Add refresh token support to backend MCP servers.

This migration adds:
1. New columns to mcp_servers table for refresh token support
2. backend_mcp_token_audit table for tracking refresh operations
3. Indexes for performance

The migration is idempotent - safe to run multiple times.
"""

import sqlite3
import sys
import logging
from pathlib import Path


logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def migrate(db_path: str) -> None:
    """Run migration to add refresh token fields.

    Args:
        db_path: Path to SQLite database file

    Raises:
        SystemExit: If migration fails
    """
    logger.info(f"Starting migration on {db_path}")

    if not Path(db_path).exists():
        logger.error(f"Database file not found: {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # === STEP 1: Add columns to mcp_servers table ===

        logger.info("Checking mcp_servers table...")
        cursor.execute("PRAGMA table_info(mcp_servers)")
        columns = [row[1] for row in cursor.fetchall()]

        new_columns = {
            'refresh_token_hash': 'TEXT',
            'token_expires_at': 'TIMESTAMP',
            'token_last_refreshed': 'TIMESTAMP',
            'refresh_endpoint': "TEXT DEFAULT '/oauth/token'"
        }

        columns_added = False
        for column_name, column_type in new_columns.items():
            if column_name not in columns:
                logger.info(f"Adding column: {column_name}")
                cursor.execute(f"ALTER TABLE mcp_servers ADD COLUMN {column_name} {column_type}")
                columns_added = True
            else:
                logger.debug(f"Column already exists: {column_name}")

        if columns_added:
            logger.info("✓ New columns added to mcp_servers")
        else:
            logger.info("✓ All columns already exist in mcp_servers")

        # === STEP 2: Create index for token expiry queries ===

        logger.info("Checking indexes...")
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='index' AND name='idx_mcp_servers_token_expiry'
        """)

        if not cursor.fetchone():
            logger.info("Creating index: idx_mcp_servers_token_expiry")
            cursor.execute("""
                CREATE INDEX idx_mcp_servers_token_expiry
                ON mcp_servers(token_expires_at)
                WHERE token_expires_at IS NOT NULL AND enabled = 1
            """)
            logger.info("✓ Index created")
        else:
            logger.info("✓ Index already exists")

        # === STEP 3: Create backend_mcp_token_audit table ===

        logger.info("Checking backend_mcp_token_audit table...")
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='backend_mcp_token_audit'
        """)

        if not cursor.fetchone():
            logger.info("Creating backend_mcp_token_audit table...")
            cursor.execute("""
                CREATE TABLE backend_mcp_token_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mcp_server_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    success BOOLEAN DEFAULT 1,
                    error_message TEXT,
                    old_expires_at TIMESTAMP,
                    new_expires_at TIMESTAMP,
                    triggered_by TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE
                )
            """)
            logger.info("✓ Table created")

            # Create indexes for audit table
            logger.info("Creating audit table indexes...")
            cursor.execute("""
                CREATE INDEX idx_backend_token_audit_server
                ON backend_mcp_token_audit(mcp_server_id)
            """)
            cursor.execute("""
                CREATE INDEX idx_backend_token_audit_timestamp
                ON backend_mcp_token_audit(timestamp)
            """)
            logger.info("✓ Audit table indexes created")
        else:
            logger.info("✓ Audit table already exists")

        # === STEP 4: Commit changes ===

        conn.commit()
        logger.info("=" * 60)
        logger.info("✓ Migration completed successfully")
        logger.info("=" * 60)

        # === STEP 5: Verify migration ===

        logger.info("\nVerifying migration...")

        # Check mcp_servers columns
        cursor.execute("PRAGMA table_info(mcp_servers)")
        current_columns = [row[1] for row in cursor.fetchall()]
        for col in new_columns.keys():
            if col in current_columns:
                logger.info(f"  ✓ Column exists: {col}")
            else:
                logger.error(f"  ✗ Missing column: {col}")

        # Check audit table
        cursor.execute("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name='backend_mcp_token_audit'
        """)
        if cursor.fetchone()[0] == 1:
            logger.info("  ✓ Audit table exists")
        else:
            logger.error("  ✗ Audit table missing")

        # Check indexes
        cursor.execute("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='index' AND name LIKE 'idx_%token%'
        """)
        index_count = cursor.fetchone()[0]
        logger.info(f"  ✓ Found {index_count} token-related indexes")

        logger.info("\n✅ Migration verification passed")

    except Exception as e:
        conn.rollback()
        logger.error("=" * 60)
        logger.error(f"✗ Migration failed: {e}")
        logger.error("=" * 60)
        logger.error("\nRolling back changes...")
        sys.exit(1)

    finally:
        conn.close()


def show_usage():
    """Display usage information."""
    print("""
Usage: python migrate_add_refresh_tokens.py [DB_PATH]

Arguments:
  DB_PATH    Path to SQLite database (default: data/auth.db)

Examples:
  python migrate_add_refresh_tokens.py
  python migrate_add_refresh_tokens.py /app/data/auth.db
  python migrate_add_refresh_tokens.py /custom/path/database.db

This migration adds refresh token support to backend MCP servers.
It is idempotent - safe to run multiple times.
    """)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        show_usage()
        sys.exit(0)

    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/auth.db"
    migrate(db_path)
