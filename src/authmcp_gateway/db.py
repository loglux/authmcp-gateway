"""Unified SQLite connection context manager."""

import logging
import os
import sqlite3
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)


@contextmanager
def get_db(db_path: str, row_factory: Optional[type] = sqlite3.Row):
    """Context manager for SQLite connections with proper lifecycle.

    - Creates parent directories if they don't exist (safe for first-run)
    - Default row_factory=sqlite3.Row (pass None for raw tuples)
    - Auto-commit on clean exit, rollback on exception
    - Always closes the connection

    Args:
        db_path: Path to SQLite database file
        row_factory: Row factory. Defaults to sqlite3.Row.
                     Pass None for raw tuples.

    Yields:
        sqlite3.Connection
    """
    if not os.path.isabs(db_path):
        db_path = os.path.abspath(db_path)

    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    if row_factory is not None:
        conn.row_factory = row_factory
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
