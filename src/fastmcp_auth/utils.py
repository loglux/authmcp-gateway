"""Utility functions for RAG MCP Server."""

import os
from typing import List


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse boolean from environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> List[str]:
    """Parse comma-separated list from environment variable."""
    value = os.getenv(name, "").strip()
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_scopes(scopes_value: str) -> List[str]:
    """Parse OAuth scopes from string (space or comma-separated)."""
    scopes_value = scopes_value.strip()
    if not scopes_value:
        return []
    parts = [part.strip() for part in scopes_value.replace(",", " ").split()]
    return [part for part in parts if part]
