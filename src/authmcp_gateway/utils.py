"""Utility functions for AuthMCP Gateway."""

from typing import List


def _parse_scopes(scopes_value: str) -> List[str]:
    """Parse OAuth scopes from string (space or comma-separated).

    Args:
        scopes_value: Space or comma-separated scope string

    Returns:
        List of individual scope strings

    Example:
        >>> _parse_scopes("openid profile email")
        ['openid', 'profile', 'email']
        >>> _parse_scopes("openid,profile,email")
        ['openid', 'profile', 'email']
    """
    scopes_value = scopes_value.strip()
    if not scopes_value:
        return []
    parts = [part.strip() for part in scopes_value.replace(",", " ").split()]
    return [part for part in parts if part]
