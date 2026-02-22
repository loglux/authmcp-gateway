"""Password hashing and validation utilities."""

import re
from typing import Optional, Tuple

import bcrypt

from authmcp_gateway.config import AuthConfig


def _parse_bcrypt_cost(hashed_password: str) -> Optional[int]:
    """Return bcrypt cost factor from hash (e.g. 12), or None if unknown."""
    try:
        parts = hashed_password.split("$")
        if len(parts) < 4:
            return None
        return int(parts[2])
    except Exception:
        return None


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password to hash

    Returns:
        str: Bcrypt hashed password (UTF-8)
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Bcrypt hash to compare against

    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        # Invalid hash format or verification error
        return False


def verify_password_with_rehash(
    plain_password: str, hashed_password: str
) -> Tuple[bool, Optional[str]]:
    """Verify password and optionally return upgraded hash.

    Rehash is triggered when verification succeeds but hash parameters
    do not match current defaults (bcrypt $2b$ with cost>=12).
    """
    is_valid = verify_password(plain_password, hashed_password)
    if not is_valid:
        return False, None

    needs_rehash = not hashed_password.startswith("$2b$")
    cost = _parse_bcrypt_cost(hashed_password)
    if cost is not None and cost < 12:
        needs_rehash = True

    if needs_rehash:
        return True, hash_password(plain_password)

    return True, None


def validate_password_strength(password: str, config: AuthConfig) -> Tuple[bool, Optional[str]]:
    """Validate password meets strength requirements.

    Args:
        password: Password to validate
        config: Authentication configuration with password policy

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
            - (True, None) if password is valid
            - (False, "error message") if password is invalid
    """
    # Check minimum length
    if len(password) < config.password_min_length:
        return False, f"Password must be at least {config.password_min_length} characters long"

    # Check for uppercase letter
    if config.password_require_uppercase:
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"

    # Check for lowercase letter
    if config.password_require_lowercase:
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"

    # Check for digit
    if config.password_require_digit:
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit"

    # Check for special character
    if config.password_require_special:
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
            return False, "Password must contain at least one special character"

    return True, None


def is_password_valid(password: str, config: AuthConfig) -> bool:
    """Check if password is valid without returning error message.

    Args:
        password: Password to validate
        config: Authentication configuration with password policy

    Returns:
        bool: True if password is valid, False otherwise
    """
    is_valid, _ = validate_password_strength(password, config)
    return is_valid
