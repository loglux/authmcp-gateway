"""Password hashing and validation utilities."""

import re
from typing import Optional, Tuple

from passlib.context import CryptContext

from src.config import AuthConfig

# Password context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password to hash

    Returns:
        str: Bcrypt hashed password
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Bcrypt hash to compare against

    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Invalid hash format or verification error
        return False


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
