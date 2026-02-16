"""Encryption utilities for sensitive backend token storage.

Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) with a key
derived from the application's JWT secret.
"""

import base64
import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_fernet: Optional[Fernet] = None


def initialize_crypto(secret_key: str) -> None:
    """Initialize Fernet encryption using JWT secret key.

    Derives a 32-byte key from the secret using SHA256, then base64-encodes
    it for Fernet (which requires a URL-safe base64-encoded 32-byte key).

    Args:
        secret_key: Application secret key (e.g., JWT_SECRET_KEY)
    """
    global _fernet
    key_bytes = hashlib.sha256(secret_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    _fernet = Fernet(fernet_key)
    logger.info("Token encryption initialized")


def encrypt_token(plaintext: str) -> str:
    """Encrypt a token string.

    Args:
        plaintext: Token to encrypt

    Returns:
        Fernet-encrypted ciphertext (base64-encoded string)

    Raises:
        RuntimeError: If crypto not initialized
    """
    if _fernet is None:
        raise RuntimeError("Crypto not initialized. Call initialize_crypto() first.")
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a token string.

    Args:
        ciphertext: Fernet-encrypted token

    Returns:
        Decrypted plaintext token

    Raises:
        RuntimeError: If crypto not initialized
        cryptography.fernet.InvalidToken: If decryption fails
    """
    if _fernet is None:
        raise RuntimeError("Crypto not initialized. Call initialize_crypto() first.")
    return _fernet.decrypt(ciphertext.encode()).decode()


def decrypt_token_safe(ciphertext: str) -> str:
    """Decrypt a token, falling back to plaintext if decryption fails.

    This handles backward compatibility with tokens stored before encryption
    was enabled. Legacy plaintext tokens will pass through unchanged.

    Args:
        ciphertext: Encrypted token or legacy plaintext token

    Returns:
        Decrypted or original plaintext token
    """
    if not ciphertext:
        return ciphertext
    if _fernet is None:
        return ciphertext
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        # Not a Fernet token — return as-is (legacy plaintext)
        return ciphertext
