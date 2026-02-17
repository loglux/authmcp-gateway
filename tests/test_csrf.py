"""Tests for CSRF protection middleware."""

from authmcp_gateway.csrf import generate_csrf_token, verify_csrf_token

SECRET = "test-secret-key-at-least-32-characters-long"


class TestCSRFToken:
    """Unit tests for CSRF token generation and verification."""

    def test_generate_and_verify(self):
        token = generate_csrf_token(SECRET)
        assert verify_csrf_token(token, SECRET)

    def test_different_tokens_are_unique(self):
        t1 = generate_csrf_token(SECRET)
        t2 = generate_csrf_token(SECRET)
        assert t1 != t2
        assert verify_csrf_token(t1, SECRET)
        assert verify_csrf_token(t2, SECRET)

    def test_tampered_token_rejected(self):
        token = generate_csrf_token(SECRET)
        tampered = token[:-4] + "XXXX"
        assert not verify_csrf_token(tampered, SECRET)

    def test_wrong_secret_rejected(self):
        token = generate_csrf_token(SECRET)
        assert not verify_csrf_token(token, "wrong-secret")

    def test_malformed_token_rejected(self):
        assert not verify_csrf_token("no-dot-here", SECRET)
        assert not verify_csrf_token("", SECRET)

    def test_none_token_rejected(self):
        assert not verify_csrf_token(None, SECRET)

    def test_token_format(self):
        token = generate_csrf_token(SECRET)
        parts = token.split(".")
        assert len(parts) == 2
        nonce, sig = parts
        assert len(nonce) == 32  # 16 bytes hex
        assert len(sig) == 64  # SHA256 hex
