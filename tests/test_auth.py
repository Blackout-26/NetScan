"""
tests/test_auth.py
───────────────────
Unit tests for the security and auth service modules.
These test pure logic only — no HTTP or database needed.
"""

import pytest
from app.core.security import (
    hash_password,
    verify_password,
    generate_session_token,
    DEFAULT_USERNAME,
    DEFAULT_PASSWORD,
)


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        h = hash_password("MySecret1")
        assert "MySecret1" not in h

    def test_correct_password_verifies(self):
        h = hash_password("Correct1")
        assert verify_password("Correct1", h) is True

    def test_wrong_password_fails(self):
        h = hash_password("Correct1")
        assert verify_password("Wrong123", h) is False

    def test_same_password_produces_different_hashes(self):
        # Salt must be different each time
        h1 = hash_password("Same1234")
        h2 = hash_password("Same1234")
        assert h1 != h2
        # But both should verify correctly
        assert verify_password("Same1234", h1)
        assert verify_password("Same1234", h2)

    def test_empty_password_does_not_crash(self):
        h = hash_password("")
        assert verify_password("", h) is True
        assert verify_password("x", h) is False

    def test_malformed_hash_returns_false(self):
        assert verify_password("anything", "notahash") is False
        assert verify_password("anything", "") is False


class TestSessionToken:
    def test_token_is_64_chars(self):
        token = generate_session_token()
        assert len(token) == 64

    def test_tokens_are_unique(self):
        tokens = {generate_session_token() for _ in range(100)}
        assert len(tokens) == 100   # no collisions in 100 tries


class TestDefaultCredentials:
    def test_default_password_meets_requirements(self):
        pw = DEFAULT_PASSWORD
        assert len(pw) >= 8
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)

    def test_default_username_not_empty(self):
        assert len(DEFAULT_USERNAME) >= 3
