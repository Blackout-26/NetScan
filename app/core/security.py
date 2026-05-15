"""
app/core/security.py
─────────────────────
Password hashing and verification using PBKDF2-HMAC-SHA256.
No extra dependencies — uses Python's built-in hashlib.
"""

import hashlib
import hmac
import os
import secrets


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using PBKDF2-HMAC-SHA256 with a random salt.
    Returns a string in the format:  salt_hex$hash_hex
    """
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=260_000,   # OWASP 2023 recommendation
    )
    return salt.hex() + "$" + key.hex()


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored hash (salt$hash format).
    Uses hmac.compare_digest to prevent timing attacks.
    """
    try:
        salt_hex, key_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        stored_key = bytes.fromhex(key_hex)
    except (ValueError, AttributeError):
        return False

    candidate = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=plaintext.encode("utf-8"),
        salt=salt,
        iterations=260_000,
    )
    return hmac.compare_digest(candidate, stored_key)


# ── Session tokens ─────────────────────────────────────────────────────────────

def generate_session_token() -> str:
    """Generate a cryptographically secure 64-character session token."""
    return secrets.token_hex(32)


# ── Default credentials (seeded on first run) ─────────────────────────────────

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "NetScan@Admin1"   # must be changed on first login
