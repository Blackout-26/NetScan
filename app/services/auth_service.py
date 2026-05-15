"""
app/services/auth_service.py
──────────────────────────────
Business logic for the single-admin authentication system.

Flow
────
1. On first startup, seed the default admin account if no user exists.
2. Admin logs in with default credentials (admin / NetScan@Admin1).
3. System detects is_first_login=True and forces a credential change.
4. Admin sets new username + password — is_first_login is cleared.
5. All subsequent requests carry the session token in an HttpOnly cookie.
6. Admin can change credentials again at any time from the settings page.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.security import (
    DEFAULT_PASSWORD,
    DEFAULT_USERNAME,
    generate_session_token,
    hash_password,
    verify_password,
)
from app.models.user import User

logger = get_logger(__name__)


# ── Seeding ────────────────────────────────────────────────────────────────────

async def seed_default_admin(db: AsyncSession) -> None:
    """
    Create the default admin account if no user row exists.
    Called once at application startup.
    """
    result = await db.execute(select(User))
    existing = result.scalar_one_or_none()
    if existing is None:
        admin = User(
            username=DEFAULT_USERNAME,
            password_hash=hash_password(DEFAULT_PASSWORD),
            is_first_login=True,
        )
        db.add(admin)
        await db.flush()
        logger.info(
            "Default admin account created. "
            "Username: '%s' — CHANGE THIS ON FIRST LOGIN.", DEFAULT_USERNAME
        )
    else:
        logger.debug("Admin account already exists — skipping seed.")


# ── Authentication ─────────────────────────────────────────────────────────────

async def authenticate(
    db: AsyncSession,
    username: str,
    password: str,
) -> Optional[User]:
    """
    Verify credentials. Returns the User on success, None on failure.
    On success, generates a fresh session token and records last_login_at.
    """
    result = await db.execute(select(User).where(User.username == username))
    user: Optional[User] = result.scalar_one_or_none()

    if user is None or not verify_password(password, user.password_hash):
        logger.warning("Failed login attempt for username='%s'", username)
        return None

    user.session_token = generate_session_token()
    user.last_login_at = datetime.now(tz=timezone.utc)
    await db.flush()
    logger.info("Successful login for username='%s'", username)
    return user


# ── Session lookup ─────────────────────────────────────────────────────────────

async def get_user_by_token(
    db: AsyncSession,
    token: str,
) -> Optional[User]:
    """Return the user matching the session token, or None if invalid/expired."""
    if not token:
        return None
    result = await db.execute(
        select(User).where(User.session_token == token)
    )
    return result.scalar_one_or_none()


# ── Logout ─────────────────────────────────────────────────────────────────────

async def logout(db: AsyncSession, user: User) -> None:
    """Invalidate the current session token."""
    user.session_token = None
    await db.flush()
    logger.info("User '%s' logged out.", user.username)


# ── Credential update ──────────────────────────────────────────────────────────

async def update_credentials(
    db: AsyncSession,
    user: User,
    new_username: str,
    new_password: str,
) -> tuple[bool, str]:
    """
    Change the admin's username and password.

    Returns (success: bool, message: str).
    Validates that:
      - new_username is not empty
      - new_password meets minimum strength requirements
      - new credentials are different from defaults (on first login)
    """
    new_username = new_username.strip()
    new_password = new_password.strip()

    if not new_username:
        return False, "Username cannot be empty."

    if len(new_username) < 3:
        return False, "Username must be at least 3 characters."

    if len(new_password) < 8:
        return False, "Password must be at least 8 characters."

    if not any(c.isupper() for c in new_password):
        return False, "Password must contain at least one uppercase letter."

    if not any(c.isdigit() for c in new_password):
        return False, "Password must contain at least one digit."

    # On first login, reject if still using the defaults
    if user.is_first_login:
        if new_username == DEFAULT_USERNAME and new_password == DEFAULT_PASSWORD:
            return False, "You must choose credentials different from the defaults."

    # Check username collision (only matters if username is actually changing)
    if new_username != user.username:
        conflict = await db.execute(
            select(User).where(User.username == new_username)
        )
        if conflict.scalar_one_or_none() is not None:
            return False, "That username is already taken."

    user.username = new_username
    user.password_hash = hash_password(new_password)
    user.is_first_login = False
    # Issue a fresh session token after credential change
    user.session_token = generate_session_token()
    await db.flush()

    logger.info("Admin credentials updated. New username='%s'", new_username)
    return True, "Credentials updated successfully."
