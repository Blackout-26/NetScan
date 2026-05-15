"""
app/core/deps.py
─────────────────
FastAPI dependencies for authentication.

Every protected API route and HTML page includes:
    current_user: User = Depends(require_auth)

This reads the HttpOnly session cookie, validates the token against the DB,
and either returns the User or raises a 401/redirect response.
"""

from __future__ import annotations

from typing import Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.services.auth_service import get_user_by_token

COOKIE_NAME = "netscan_session"


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Read the session cookie and return the matching User, or None.
    Does NOT raise — use require_auth for protected routes.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return await get_user_by_token(db, token)


async def require_auth(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency for protected API routes.
    Returns the current User or raises HTTP 401.
    """
    user = await get_current_user(request, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please log in.",
        )
    return user


async def require_auth_redirect(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency for HTML page routes.
    Returns the current User or REDIRECTS to /login (browser-friendly).
    """
    user = await get_current_user(request, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": f"/login?next={request.url.path}"},
        )
    return user
