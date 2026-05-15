"""
app/api/routes/auth.py
───────────────────────
Authentication endpoints:

  POST /api/v1/auth/login          — validate credentials, set session cookie
  POST /api/v1/auth/logout         — clear session cookie
  GET  /api/v1/auth/me             — return current user info
  POST /api/v1/auth/update-credentials — change username + password
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import COOKIE_NAME, require_auth
from app.database.session import get_db
from app.models.user import User
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ── Request / Response schemas ─────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    message: str
    is_first_login: bool
    username: str


class UpdateCredentialsRequest(BaseModel):
    new_username: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=1)
    confirm_password: str = Field(..., min_length=1)


class UserInfoResponse(BaseModel):
    username: str
    is_first_login: bool
    last_login_at: str | None


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse, summary="Admin login")
async def login(
    payload: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    user = await auth_service.authenticate(db, payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Set HttpOnly cookie — JS cannot read this, preventing XSS token theft
    response.set_cookie(
        key=COOKIE_NAME,
        value=user.session_token,
        httponly=True,
        samesite="lax",
        secure=False,   # set True in production behind HTTPS
        max_age=60 * 60 * 8,  # 8-hour session
    )

    return LoginResponse(
        message="Login successful.",
        is_first_login=user.is_first_login,
        username=user.username,
    )


@router.post("/logout", summary="Admin logout")
async def logout(
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> dict:
    await auth_service.logout(db, current_user)
    response.delete_cookie(COOKIE_NAME)
    return {"message": "Logged out successfully."}


@router.get("/me", response_model=UserInfoResponse, summary="Current user info")
async def me(current_user: User = Depends(require_auth)) -> UserInfoResponse:
    return UserInfoResponse(
        username=current_user.username,
        is_first_login=current_user.is_first_login,
        last_login_at=(
            current_user.last_login_at.isoformat()
            if current_user.last_login_at else None
        ),
    )


@router.post(
    "/update-credentials",
    summary="Change admin username and password",
)
async def update_credentials(
    payload: UpdateCredentialsRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth),
) -> dict:
    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match.",
        )

    success, message = await auth_service.update_credentials(
        db=db,
        user=current_user,
        new_username=payload.new_username,
        new_password=payload.new_password,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )

    # Re-issue the session cookie with the new token
    response.set_cookie(
        key=COOKIE_NAME,
        value=current_user.session_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 8,
    )

    return {"message": message}
