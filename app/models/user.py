"""
app/models/user.py
───────────────────
Single-admin user model.
NetScan supports exactly one admin account — no multi-user system.

Columns
───────
id               : PK
username         : login name (unique)
password_hash    : PBKDF2-HMAC-SHA256 hash (salt$key)
session_token    : current active session token (NULL = logged out)
is_first_login   : True until the admin changes the default credentials
created_at       : account creation timestamp
last_login_at    : last successful login timestamp
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    session_token: Mapped[Optional[str]] = mapped_column(String(128), unique=True)
    is_first_login: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<User username={self.username!r} first_login={self.is_first_login}>"
