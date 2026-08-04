"""Authentication and user management service."""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, UnauthorizedError
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User, UserRole
from app.schemas.auth import LoginRequest
from app.schemas.user import UserCreate, UserUpdate


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------ users
    def create_user(self, data: UserCreate) -> User:
        if self._get_by_username(data.username) is not None:
            raise ConflictError(f"Username '{data.username}' is already taken")
        if self._get_by_email(data.email) is not None:
            raise ConflictError("Email is already registered")
        user = User(
            username=data.username,
            email=str(data.email).lower(),
            password_hash=hash_password(data.password),
            full_name=data.full_name,
            role=data.role,
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_user(self, user_id: str) -> User:
        user = self.db.get(User, user_id)
        if user is None:
            raise NotFoundError("User not found")
        return user

    def list_users(self, offset: int = 0, limit: int = 50) -> tuple[list[User], int]:
        total = self.db.scalar(select(func.count(User.id))) or 0
        query = select(User).order_by(User.created_at)
        users = list(self.db.scalars(query.offset(offset).limit(limit)).all())
        return users, total

    def update_user(self, user_id: str, data: UserUpdate) -> User:
        user = self.get_user(user_id)
        if data.full_name is not None:
            user.full_name = data.full_name
        if data.role is not None:
            user.role = data.role
        if data.is_active is not None:
            user.is_active = data.is_active
        if data.password:
            user.password_hash = hash_password(data.password)
        self.db.commit()
        self.db.refresh(user)
        return user

    # -------------------------------------------------------------- auth flow
    def authenticate(self, request: LoginRequest) -> User:
        user = self._get_by_username(request.username)
        if user is None or not verify_password(request.password, user.password_hash):
            raise UnauthorizedError("Invalid username or password")
        if not user.is_active:
            raise UnauthorizedError("Account is disabled", code="account_disabled")
        user.last_login_at = datetime.now(timezone.utc)
        self.db.commit()
        return user

    def issue_token(self, user: User) -> tuple[str, datetime]:
        expires_at = datetime.now(timezone.utc).timestamp() + 60 * 60 * 24
        token = create_access_token(
            user.id, extra={"username": user.username, "role": user.role.value}
        )
        return token, datetime.fromtimestamp(expires_at, tz=timezone.utc)

    def resolve_token_user(self, subject: str) -> User:
        user = self.db.get(User, subject)
        if user is None or not user.is_active:
            raise UnauthorizedError("Account no longer valid")
        return user

    # --------------------------------------------------------------- internal
    def _get_by_username(self, username: str) -> User | None:
        return self.db.scalar(select(User).where(User.username == username))

    def _get_by_email(self, email: str) -> User | None:
        return self.db.scalar(select(User).where(User.email == email.lower()))


def bootstrap_admin(db: Session) -> None:
    """Create the initial administrator account on first startup."""
    from app.core.config import settings

    existing = db.scalar(
        select(User).where(User.username == settings.first_admin_username)
    )
    if existing is not None:
        return
    admin = User(
        username=settings.first_admin_username,
        email=settings.first_admin_email,
        password_hash=hash_password(settings.first_admin_password),
        full_name="System Administrator",
        role=UserRole.admin,
        is_active=True,
    )
    db.add(admin)
    db.commit()
