"""User management endpoints (admin only)."""

from fastapi import APIRouter, Query

from app.api.deps import AdminUser, DbSession
from app.api.responses import Page, paginate
from app.models.user import User
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.auth_service import AuthService

router = APIRouter()


@router.get("", response_model=Page[UserRead])
def list_users(
    admin: AdminUser,
    db: DbSession,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    users, total = AuthService(db).list_users(offset=offset, limit=limit)
    return paginate(users, total, offset, limit)


@router.post("", response_model=UserRead, status_code=201)
def create_user(payload: UserCreate, admin: AdminUser, db: DbSession) -> User:
    return AuthService(db).create_user(payload)


@router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: str, admin: AdminUser, db: DbSession) -> User:
    return AuthService(db).get_user(user_id)


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: str, payload: UserUpdate, admin: AdminUser, db: DbSession
) -> User:
    return AuthService(db).update_user(user_id, payload)
