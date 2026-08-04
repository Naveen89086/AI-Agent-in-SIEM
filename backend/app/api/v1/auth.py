"""Authentication endpoints."""

from fastapi import APIRouter, Depends

from app.api.deps import CurrentUser
from app.schemas.auth import LoginRequest, Token
from app.schemas.user import UserRead
from app.services.auth_service import AuthService
from app.api.deps import DbSession

router = APIRouter()


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, db: DbSession) -> Token:
    service = AuthService(db)
    user = service.authenticate(payload)
    access_token, expires_at = service.issue_token(user)
    return Token(
        access_token=access_token,
        expires_at=expires_at,
        user=UserRead.model_validate(user),
    )


@router.get("/me", response_model=UserRead)
def me(user: CurrentUser) -> UserRead:
    return UserRead.model_validate(user)
