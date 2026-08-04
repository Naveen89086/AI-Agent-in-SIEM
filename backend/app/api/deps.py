"""FastAPI dependencies: DB session, current user, RBAC."""

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, RateLimitError
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User, UserRole
from app.services.auth_service import AuthService

DbSession = Annotated[Session, Depends(get_db)]


def _bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        from app.core.exceptions import UnauthorizedError

        raise UnauthorizedError("Missing bearer token")
    return auth.split(" ", 1)[1].strip()


def get_current_user(
    request: Request,
    db: DbSession,
    token: str = Depends(_bearer_token),
) -> User:
    payload = decode_access_token(token)
    return AuthService(db).resolve_token_user(payload["sub"])


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: UserRole):
    def checker(user: CurrentUser) -> User:
        if user.role not in roles:
            raise ForbiddenError("You do not have permission to perform this action")
        return user

    return checker


AdminUser = Annotated[User, Depends(require_roles(UserRole.admin))]
AnalystOrAdmin = Annotated[User, Depends(require_roles(UserRole.analyst, UserRole.admin))]


def enforce_rate_limit(request: Request) -> None:
    """Simple in-memory per-IP rate limiter (token bucket)."""
    from app.core.config import settings

    window_seconds = 60
    now = int(__import__("time").time())
    key = f"rl:{request.client.host}:{now // window_seconds}"
    cache = getattr(request.app.state, "rate_cache", None)
    if cache is None:
        from collections import defaultdict

        cache = defaultdict(int)
        request.app.state.rate_cache = cache
    cache[key] += 1
    # prune old windows periodically
    if len(cache) > 5000:
        for k in [k for k in cache if int(k.split(":")[-2]) < now // window_seconds - 1]:
            cache.pop(k, None)
    if cache[key] > settings.rate_limit_per_minute:
        raise RateLimitError()
