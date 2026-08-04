"""Ingest endpoint authentication.

Two modes, controlled by `INGEST_API_KEY`:
  1. Key mode (recommended for agents): client sends `X-API-Key` header.
  2. User mode (default in dev): client presents a standard JWT bearer token.
"""

from typing import Annotated

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.exceptions import UnauthorizedError
from app.core.security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def verify_ingest_auth(
    x_api_key: str | None = Header(default=None),
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> None:
    if settings.ingest_api_key:
        if not x_api_key or x_api_key != settings.ingest_api_key:
            raise UnauthorizedError("Invalid or missing API key", code="invalid_api_key")
        return
    # No key configured: fall back to a valid user JWT.
    if credentials is None or not credentials.credentials:
        raise UnauthorizedError("Authentication required")
    payload = decode_access_token(credentials.credentials)
    if not payload.get("sub"):
        raise UnauthorizedError("Invalid token")
