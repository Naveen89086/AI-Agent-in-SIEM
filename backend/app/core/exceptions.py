"""Centralized exception hierarchy and FastAPI error handlers.

Converts domain errors into consistent RFC7807-style problem responses.
"""

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class AppError(Exception):
    """Base application error with an HTTP status and stable error code."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "app_error",
        http_status: int = status.HTTP_400_BAD_REQUEST,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.http_status = http_status
        self.details = details


class NotFoundError(AppError):
    def __init__(self, message: str, code: str = "not_found") -> None:
        super().__init__(message, code=code, http_status=status.HTTP_404_NOT_FOUND)


class ConflictError(AppError):
    def __init__(self, message: str, code: str = "conflict") -> None:
        super().__init__(message, code=code, http_status=status.HTTP_409_CONFLICT)


class UnauthorizedError(AppError):
    def __init__(self, message: str = "Authentication required", code: str = "unauthorized") -> None:
        super().__init__(message, code=code, http_status=status.HTTP_401_UNAUTHORIZED)


class ForbiddenError(AppError):
    def __init__(self, message: str = "Insufficient permissions", code: str = "forbidden") -> None:
        super().__init__(message, code=code, http_status=status.HTTP_403_FORBIDDEN)


class ValidationError(AppError):
    def __init__(self, message: str, details: Any = None, code: str = "validation_error") -> None:
        super().__init__(message, code=code, http_status=status.HTTP_422_UNPROCESSABLE_ENTITY, details=details)


class RateLimitError(AppError):
    def __init__(self, message: str = "Rate limit exceeded") -> None:
        super().__init__(message, code="rate_limited", http_status=status.HTTP_429_TOO_MANY_REQUESTS)


def _body(err: AppError) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error": {
            "code": err.code,
            "message": err.message,
            "status": err.http_status,
        }
    }
    if err.details is not None:
        payload["error"]["details"] = err.details
    return payload


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=_body(exc))

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = []
        for item in exc.errors():
            loc = ".".join(str(part) for part in item.get("loc", []))
            errors.append({"field": loc, "message": item.get("msg", "invalid value")})
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request validation failed",
                    "status": status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "details": errors,
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        import logging

        logging.getLogger("siem.api").exception("Unhandled exception")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected error occurred",
                    "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                }
            },
        )
