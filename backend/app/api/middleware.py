"""HTTP middleware: request IDs and access logging (module 7)."""

import logging
import time
import uuid

log = logging.getLogger("siem.api.access")


class RequestContextMiddleware:
    """Assign a request id, expose it on the response and log an access line."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        headers = list(scope.get("headers", []))
        headers.append((b"x-request-id", request_id.encode()))
        scope["headers"] = headers

        started = time.perf_counter()
        status = [0]

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                status[0] = message["status"]
                for key, value in message.get("headers", []):
                    if key == b"x-request-id":
                        break
                else:
                    message["headers"] = message.get("headers", []) + [
                        (b"x-request-id", request_id.encode())
                    ]
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            log.info(
                "request id=%s method=%s path=%s status=%s duration_ms=%.1f",
                request_id,
                scope.get("method"),
                scope.get("path"),
                status[0],
                elapsed_ms,
            )
