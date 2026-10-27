"""Refuse oversized request bodies BEFORE they are stored.

Without this, the server first receives and spools a whole upload to disk and
only then notices that it is too big. Two checks are made:
  1. The declared Content-Length: refused immediately, nothing is read.
  2. The bytes actually received: covers clients that send no Content-Length.
"""

from starlette.responses import JSONResponse

TOO_LARGE_DETAIL = "Request body is too large."


class _BodyTooLarge(Exception):
    pass


def _declared_length(scope):
    for name, value in scope["headers"]:
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _declared_length(scope)
        if declared is not None and declared > self.max_bytes:
            await self._reject(scope, receive, send)
            return

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if response_started:
                raise
            await self._reject(scope, receive, send)

    async def _reject(self, scope, receive, send):
        response = JSONResponse({"detail": TOO_LARGE_DETAIL}, status_code=413)
        await response(scope, receive, send)