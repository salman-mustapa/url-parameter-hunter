"""Bound request bodies and login attempts without buffering SSE responses."""
import asyncio
import time
from collections import OrderedDict, deque

from starlette.datastructures import Headers, URL
from starlette.responses import JSONResponse

from app.core.config import settings


class HTTPSecurityMiddleware:
    def __init__(self, app):
        self.app = app
        self.auth_attempts = OrderedDict()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        path = scope["path"]

        async def secured_send(message):
            if message["type"] == "http.response.start":
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", b"frame-ancestors 'none'; object-src 'none'; base-uri 'self'"),
                ]
                if path.startswith("/api/"):
                    extra.append((b"cache-control", b"no-store"))
                message = {**message, "headers": list(message.get("headers", [])) + extra}
            await send(message)

        async def reject(code, detail, response_headers=None):
            await JSONResponse({"detail": detail}, status_code=code, headers=response_headers)(scope, receive, secured_send)

        unsafe = scope["method"] not in {"GET", "HEAD", "OPTIONS"}
        callback = path.startswith("/api/oob/")
        if unsafe and not callback and not headers.get("authorization", "").startswith("Bearer "):
            origin = headers.get("origin")
            url = URL(scope=scope)
            local_origin = f"{url.scheme}://{url.netloc}"
            allowed = {value.strip() for value in settings.cors_origins.split(",") if value.strip() != "*"}
            if (origin and origin != local_origin and origin not in allowed) or (not origin and headers.get("sec-fetch-site") == "cross-site"):
                return await reject(403, "Cross-origin request rejected")

        if unsafe and path in {"/api/auth/login", "/api/auth/register"}:
            now = time.monotonic()
            client = (scope.get("client") or ("unknown",))[0]
            attempts = self.auth_attempts.setdefault(client, deque())
            while attempts and attempts[0] <= now - 60:
                attempts.popleft()
            self.auth_attempts.move_to_end(client)
            while len(self.auth_attempts) > 4096:
                self.auth_attempts.popitem(last=False)
            if len(attempts) >= 20:
                return await reject(429, "Terlalu banyak percobaan. Coba lagi dalam satu menit.", {"Retry-After": "60"})
            attempts.append(now)

        if unsafe and path.startswith("/api/"):
            limit = 16_384 if path.startswith("/api/auth/") else 1_048_576
            try:
                content_length = int(headers.get("content-length", "0"))
            except ValueError:
                return await reject(400, "Invalid Content-Length")
            if content_length > limit:
                return await reject(413, "Request body too large")
            body = bytearray()
            deadline = time.monotonic() + 15
            while True:
                try:
                    message = await asyncio.wait_for(receive(), timeout=max(.01, deadline - time.monotonic()))
                except TimeoutError:
                    return await reject(408, "Request body timeout")
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > limit:
                    return await reject(413, "Request body too large")
                if not message.get("more_body", False):
                    break
            body_sent = False

            async def bounded_receive():
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, bounded_receive, secured_send)
        else:
            await self.app(scope, receive, secured_send)
