import threading
import time
from collections import defaultdict, deque

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import settings

DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware:
    """Adds defensive HTTP headers to every response."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope["path"]

        async def send_with_headers(message: Message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                }
                if not path.startswith(DOC_PATHS):
                    extra[b"content-security-policy"] = b"default-src 'none'; frame-ancestors 'none'"
                    extra[b"cache-control"] = b"no-store"
                if settings.is_production:
                    extra[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                existing = {k.lower() for k, _ in headers}
                headers.extend((k, v) for k, v in extra.items() if k not in existing)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class _SlidingWindow:
    def __init__(self):
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self):
        with self.lock:
            self.hits.clear()


limiter = _SlidingWindow()


class RateLimitMiddleware:
    """Per-client sliding-window rate limit; login is limited more strictly."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        client = request.client.host if request.client else "unknown"
        is_login = request.url.path.endswith("/auth/login")
        allowed = limiter.allow(f"all:{client}", settings.rate_limit_per_minute)
        if allowed and is_login:
            allowed = limiter.allow(f"login:{client}", settings.login_rate_limit_per_minute)
        if not allowed:
            response = JSONResponse(
                {"detail": "Too many requests. Please slow down."},
                status_code=429,
                headers={"Retry-After": "60"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
