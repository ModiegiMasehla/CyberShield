import logging
import re
import threading
import time
import uuid
from collections import defaultdict, deque

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import settings

DOC_PATHS = ("/docs", "/redoc", "/openapi.json")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
access_logger = logging.getLogger("cybershield.access")


class RequestContextMiddleware:
    """Assigns a request id (echoed in `X-Request-ID`) and writes one access-log line per request.

    Only method, path, status, duration, client and id are logged: never query strings, headers or bodies.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = Request(scope).headers.get("x-request-id", "")
        request_id = incoming if REQUEST_ID_RE.fullmatch(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        status = 500

        async def send_with_id(message: Message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            client = scope["client"][0] if scope.get("client") else "unknown"
            access_logger.info(
                "request_id=%s method=%s path=%s status=%s duration_ms=%.1f client=%s",
                request_id,
                scope["method"],
                scope["path"],
                status,
                (time.perf_counter() - started) * 1000,
                client,
            )


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
    MAX_KEYS = 50_000

    def __init__(self):
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _sweep(self, now: float, window: float) -> None:
        """Drop clients with no hits inside the window so memory stays bounded."""
        for key in [k for k, q in self.hits.items() if not q or now - q[-1] > window]:
            del self.hits[key]
        self._last_sweep = now

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self.lock:
            if now - self._last_sweep > window or len(self.hits) > self.MAX_KEYS:
                self._sweep(now, window)
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
