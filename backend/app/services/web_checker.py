import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx

SECURITY_HEADERS = {
    "content-security-policy": "Controls executable content sources.",
    "strict-transport-security": "Forces browsers to prefer HTTPS.",
    "x-content-type-options": "Reduces MIME-sniffing risks.",
    "x-frame-options": "Helps prevent clickjacking.",
    "referrer-policy": "Controls referrer information leakage.",
    "permissions-policy": "Restricts browser capabilities.",
}
MAX_REDIRECTS = 3


class UnsafeTargetError(ValueError):
    pass


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved


async def validate_url(url: str) -> None:
    """Reject non-HTTP(S) URLs and hosts that resolve to link-local/metadata/unspecified addresses."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeTargetError("Only HTTP(S) URLs with a hostname are allowed.")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise UnsafeTargetError("Host could not be resolved.") from None
    for info in infos:
        if _is_blocked(ipaddress.ip_address(info[4][0])):
            raise UnsafeTargetError("Target resolves to a blocked address range.")


def parse_cookie(value: str) -> dict:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": "samesite" in attrs,
    }


async def check_headers(url: str):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            await validate_url(current)
            r = await client.get(current)
            if r.is_redirect and r.headers.get("location"):
                current = urljoin(current, r.headers["location"])
                continue
            break
        else:
            raise UnsafeTargetError("Too many redirects.")
    headers = {k.lower(): v for k, v in r.headers.items()}
    rows = [
        {"header": h, "status": "PRESENT" if h in headers else "MISSING", "why": why}
        for h, why in SECURITY_HEADERS.items()
    ]
    cookies = [parse_cookie(v) for v in r.headers.get_list("set-cookie")]
    return {
        "url": str(r.url),
        "status_code": r.status_code,
        "https": r.url.scheme == "https",
        "headers": rows,
        "cookies": cookies,
        "server": headers.get("server", "not disclosed"),
    }
