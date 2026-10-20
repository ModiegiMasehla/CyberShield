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
TOTAL_TIMEOUT_SECONDS = 15

# Cloud metadata / internal control endpoints that are not covered by is_link_local.
EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "100.64.0.0/10",  # carrier-grade NAT, includes Alibaba Cloud metadata 100.100.100.200
        "168.63.129.16/32",  # Azure wire server
        "fd00:ec2::254/128",  # AWS IMDS over IPv6
    )
]


class UnsafeTargetError(ValueError):
    pass


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:169.254.169.254 must be judged as the IPv4 address it really is
    if ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return True
    return any(ip in net for net in EXTRA_BLOCKED_NETWORKS if ip.version == net.version)


async def resolve_safe_address(url: str) -> str:
    """Validate the URL and return the single IP address that the caller must connect to.

    Connecting to this exact address (instead of letting the HTTP client resolve the name again) closes the
    DNS-rebinding window between "check" and "use".
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeTargetError("Only HTTP(S) URLs with a hostname are allowed.")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM
        )
    except (socket.gaierror, UnicodeError):
        raise UnsafeTargetError("Host could not be resolved.") from None
    addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    if not addresses or any(_is_blocked(a) for a in addresses):
        raise UnsafeTargetError("Target resolves to a blocked address range.")
    return str(addresses[0])


async def validate_url(url: str) -> None:
    await resolve_safe_address(url)


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


async def _fetch_headers(client: httpx.AsyncClient, url: str):
    """GET the URL pinned to its validated IP; returns (redirect_location|None, status, headers, cookies)."""
    address = await resolve_safe_address(url)
    parsed = urlparse(url)
    host_header = parsed.hostname if ":" not in parsed.hostname else f"[{parsed.hostname}]"
    if parsed.port:
        host_header += f":{parsed.port}"
    pinned = httpx.URL(url).copy_with(host=address, userinfo=b"")
    extensions = {"sni_hostname": parsed.hostname} if parsed.scheme == "https" else {}
    async with client.stream("GET", pinned, headers={"Host": host_header}, extensions=extensions) as r:
        # Only the headers are needed; leaving the block closes the connection without reading the body.
        location = r.headers.get("location") if r.is_redirect else None
        return location, r.status_code, dict(r.headers), r.headers.get_list("set-cookie")


async def check_headers(url: str):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
        current = url
        async with asyncio.timeout(TOTAL_TIMEOUT_SECONDS):
            for _ in range(MAX_REDIRECTS + 1):
                location, status, raw_headers, set_cookies = await _fetch_headers(client, current)
                if location:
                    current = urljoin(current, location)
                    continue
                break
            else:
                raise UnsafeTargetError("Too many redirects.")
    headers = {k.lower(): v for k, v in raw_headers.items()}
    rows = [
        {"header": h, "status": "PRESENT" if h in headers else "MISSING", "why": why}
        for h, why in SECURITY_HEADERS.items()
    ]
    return {
        "url": current,
        "status_code": status,
        "https": urlparse(current).scheme == "https",
        "headers": rows,
        "cookies": [parse_cookie(v) for v in set_cookies],
        "server": headers.get("server", "not disclosed"),
    }
