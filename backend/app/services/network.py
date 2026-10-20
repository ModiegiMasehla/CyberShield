import asyncio
import ipaddress
import platform
import socket
import struct

COMMON_SERVICES = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    5432: "PostgreSQL",
    8000: "HTTP-alt",
    8080: "HTTP-proxy",
}
MAX_PORTS = 1024


def parse_default_gateway(route_table: str) -> str | None:
    """Parse /proc/net/route text and return the default gateway address."""
    for line in route_table.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:  # RTF_GATEWAY
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    return None


def parse_nameservers(resolv_conf: str) -> list[str]:
    servers = []
    for line in resolv_conf.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
    return servers


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _local_ip() -> str:
    # A UDP "connect" only selects a route; no packet is sent.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return "unknown"


def network_info():
    try:
        interfaces = [name for _, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        interfaces = []
    return {
        "hostname": socket.gethostname(),
        "local_ip": _local_ip(),
        "interfaces": interfaces,
        "dns": parse_nameservers(_read("/etc/resolv.conf")),
        "default_gateway": parse_default_gateway(_read("/proc/net/route")) or "not determined",
        "os": platform.platform(),
    }


# Explicit lab ranges: ipaddress.is_private is also True for documentation/test ranges (e.g. 203.0.113.0/24).
LAB_NETWORKS = [
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
]


def validate_lab_target(target: str):
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError("Target must be an IP address in safe lab mode.") from None
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ValueError(
            "Safe scanner does not allow unspecified, multicast, link-local or reserved addresses."
        )
    if not (ip.is_loopback or any(ip in net for net in LAB_NETWORKS)):
        raise ValueError("Safe scanner allows localhost or private-network targets only.")
    return ip


async def scan_ports(target: str, start: int, end: int):
    validate_lab_target(target)
    if end - start + 1 > MAX_PORTS:
        raise ValueError(f"Maximum scan range is {MAX_PORTS} ports.")
    sem = asyncio.Semaphore(64)

    async def check(port):
        async with sem:
            try:
                fut = asyncio.get_running_loop().run_in_executor(None, _check, target, port)
                is_open = await asyncio.wait_for(fut, timeout=0.8)
            except Exception:
                is_open = False
            return {
                "port": port,
                "state": "OPEN" if is_open else "CLOSED",
                "service": COMMON_SERVICES.get(port, "unknown"),
            }

    results = await asyncio.gather(*(check(p) for p in range(start, end + 1)))
    return [r for r in results if r["state"] == "OPEN"]


def _check(target, port):
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((target, port)) == 0
