import asyncio
import ipaddress
import platform
import socket

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


def network_info():
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = "unknown"
    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "interfaces": [],
        "dns": [],
        "default_gateway": "not determined",
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
