import asyncio, ipaddress, socket
from concurrent.futures import ThreadPoolExecutor

COMMON_SERVICES = {22:"SSH", 53:"DNS", 80:"HTTP", 443:"HTTPS", 5432:"PostgreSQL", 8000:"HTTP-alt", 8080:"HTTP-proxy"}

def network_info():
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = "unknown"
    return {"hostname": hostname, "local_ip": local_ip, "interfaces": [], "dns": [], "default_gateway": "not determined", "os": __import__("platform").platform()}

def validate_lab_target(target: str):
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError("Target must be an IP address in safe lab mode.")
    if not (ip.is_loopback or ip.is_private):
        raise ValueError("Safe scanner allows localhost or private-network targets only.")
    return ip

async def scan_ports(target: str, start: int, end: int):
    validate_lab_target(target)
    if end - start > 1024:
        raise ValueError("Maximum scan range is 1024 ports.")
    sem = asyncio.Semaphore(64)
    async def check(port):
        async with sem:
            try:
                fut = asyncio.get_running_loop().run_in_executor(None, _check, target, port)
                is_open = await asyncio.wait_for(fut, timeout=0.8)
                return {"port": port, "state": "OPEN" if is_open else "CLOSED", "service": COMMON_SERVICES.get(port, "unknown")}
            except Exception:
                return {"port": port, "state": "CLOSED", "service": COMMON_SERVICES.get(port, "unknown")}
    return [r for r in await asyncio.gather(*(check(p) for p in range(start, end+1))) if r["state"] == "OPEN"]

def _check(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((target, port)) == 0
