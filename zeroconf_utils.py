import socket
import threading
import time
import os
import re
import subprocess
from typing import Optional, List

try:
    import zeroconf as zc
    _ZEROCONF_AVAILABLE = True
except ImportError:
    zc = None
    _ZEROCONF_AVAILABLE = False
    print("WARNING: zeroconf not installed — network discovery disabled. Use env-var fallbacks.")

ADVERTISED_HOSTNAME = os.environ.get("ADVERTISED_HOSTNAME", socket.gethostname() + ".local")


def get_all_ips() -> List[str]:
    ips = []
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True)
        for m in re.finditer(r"IPv4 Address[^:]*:\s*([0-9.]+)", out.stdout, re.I):
            ip = m.group(1)
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    if not ips:
        ips.append("127.0.0.1")
    return ips


def get_my_ip() -> str:
    ips = get_all_ips()
    return ips[0] if ips else "127.0.0.1"


def advertise_service(service_type: str, name: str, port: int,
                      hostname: str = "", properties: dict = None):
    if not _ZEROCONF_AVAILABLE:
        return None
    z = zc.Zeroconf()
    all_ips = get_all_ips()
    if not hostname:
        hostname = ADVERTISED_HOSTNAME
    fq_type = service_type if service_type.endswith(".local.") else f"{service_type}.local."
    info = zc.ServiceInfo(
        type_=fq_type,
        name=f"{name}.{fq_type}",
        server=hostname,
        addresses=[socket.inet_aton(ip) for ip in all_ips],
        port=port,
        properties=properties or {},
    )
    z.register_service(info)
    return z


class _ServiceListener:
    def __init__(self):
        self.found = []
        self._lock = threading.Lock()
    def add_service(self, zc_, type_, name):
        info = zc_.get_service_info(type_, name)
        if info:
            with self._lock:
                self.found.append(info)
    def remove_service(self, zc_, type_, name):
        pass
    def update_service(self, zc_, type_, name):
        pass


def discover_service(service_type: str, timeout: float = 3.0) -> Optional[object]:
    if not _ZEROCONF_AVAILABLE:
        return None
    z = zc.Zeroconf()
    listener = _ServiceListener()
    fq_type = service_type if service_type.endswith(".local.") else f"{service_type}.local."
    browser = zc.ServiceBrowser(z, fq_type, listener)
    time.sleep(timeout)
    browser.cancel()
    z.close()
    if listener.found:
        return listener.found[0]
    return None


def resolve_service(info):
    hostname = info.server.strip(".") if info.server else ""
    ip = socket.inet_ntoa(info.addresses[0]) if info.addresses else ""
    port = info.port
    return hostname, ip, port


def resolve_url(info, use_https: bool = False) -> str:
    hostname, ip, port = resolve_service(info)
    if use_https:
        return f"https://{hostname}:{port}"
    return f"http://{ip}:{port}"
