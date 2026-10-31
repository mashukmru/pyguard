"""
PyGuard attack simulator: Port scanning.

Controlled, local-only simulation to test firewall detection of port scans.
Uses TCP SYN or connect-style probes to a limited set of ports.
"""

import socket
import time
from typing import List, Optional

from pyguard.core.logger import get_logger

# Safe default: only common ports and localhost
DEFAULT_PORTS = [21, 22, 23, 25, 80, 443, 3389, 8080]
DEFAULT_TIMEOUT = 0.5
MAX_PORTS = 50


def run_port_scan(
    target: str = "127.0.0.1",
    ports: Optional[List[int]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """
    Simulate a port scan against target (local testing only).
    Returns dict with open_ports, closed_count, duration_sec, error.
    """
    # Enforce local-only for safety
    if target not in ("127.0.0.1", "localhost", "::1"):
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)
            if not ip.is_loopback:
                return {
                    "error": "Attack simulation allowed only for localhost (127.0.0.1 or ::1).",
                    "open_ports": [],
                    "closed_count": 0,
                    "duration_sec": 0,
                }
        except Exception:
            return {"error": "Invalid target. Use 127.0.0.1 for local testing.", "open_ports": [], "closed_count": 0, "duration_sec": 0}

    port_list = list(ports or DEFAULT_PORTS)[:MAX_PORTS]
    open_ports = []
    closed_count = 0
    start = time.perf_counter()
    logger = get_logger()

    for port in port_list:
        if not (0 < port <= 65535):
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target if target != "localhost" else "127.0.0.1", port))
                open_ports.append(port)
        except (socket.timeout, socket.error, OSError):
            closed_count += 1
    duration = time.perf_counter() - start

    logger.log_simulation(
        sim_type="port_scan",
        target=target,
        duration_sec=round(duration, 2),
        outcome=f"open={len(open_ports)} closed={closed_count}",
        extra={"open_ports": open_ports, "closed_count": closed_count},
    )
    return {
        "open_ports": open_ports,
        "closed_count": closed_count,
        "duration_sec": round(duration, 2),
        "error": None,
    }
