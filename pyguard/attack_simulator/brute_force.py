"""
PyGuard attack simulator: Brute force (repeated connection attempts).

Controlled, local-only simulation to test firewall detection of brute-force
attempts (e.g. repeated TCP connections to SSH/RDP port).
"""

import socket
import time
from typing import Optional

from pyguard.core.logger import get_logger

DEFAULT_ATTEMPTS = 8
DEFAULT_TIMEOUT = 0.3


def run_brute_force_simulation(
    target: str = "127.0.0.1",
    port: int = 22,
    attempts: int = DEFAULT_ATTEMPTS,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """
    Simulate repeated connection attempts to one port (brute-force style).
    Local testing only. Returns dict with attempts, success_count, duration_sec, error.
    """
    if target not in ("127.0.0.1", "localhost", "::1"):
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)
            if not ip.is_loopback:
                return {
                    "error": "Simulation allowed only for localhost.",
                    "attempts": 0,
                    "success_count": 0,
                    "duration_sec": 0,
                }
        except Exception:
            return {"error": "Invalid target. Use 127.0.0.1 for local testing.", "attempts": 0, "success_count": 0, "duration_sec": 0}

    attempts = min(max(1, attempts), 50)
    success_count = 0
    start = time.perf_counter()
    logger = get_logger()
    host = target if target != "localhost" else "127.0.0.1"

    for _ in range(attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                success_count += 1
        except (socket.timeout, socket.error, OSError):
            pass
    duration = time.perf_counter() - start

    logger.log_simulation(
        sim_type="brute_force",
        target=target,
        port=port,
        duration_sec=round(duration, 2),
        outcome=f"success={success_count}/{attempts}",
        extra={"attempts": attempts, "success_count": success_count},
    )
    return {
        "attempts": attempts,
        "success_count": success_count,
        "duration_sec": round(duration, 2),
        "error": None,
    }
