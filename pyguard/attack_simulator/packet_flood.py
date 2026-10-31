"""
PyGuard attack simulator: Packet flooding.

Controlled, local-only simulation: send a burst of TCP/UDP packets to test
firewall rate limiting and flood detection. Short duration and limited count.
"""

import socket
import time
from typing import Optional

from pyguard.core.logger import get_logger

# Safe limits for simulation
MAX_PACKETS = 200
MAX_DURATION_SEC = 5.0
DEFAULT_DURATION = 2.0
DEFAULT_PORT = 9999


def run_packet_flood(
    target: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    duration_sec: float = DEFAULT_DURATION,
    use_udp: bool = True,
) -> dict:
    """
    Simulate a short packet flood to the target:port (local only).
    Returns dict with packets_sent, duration_sec, error.
    """
    if target not in ("127.0.0.1", "localhost", "::1"):
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)
            if not ip.is_loopback:
                return {
                    "error": "Flood simulation allowed only for localhost.",
                    "packets_sent": 0,
                    "duration_sec": 0,
                }
        except Exception:
            return {"error": "Invalid target. Use 127.0.0.1 for local testing.", "packets_sent": 0, "duration_sec": 0}

    duration_sec = min(max(0.5, duration_sec), MAX_DURATION_SEC)
    host = target if target != "localhost" else "127.0.0.1"
    logger = get_logger()
    start = time.perf_counter()
    packets_sent = 0
    payload = b"PYGUARD_FLOOD_SIM"

    try:
        if use_udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                while time.perf_counter() - start < duration_sec and packets_sent < MAX_PACKETS:
                    sock.sendto(payload, (host, port))
                    packets_sent += 1
            finally:
                sock.close()
        else:
            while time.perf_counter() - start < duration_sec and packets_sent < MAX_PACKETS:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.1)
                        s.connect((host, port))
                    packets_sent += 1
                except (socket.error, OSError):
                    packets_sent += 1  # count attempt
    except Exception as e:
        logger.log_simulation(
            sim_type="flood",
            target=target,
            duration_sec=round(time.perf_counter() - start, 2),
            outcome="error",
            extra={"error": str(e)},
        )
        return {
            "packets_sent": packets_sent,
            "duration_sec": round(time.perf_counter() - start, 2),
            "error": str(e),
        }

    elapsed = time.perf_counter() - start
    logger.log_simulation(
        sim_type="flood",
        target=target,
        duration_sec=round(elapsed, 2),
        outcome=f"sent={packets_sent}",
        extra={"packets_sent": packets_sent, "protocol": "udp" if use_udp else "tcp"},
    )
    return {
        "packets_sent": packets_sent,
        "duration_sec": round(elapsed, 2),
        "error": None,
    }
