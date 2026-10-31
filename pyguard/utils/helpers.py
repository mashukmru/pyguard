"""
PyGuard utility helpers.

Provides path resolution, IP/port normalization, and shared constants
for use across core and attack_simulator modules.
Extensible for future ML-based IDS integration.
"""

import os
import sys
from pathlib import Path
from typing import Any, List, Optional, Union


# ---------------------------------------------------------------------------
# Path resolution: ensure we can find config and logs from any cwd
# ---------------------------------------------------------------------------

def get_project_root() -> Path:
    """Return the PyGuard project root (directory containing pyguard package)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    # When running as python -m pyguard, __file__ is inside pyguard/
    p = Path(__file__).resolve()
    # pyguard/utils/helpers.py -> go up to pyguard, then to project root
    if "pyguard" in p.parts:
        idx = p.parts.index("pyguard")
        return Path(*p.parts[:idx])
    return p.parent.parent


def get_config_dir() -> Path:
    """Return path to config directory (contains rules.json)."""
    root = get_project_root()
    return root / "pyguard" / "config"


def get_rules_path() -> Path:
    """Return path to rules.json."""
    return get_config_dir() / "rules.json"


def get_geo_rules_path() -> Path:
    """Return path to geo_rules.json."""
    return get_config_dir() / "geo_rules.json"


def get_logs_dir() -> Path:
    """Return path to logs directory; create if missing."""
    root = get_project_root()
    log_dir = root / "pyguard" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


# ---------------------------------------------------------------------------
# IP and port normalization (for rule matching and extensibility)
# ---------------------------------------------------------------------------

def normalize_ip(ip: Optional[str]) -> Optional[str]:
    """Return stripped IP string or None if empty/invalid."""
    if ip is None or not isinstance(ip, str):
        return None
    s = ip.strip()
    return s if s else None


def normalize_port(port: Optional[Union[int, List[int]]]) -> Optional[List[int]]:
    """Convert port to list of integers for consistent rule matching."""
    if port is None:
        return None
    if isinstance(port, int):
        return [port] if 0 <= port <= 65535 else None
    if isinstance(port, list):
        out = []
        for p in port:
            if isinstance(p, int) and 0 <= p <= 65535:
                out.append(p)
        return out if out else None
    return None


def parse_protocol(proto: Optional[str]) -> Optional[str]:
    """Return lowercase protocol string (tcp, udp, icmp) or None."""
    if proto is None or not isinstance(proto, str):
        return None
    s = proto.strip().lower()
    if s in ("tcp", "udp", "icmp"):
        return s
    return None


def safe_get(data: dict, key: str, default: Any = None) -> Any:
    """Safely get a key from a dict (for rule/config access)."""
    try:
        return data.get(key, default)
    except (AttributeError, TypeError):
        return default
