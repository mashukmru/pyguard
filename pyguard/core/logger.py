"""
PyGuard structured logger.

Logs blocked packets, suspicious activities, and attack simulations
in JSON format to the logs/ directory. Supports alerts for traffic analysis
and future SIEM integration.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from pyguard.utils.helpers import get_logs_dir


class PyGuardLogger:
    """
    Structured JSON logger for firewall events.
    Writes to pyguard/logs/ with rotation-friendly naming (single file or daily).
    """

    def __init__(self, log_dir: Optional[Path] = None, log_filename: Optional[str] = None):
        self._log_dir = log_dir or get_logs_dir()
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_filename = log_filename or "pyguard.log"
        self._log_path = self._log_dir / self._log_filename

    def _write(self, entry: Dict[str, Any]) -> None:
        """Append one JSON line to the log file."""
        try:
            entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
            line = json.dumps(entry, default=str) + "\n"
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError as e:
            # Fallback to stderr if logs dir not writable
            print(json.dumps({**entry, "log_error": str(e)}, default=str), file=__import__("sys").stderr)

    def log_blocked(
        self,
        reason: str,
        source_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        rule_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a blocked packet or flow."""
        entry = {
            "event": "blocked",
            "reason": reason,
            "source_ip": source_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "rule_id": rule_id,
        }
        if extra:
            entry["extra"] = extra
        self._write(entry)

    def log_suspicious(
        self,
        activity: str,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log suspicious activity (e.g. port scan, brute force, flood)."""
        entry = {
            "event": "suspicious",
            "activity": activity,
            "source_ip": source_ip,
            "details": details or {},
        }
        self._write(entry)

    def log_alert(
        self,
        alert_type: str,
        message: str,
        severity: str = "medium",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an alert for traffic analysis / SIEM."""
        entry = {
            "event": "alert",
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "metadata": metadata or {},
        }
        self._write(entry)

    def log_simulation(
        self,
        sim_type: str,
        target: str,
        port: Optional[int] = None,
        duration_sec: Optional[float] = None,
        outcome: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log attack simulation run (internal testing only)."""
        entry = {
            "event": "simulation",
            "sim_type": sim_type,
            "target": target,
            "port": port,
            "duration_sec": duration_sec,
            "outcome": outcome,
            "extra": extra or {},
        }
        self._write(entry)

    def log_info(self, message: str, **kwargs: Any) -> None:
        """Log general info (e.g. firewall start/stop, rule reload)."""
        self._write({"event": "info", "message": message, **kwargs})

    @property
    def log_path(self) -> Path:
        return self._log_path


# Singleton for use across modules; can be overridden for tests
_default_logger: Optional[PyGuardLogger] = None


def get_logger(log_dir: Optional[Path] = None) -> PyGuardLogger:
    """Return the default PyGuard logger instance."""
    global _default_logger
    if _default_logger is None:
        _default_logger = PyGuardLogger(log_dir=log_dir)
    return _default_logger
