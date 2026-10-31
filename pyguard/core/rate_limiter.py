"""
PyGuard rate limiter.

Tracks packet counts per source IP and globally to enforce rate limits.
Used for both rule-based rate_limit action and attack detection
(port scan, brute force, flood). Thread-safe.
"""

import threading
import time
from collections import defaultdict
from typing import Dict, Optional, Tuple


class RateLimiter:
    """
    Per-IP and global packet rate limiting with sliding window.
    Supports configurable max packets per second and cleanup of stale entries.
    """

    def __init__(
        self,
        global_max_pps: int = 1000,
        per_ip_max_pps: int = 100,
        window_sec: float = 1.0,
    ):
        self._global_max_pps = max(1, global_max_pps)
        self._per_ip_max_pps = max(1, per_ip_max_pps)
        self._window_sec = max(0.1, window_sec)
        self._lock = threading.RLock()
        # source_ip -> list of timestamps (trimmed to window)
        self._per_ip: Dict[str, list] = defaultdict(list)
        self._global_timestamps: list = []
        self._last_cleanup = time.monotonic()
        self._cleanup_interval_sec = 10.0

    def _trim(self, timestamps: list, now: float) -> None:
        """Remove timestamps older than window."""
        cutoff = now - self._window_sec
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

    def _cleanup_if_needed(self, now: float) -> None:
        """Periodically remove stale per-IP entries."""
        if now - self._last_cleanup < self._cleanup_interval_sec:
            return
        self._last_cleanup = now
        stale = [ip for ip, ts in self._per_ip.items() if not ts or ts[-1] < now - self._window_sec]
        for ip in stale:
            del self._per_ip[ip]

    def allow_packet(
        self,
        source_ip: Optional[str] = None,
        custom_per_ip_limit: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Record a packet and check if it should be allowed by rate limit.
        Returns (allowed, reason_string).
        """
        now = time.monotonic()
        with self._lock:
            self._trim(self._global_timestamps, now)
            if len(self._global_timestamps) >= self._global_max_pps:
                return False, "global_rate_limit_exceeded"
            self._global_timestamps.append(now)

            if source_ip:
                self._trim(self._per_ip[source_ip], now)
                limit = custom_per_ip_limit if custom_per_ip_limit is not None else self._per_ip_max_pps
                if len(self._per_ip[source_ip]) >= limit:
                    return False, "per_ip_rate_limit_exceeded"
                self._per_ip[source_ip].append(now)

            self._cleanup_if_needed(now)
        return True, "ok"

    def get_current_rates(self) -> Tuple[int, Dict[str, int]]:
        """Return (global_count_in_window, dict of source_ip -> count)."""
        now = time.monotonic()
        with self._lock:
            self._trim(self._global_timestamps, now)
            per_ip = {ip: len(ts) for ip, ts in self._per_ip.items() if ts}
        return len(self._global_timestamps), per_ip

    def update_limits(
        self,
        global_max_pps: Optional[int] = None,
        per_ip_max_pps: Optional[int] = None,
    ) -> None:
        """Update limits from config (e.g. after rule reload)."""
        with self._lock:
            if global_max_pps is not None:
                self._global_max_pps = max(1, global_max_pps)
            if per_ip_max_pps is not None:
                self._per_ip_max_pps = max(1, per_ip_max_pps)
