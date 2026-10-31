"""
PyGuard rule engine.

Implements IP filtering, port filtering, protocol filtering, and rate-limit
rule support. Rules are loaded from config/rules.json and can be dynamically
reloaded without restarting the system.
"""

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pyguard.utils.helpers import get_rules_path, normalize_ip, normalize_port, parse_protocol, safe_get


class Rule:
    """Single firewall rule with optional IP, port, protocol, and rate_limit."""

    def __init__(
        self,
        rule_id: str,
        action: str,
        enabled: bool = True,
        description: Optional[str] = None,
        source_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[List[int]] = None,
        dst_port: Optional[List[int]] = None,
        protocol: Optional[str] = None,
        max_packets_per_second: Optional[int] = None,
    ):
        self.id = rule_id
        self.action = action.strip().lower()  # allow, block, rate_limit
        self.enabled = enabled
        self.description = description or ""
        self.source_ip = normalize_ip(source_ip)
        self.dst_ip = normalize_ip(dst_ip)
        self.src_port = normalize_port(src_port)
        self.dst_port = normalize_port(dst_port)
        self.protocol = parse_protocol(protocol)
        self.max_packets_per_second = max_packets_per_second if isinstance(max_packets_per_second, int) else None

    def matches(
        self,
        source_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: Optional[str],
    ) -> bool:
        """Return True if the packet/flow matches this rule."""
        if not self.enabled:
            return False
        if self.source_ip is not None and source_ip != self.source_ip:
            return False
        if self.dst_ip is not None and dst_ip != self.dst_ip:
            return False
        if self.src_port is not None and (src_port is None or src_port not in self.src_port):
            return False
        if self.dst_port is not None and (dst_port is None or dst_port not in self.dst_port):
            return False
        if self.protocol is not None and (protocol is None or protocol.lower() != self.protocol):
            return False
        return True


class RuleEngine:
    """
    Loads, stores, and evaluates firewall rules.
    Supports dynamic reload from disk without restart.
    """

    def __init__(self, rules_path: Optional[Path] = None):
        self._path = rules_path or get_rules_path()
        self._lock = threading.RLock()
        self._rules: List[Rule] = []
        self._default_policy = "allow"
        self._rate_limits_config: Dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        """Reload rules from config file. Safe to call from any thread."""
        with self._lock:
            self._rules = []
            self._default_policy = "allow"
            self._rate_limits_config = {}
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                return
            self._default_policy = str(safe_get(data, "default_policy", "allow")).lower()
            self._rate_limits_config = dict(safe_get(data, "rate_limits") or {})
            for r in safe_get(data, "rules") or []:
                if not isinstance(r, dict):
                    continue
                rid = safe_get(r, "id") or safe_get(r, "rule_id")
                if not rid:
                    continue
                action = safe_get(r, "action", "allow")
                port = safe_get(r, "dst_port") or safe_get(r, "port")
                self._rules.append(
                    Rule(
                        rule_id=str(rid),
                        action=action,
                        enabled=bool(safe_get(r, "enabled", True)),
                        description=safe_get(r, "description"),
                        source_ip=safe_get(r, "source_ip"),
                        dst_ip=safe_get(r, "dst_ip"),
                        src_port=safe_get(r, "src_port"),
                        dst_port=port,
                        protocol=safe_get(r, "protocol"),
                        max_packets_per_second=safe_get(r, "max_packets_per_second"),
                    )
                )

    def evaluate(
        self,
        source_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: Optional[str],
    ) -> Tuple[str, Optional[Rule]]:
        """
        Evaluate packet against rules. First matching rule wins.
        Returns (action, matched_rule) where action is 'allow', 'block', or 'rate_limit'.
        """
        with self._lock:
            for rule in self._rules:
                if rule.matches(source_ip, dst_ip, src_port, dst_port, protocol):
                    return rule.action, rule
            return self._default_policy, None

    def get_rate_limits_config(self) -> Dict[str, Any]:
        """Return rate limit thresholds (e.g. per_ip_max_pps, port_scan_threshold)."""
        with self._lock:
            return dict(self._rate_limits_config)

    def get_rules(self) -> List[Rule]:
        """Return a copy of current rules (for CLI list)."""
        with self._lock:
            return list(self._rules)

    def add_rule(self, rule: Rule) -> None:
        """Add a rule in memory and persist to rules file."""
        with self._lock:
            self._rules = [r for r in self._rules if r.id != rule.id]
            self._rules.append(rule)
            self._persist()

    def remove_rule(self, rule_id: str) -> bool:
        """Remove rule by id; persist. Returns True if removed."""
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            if len(self._rules) < before:
                self._persist()
                return True
            return False

    def _persist(self) -> None:
        """Write current rules back to JSON (preserve structure)."""
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            data = {"default_policy": "allow", "rules": [], "rate_limits": {}}
        data["rules"] = []
        for r in self._rules:
            data["rules"].append({
                "id": r.id,
                "action": r.action,
                "enabled": r.enabled,
                "description": r.description,
                "source_ip": r.source_ip,
                "dst_ip": r.dst_ip,
                "src_port": r.src_port,
                "dst_port": r.dst_port,
                "protocol": r.protocol,
                "max_packets_per_second": r.max_packets_per_second,
            })
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
