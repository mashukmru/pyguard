"""
PyGuard firewall.

Clear separation: detection (rule engine + rate limiter + attack heuristics)
and enforcement (allow/block decision + logging). Consumes PacketInfo from
the packet sniffer and applies rules; logs blocked and suspicious activity.
Extensible for future ML-based IDS integration.
"""

import threading
import time
from collections import defaultdict
from typing import Optional

from pyguard.core.logger import get_logger
from pyguard.core.packet_sniffer import PacketInfo
from pyguard.core.rate_limiter import RateLimiter
from pyguard.core.rule_engine import Rule, RuleEngine
from pyguard.core.geo_lookup import GeoLookup
from pyguard.core.geo_rule_engine import GeoRuleEngine
from pyguard.utils.network_context import classify_traffic, discover_local_addresses


class Firewall:
    """
    Detection: rule matching, rate limiting, and simple attack heuristics
    (port scan, brute force, flood). Enforcement: allow vs block and logging.
    """

    def __init__(
        self,
        rule_engine: Optional[RuleEngine] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self._engine = rule_engine or RuleEngine()
        self._limiter = rate_limiter or RateLimiter()
        self._geo_engine = GeoRuleEngine()
        self._geo_lookup = GeoLookup(api_key=self._geo_engine.get_api_key())
        self._logger = get_logger()
        self._lock = threading.RLock()
        # Attack detection state (per source_ip)
        self._port_scan_ports: defaultdict = defaultdict(set)
        self._brute_force_count: defaultdict = defaultdict(int)
        self._brute_force_last_seen: defaultdict = defaultdict(float)
        self._alerted_until: defaultdict = defaultdict(float)
        self._last_activity: defaultdict = defaultdict(float)
        self._port_scan_window = 5.0
        self._local_addresses = discover_local_addresses()
        self._brute_window = 10.0
        self._reload_interval = 2.0
        self._last_reload = 0.0
        self._apply_rate_limits_config()

    def _apply_rate_limits_config(self) -> None:
        """Sync rate limiter with rule engine config."""
        cfg = self._engine.get_rate_limits_config()
        self._limiter.update_limits(
            global_max_pps=cfg.get("global_max_pps"),
            per_ip_max_pps=cfg.get("per_ip_max_pps"),
        )

    def _maybe_reload_rules(self) -> None:
        """Periodically reload rules for dynamic updates without restart."""
        now = time.monotonic()
        if now - self._last_reload >= self._reload_interval:
            self._last_reload = now
            self._engine.reload()
            self._apply_rate_limits_config()

    def _check_attack_heuristics(self, info: PacketInfo) -> Optional[str]:
        """
        Detection: simple heuristics for port scan, brute force, flood.
        Returns alert type string if suspicious, else None.
        """
        src = info.source_ip or ""
        now = time.monotonic()

        # Count TCP connection attempts, not reply/established packets. Group by
        # source and destination so unrelated targets do not merge into one scan.
        port_scan_threshold = self._engine.get_rate_limits_config().get("port_scan_threshold", 10)
        tcp_connection_attempt = (
            info.protocol != "tcp"
            or info.tcp_flags is None
            or (info.tcp_flags & 0x02 != 0 and info.tcp_flags & 0x10 == 0)
        )
        scan_key = (src, info.dst_ip or "")
        if info.dst_port is not None and tcp_connection_attempt:
            if now - self._last_activity[scan_key] > self._port_scan_window:
                self._port_scan_ports[scan_key].clear()
                self._alerted_until[f"port_scan:{scan_key}"] = 0.0
            self._port_scan_ports[scan_key].add(info.dst_port)
            self._last_activity[scan_key] = now
            alert_key = f"port_scan:{scan_key}"
            if (
                len(self._port_scan_ports[scan_key]) >= port_scan_threshold
                and now >= self._alerted_until[alert_key]
            ):
                self._alerted_until[alert_key] = now + self._port_scan_window
                return "port_scan"

        # Brute force: many connections to same port (e.g. SSH 22)
        if info.protocol == "tcp" and not tcp_connection_attempt:
            return None
        brute_threshold = self._engine.get_rate_limits_config().get("brute_force_threshold", 5)
        key = f"{src}:{info.dst_port}"
        if now - self._brute_force_last_seen[key] > self._brute_window:
            self._brute_force_count[key] = 0
            self._alerted_until[f"brute_force:{key}"] = 0.0
        self._brute_force_count[key] = self._brute_force_count.get(key, 0) + 1
        self._brute_force_last_seen[key] = now
        brute_alert_key = f"brute_force:{key}"
        if (
            self._brute_force_count[key] >= brute_threshold
            and info.dst_port in (22, 21, 23, 3389)
            and now >= self._alerted_until[brute_alert_key]
        ):
            self._alerted_until[brute_alert_key] = now + self._brute_window
            return "brute_force"

        # Flood: handled by rate limiter below
        return None

    def process_packet(self, info: PacketInfo) -> None:
        """
        Main entry: detection then enforcement.
        - Reload rules periodically.
        - Match rules, apply rate limit, check heuristics.
        - Allow or block; log blocks and suspicious activity.
        """
        self._maybe_reload_rules()

        src_ip = info.source_ip
        dst_ip = info.dst_ip
        src_port = info.src_port
        dst_port = info.dst_port
        protocol = info.protocol

        # ----- Detection: Geo-location based filtering (High Priority) -----
        country = self._geo_lookup.get_country(src_ip)
        if country and self._geo_engine.is_country_blocked(country):
            self._logger.log_blocked(
                reason=f"[BLOCKED-GEO] Packet from {src_ip} ({country})",
                source_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
            )
            return

        # ----- Detection: rule evaluation -----
        action, matched_rule = self._engine.evaluate(src_ip, dst_ip, src_port, dst_port, protocol)

        # ----- Detection: rate limit (for rate_limit rule or global) -----
        per_ip_limit = None
        if matched_rule and matched_rule.action == "rate_limit" and matched_rule.max_packets_per_second:
            per_ip_limit = matched_rule.max_packets_per_second
        allowed_rate, reason = self._limiter.allow_packet(source_ip=src_ip, custom_per_ip_limit=per_ip_limit)
        if not allowed_rate:
            self._logger.log_blocked(
                reason=reason,
                source_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                rule_id=matched_rule.id if matched_rule else None,
            )
            self._logger.log_suspicious("flood", source_ip=src_ip, details={"reason": reason})
            return
        if matched_rule and matched_rule.action == "block":
            self._logger.log_blocked(
                reason="rule_match",
                source_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                rule_id=matched_rule.id,
            )
            return
        if matched_rule and matched_rule.action == "allow":
            # Explicit allow
            pass
        elif action == "block":
            self._logger.log_blocked(
                reason="default_policy_block",
                source_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
            )
            return

        # ----- Attack heuristics -----
        traffic_context = classify_traffic(src_ip, dst_ip, self._local_addresses)
        alert = self._check_attack_heuristics(info)
        if alert:
            classification_reason = {
                "local_originated": "Source address matches an address assigned to this host; detection criteria still matched.",
                "remote_to_local": "Destination address matches an address assigned to this host.",
                "local_to_local": "Both endpoints match addresses assigned to this host.",
                "not_assigned_to_local_host": "Neither endpoint matched a discovered local interface address.",
                "unknown": "One or both endpoint addresses could not be classified.",
            }.get(traffic_context["direction"], "Traffic direction classified from endpoint addresses.")
            classification = {
                **traffic_context,
                "reason": classification_reason,
            }
            if alert == "port_scan":
                classification["detection_basis"] = (
                    f"{len(self._port_scan_ports[(src_ip or '', dst_ip or '')])} distinct TCP SYN destination ports in a {self._port_scan_window:g}s window."
                    if protocol == "tcp"
                    else f"Distinct {protocol} destination ports in a {self._port_scan_window:g}s window; this protocol has no TCP handshake state."
                )
            self._logger.log_suspicious(
                alert,
                source_ip=src_ip,
                details={
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "tcp_flags": info.tcp_flags,
                    "traffic_classification": classification,
                },
            )
            self._logger.log_alert(
                f"possible_{alert}",
                f"Suspicious activity: {alert} from {src_ip}",
                severity="medium",
                metadata={
                    "source_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "tcp_flags": info.tcp_flags,
                    "traffic_classification": classification,
                },
            )
        # Enforcement: packet allowed (we only log; actual drop would be at OS/iptables level in full deployment)
        # In this design we log blocks; integration with OS firewall would go here.

    def get_rule_engine(self) -> RuleEngine:
        return self._engine

    def get_rate_limiter(self) -> RateLimiter:
        return self._limiter
