"""
PyGuard Web API – REST endpoints for the web dashboard.

Provides JSON API for firewall status, start/stop, rule management,
attack simulation, and log retrieval.
"""

import json
import threading
from pathlib import Path

from flask import Blueprint, jsonify, request

from pyguard.attack_simulator.brute_force import run_brute_force_simulation
from pyguard.attack_simulator.packet_flood import run_packet_flood
from pyguard.attack_simulator.port_scan import run_port_scan
from pyguard.core.firewall import Firewall
from pyguard.core.logger import get_logger
from pyguard.core.packet_sniffer import PacketSniffer, SCAPY_AVAILABLE
from pyguard.core.rate_limiter import RateLimiter
from pyguard.core.rule_engine import Rule, RuleEngine
from pyguard.core.geo_lookup import GeoLookup
from pyguard.core.geo_rule_engine import GeoRuleEngine
from pyguard.utils.helpers import get_logs_dir, get_rules_path

api = Blueprint("api", __name__, url_prefix="/api")

# Shared state
_firewall = None
_sniffer = None
_lock = threading.Lock()


def _is_running():
    return _sniffer is not None and _sniffer._thread is not None and _sniffer._thread.is_alive()


_geo_engine = GeoRuleEngine()
_geo_lookup = GeoLookup()


@api.route("/status", methods=["GET"])
def status():
    """Get firewall running status."""
    return jsonify({
        "running": _is_running(),
        "scapy_available": SCAPY_AVAILABLE,
    })


@api.route("/start", methods=["POST"])
def start():
    """Start the firewall (packet capture + rule engine + rate limiter)."""
    global _firewall, _sniffer
    with _lock:
        if _is_running():
            return jsonify({"status": "already_running"}), 200
        if not SCAPY_AVAILABLE:
            return jsonify({"error": "Scapy is not installed. Install with: pip install scapy"}), 500

        data = request.get_json(silent=True) or {}
        interface = data.get("interface")
        filter_expr = data.get("filter", "ip")

        _firewall = Firewall(rule_engine=RuleEngine(), rate_limiter=RateLimiter())
        logger = get_logger()
        logger.log_info("Firewall started via web dashboard", interface=interface, filter=filter_expr)

        def on_packet(packet_info):
            _firewall.process_packet(packet_info)

        _sniffer = PacketSniffer(
            packet_callback=on_packet,
            interface=interface,
            filter_expr=filter_expr,
        )
        _sniffer.start()
        if not _sniffer.wait_until_started():
            error = _sniffer.error or "Packet capture stopped during startup."
            _sniffer = None
            _firewall = None
            return jsonify({"error": error}), 500
    return jsonify({"status": "started"}), 200


@api.route("/stop", methods=["POST"])
def stop():
    """Stop the firewall."""
    global _sniffer
    with _lock:
        if not _is_running():
            return jsonify({"status": "not_running"}), 200
        _sniffer.stop()
        _sniffer = None
        get_logger().log_info("Firewall stopped via web dashboard")
    return jsonify({"status": "stopped"}), 200


# ---- Rules ----

@api.route("/rules", methods=["GET"])
def list_rules():
    """List all firewall rules."""
    engine = RuleEngine(rules_path=get_rules_path())
    rules = []
    for r in engine.get_rules():
        rules.append({
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
    return jsonify({"rules": rules})


@api.route("/rules", methods=["POST"])
def add_rule():
    """Add a firewall rule."""
    data = request.get_json()
    if not data or not data.get("id"):
        return jsonify({"error": "Missing required field: id"}), 400

    engine = RuleEngine(rules_path=get_rules_path())
    dst_port = data.get("dst_port")
    src_port = data.get("src_port")
    if isinstance(dst_port, int):
        dst_port = [dst_port]
    if isinstance(src_port, int):
        src_port = [src_port]

    rule = Rule(
        rule_id=data["id"],
        action=data.get("action", "block"),
        enabled=data.get("enabled", True),
        description=data.get("description", ""),
        source_ip=data.get("source_ip"),
        dst_ip=data.get("dst_ip"),
        dst_port=dst_port,
        src_port=src_port,
        protocol=data.get("protocol"),
        max_packets_per_second=data.get("max_pps"),
    )
    engine.add_rule(rule)
    return jsonify({"status": "added", "id": data["id"]}), 201


@api.route("/rules/<rule_id>", methods=["DELETE"])
def remove_rule(rule_id):
    """Remove a firewall rule by ID."""
    engine = RuleEngine(rules_path=get_rules_path())
    if engine.remove_rule(rule_id):
        return jsonify({"status": "removed", "id": rule_id})
    return jsonify({"error": f"Rule '{rule_id}' not found"}), 404


# ---- Simulation ----

@api.route("/simulate", methods=["POST"])
def simulate():
    """Run attack simulation."""
    data = request.get_json()
    if not data or not data.get("type"):
        return jsonify({"error": "Missing required field: type"}), 400

    sim_type = data["type"]
    target = data.get("target", "127.0.0.1")
    port = data.get("port", 22)
    duration = data.get("duration", 2.0)

    if sim_type == "port_scan":
        result = run_port_scan(target=target)
    elif sim_type == "brute_force":
        result = run_brute_force_simulation(target=target, port=port)
    elif sim_type == "flood":
        result = run_packet_flood(target=target, port=port, duration_sec=duration)
    else:
        return jsonify({"error": f"Unknown simulation type: {sim_type}"}), 400

    return jsonify({"type": sim_type, "result": result})


# ---- Rule Testing ----

@api.route("/test-rule", methods=["POST"])
def test_rule():
    """Test a specific rule by simulating a packet that matches its criteria."""
    data = request.get_json()
    rule_id = data.get("rule_id") if data else None
    if not rule_id:
        return jsonify({"error": "Missing required field: rule_id"}), 400

    engine = RuleEngine(rules_path=get_rules_path())

    # Find the rule
    target_rule = None
    for r in engine.get_rules():
        if r.id == rule_id:
            target_rule = r
            break
    if not target_rule:
        return jsonify({"error": f"Rule '{rule_id}' not found"}), 404

    # Build a simulated packet that matches this rule's criteria
    sim_src_ip = target_rule.source_ip or "203.0.113.50"
    sim_dst_ip = target_rule.dst_ip or "192.168.1.1"
    sim_src_port = target_rule.src_port[0] if target_rule.src_port else 54321
    sim_dst_port = target_rule.dst_port[0] if target_rule.dst_port else 80
    sim_protocol = target_rule.protocol or "tcp"

    # Evaluate ONLY the target rule (isolated, not the full rule chain)
    matched = target_rule.matches(sim_src_ip, sim_dst_ip, sim_src_port, sim_dst_port, sim_protocol)

    if not matched:
        verdict = "NO MATCH"
        verdict_detail = "Simulated packet did not match this rule"
    elif target_rule.action == "rate_limit":
        limiter = RateLimiter()
        custom_limit = target_rule.max_packets_per_second or 100
        for _ in range(custom_limit + 5):
            limiter.allow_packet(source_ip=sim_src_ip, custom_per_ip_limit=custom_limit)
        verdict = "RATE LIMITED"
        verdict_detail = f"Exceeded {custom_limit} packets/sec limit"
    elif target_rule.action == "block":
        verdict = "BLOCKED"
        verdict_detail = f"Matched rule '{target_rule.id}'"
    elif target_rule.action == "allow":
        verdict = "ALLOWED"
        verdict_detail = f"Matched rule '{target_rule.id}'"
    else:
        verdict = target_rule.action.upper()
        verdict_detail = f"Rule '{target_rule.id}' action: {target_rule.action}"

    # Log the test with verdict-specific event type
    logger = get_logger()
    if verdict == "BLOCKED":
        logger.log_blocked(
            reason=f"Rule test: {verdict_detail}",
            source_ip=sim_src_ip, dst_ip=sim_dst_ip,
            src_port=sim_src_port, dst_port=sim_dst_port,
            protocol=sim_protocol, rule_id=rule_id,
        )
    elif verdict == "RATE LIMITED":
        logger._write({
            "event": "rate_limited",
            "message": f"Rule test: {verdict_detail}",
            "source_ip": sim_src_ip, "dst_ip": sim_dst_ip,
            "src_port": sim_src_port, "dst_port": sim_dst_port,
            "protocol": sim_protocol, "rule_id": rule_id,
        })
    else:
        logger._write({
            "event": "allowed",
            "message": f"Rule test: {verdict_detail}",
            "source_ip": sim_src_ip, "dst_ip": sim_dst_ip,
            "src_port": sim_src_port, "dst_port": sim_dst_port,
            "protocol": sim_protocol, "rule_id": rule_id,
        })

    return jsonify({
        "rule_id": rule_id,
        "rule_action": target_rule.action,
        "rule_description": target_rule.description,
        "simulated_packet": {
            "source_ip": sim_src_ip,
            "dst_ip": sim_dst_ip,
            "src_port": sim_src_port,
            "dst_port": sim_dst_port,
            "protocol": sim_protocol,
        },
        "verdict": verdict,
        "verdict_detail": verdict_detail,
        "matched_rule": target_rule.id if matched else None,
    })


@api.route("/test-custom", methods=["POST"])
def test_custom():
    """Test a custom packet against all rules."""
    data = request.get_json() or {}
    src_ip = data.get("source_ip", "203.0.113.50")
    dst_ip = data.get("dst_ip", "192.168.1.1")
    src_port = data.get("src_port")
    dst_port = data.get("dst_port")
    protocol = data.get("protocol", "tcp")
    max_pps = data.get("max_pps")

    engine = RuleEngine(rules_path=get_rules_path())
    action, matched_rule = engine.evaluate(
        source_ip=src_ip,
        dst_ip=dst_ip,
        src_port=int(src_port) if src_port else None,
        dst_port=int(dst_port) if dst_port else None,
        protocol=protocol,
    )

    # Check rate limiting if applicable
    rate_allowed = True
    if matched_rule and matched_rule.action == "rate_limit":
        pps_limit = max_pps or (matched_rule.max_packets_per_second or 100)
        limiter = RateLimiter()
        for _ in range(pps_limit + 5):
            rate_allowed, _ = limiter.allow_packet(
                source_ip=src_ip, custom_per_ip_limit=pps_limit
            )

    if not rate_allowed:
        verdict = "RATE LIMITED"
    elif action == "block":
        verdict = "BLOCKED"
    elif action == "allow":
        verdict = "ALLOWED"
    elif action == "rate_limit":
        verdict = "RATE LIMITED"
    else:
        verdict = action.upper()

    # Log the custom packet test with verdict-specific event type
    logger = get_logger()
    rule_id = matched_rule.id if matched_rule else None
    detail = f"Custom packet test: {matched_rule.description if matched_rule else 'No rule matched (default allow)'}"
    if verdict == "BLOCKED":
        logger.log_blocked(
            reason=detail,
            source_ip=src_ip, dst_ip=dst_ip,
            src_port=int(src_port) if src_port else None,
            dst_port=int(dst_port) if dst_port else None,
            protocol=protocol, rule_id=rule_id,
        )
    elif verdict == "RATE LIMITED":
        logger._write({
            "event": "rate_limited",
            "message": detail,
            "source_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol, "rule_id": rule_id,
        })
    else:
        logger._write({
            "event": "allowed",
            "message": detail,
            "source_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol, "rule_id": rule_id,
        })

    return jsonify({
        "simulated_packet": {
            "source_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol,
        },
        "verdict": verdict,
        "matched_rule": {
            "id": matched_rule.id,
            "action": matched_rule.action,
            "description": matched_rule.description,
        } if matched_rule else None,
        "applied_policy": "default_allow" if not matched_rule else "rule_match",
    })


# ---- Geo Rules ----

@api.route("/geo-rules", methods=["GET"])
def get_geo_rules():
    """List blocked countries; the saved API key stays server-side."""
    return jsonify({
        "blocked_countries": _geo_engine.get_blocked_countries(),
    })


@api.route("/geo-rules/settings", methods=["POST"])
def update_geo_settings():
    """Update geo-location settings (API key)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    if "api_key" in data:
        _geo_engine.set_api_key(data["api_key"])
        _geo_lookup.set_api_key(data["api_key"])

    return jsonify({"status": "updated"}), 200


@api.route("/geo-rules/block", methods=["POST"])
def block_country():
    """Add a country to the block list."""
    data = request.get_json()
    if not data or not data.get("country_code"):
        return jsonify({"error": "Missing required field: country_code"}), 400

    code = data["country_code"]
    if _geo_engine.add_blocked_country(code):
        return jsonify({"status": "blocked", "country_code": code.upper()}), 201
    return jsonify({"status": "already_blocked", "country_code": code.upper()}), 200


@api.route("/geo-rules/unblock", methods=["POST"])
def unblock_country():
    """Remove a country from the block list."""
    data = request.get_json()
    if not data or not data.get("country_code"):
        return jsonify({"error": "Missing required field: country_code"}), 400

    code = data["country_code"]
    if _geo_engine.remove_blocked_country(code):
        return jsonify({"status": "unblocked", "country_code": code.upper()}), 200
    return jsonify({"error": f"Country '{code}' not in block list"}), 404


@api.route("/geo-rules/country-of-ip", methods=["GET"])
def get_country_of_ip():
    """Detect country for a given IP."""
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "Missing required parameter: ip"}), 400

    country = _geo_lookup.get_country(ip)
    return jsonify({
        "ip": ip,
        "country_code": country
    })


# ---- Logs ----

@api.route("/logs", methods=["GET"])
def get_logs():
    """Get recent log entries."""
    lines_count = max(0, min(request.args.get("lines", 500, type=int), 5000))
    search = request.args.get("search", "").lower()
    severity = request.args.get("severity", "").lower()

    log_path = get_logs_dir() / "pyguard.log"
    if not log_path.exists():
        return jsonify({"logs": [], "total": 0})

    entries = []
    for line in _read_tail_lines(log_path, lines_count):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Apply filters
        if search and search not in line.lower():
            continue
        if severity and entry.get("event", "") != severity:
            continue

        entries.append(entry)

    return jsonify({"logs": entries, "total": len(entries)})


def _read_tail_lines(path: Path, count: int, chunk_size: int = 8192):
    """Read only the requested tail of a log file, with bounded memory."""
    if count <= 0:
        return []
    chunks = []
    newline_count = 0
    with open(path, "rb") as log_file:
        position = log_file.seek(0, 2)
        while position > 0 and newline_count < count:
            start = max(0, position - chunk_size)
            log_file.seek(start)
            chunk = log_file.read(position - start)
            chunks.append(chunk)
            newline_count += chunk.count(b"\n")
            position = start

        data = b"".join(reversed(chunks))
        if position > 0:
            log_file.seek(position - 1)
            starts_on_line_boundary = log_file.read(1) == b"\n"
            if not starts_on_line_boundary:
                first_newline = data.find(b"\n")
                data = data[first_newline + 1:] if first_newline >= 0 else b""
        lines = data.splitlines()
        return [line.decode("utf-8", errors="replace") for line in lines[-count:]]
