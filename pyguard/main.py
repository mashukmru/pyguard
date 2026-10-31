"""
PyGuard CLI – A Python Based Intelligent Firewall.

Command-line interface: start/stop firewall, add/remove rules,
run attack simulations (local only), view logs.

Architecture (modular, separation of concerns):
  - core.packet_sniffer: Scapy capture -> PacketInfo (TCP/UDP/ICMP)
  - core.rule_engine: rules from config/rules.json, dynamic reload
  - core.rate_limiter: per-IP and global PPS limits
  - core.firewall: detection (rules + rate + heuristics) then enforcement (log block/allow)
  - core.logger: structured JSON logs to logs/
  - attack_simulator: port_scan, brute_force, packet_flood (localhost only)
  - Extensible for future ML-based IDS and SIEM integration.
"""

import sys
from pathlib import Path

import click

# Ensure package root is on path when run as python -m pyguard
if __name__ == "__main__":
    _root = Path(__file__).resolve().parent.parent
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

from pyguard.attack_simulator.brute_force import run_brute_force_simulation
from pyguard.attack_simulator.packet_flood import run_packet_flood
from pyguard.attack_simulator.port_scan import run_port_scan
from pyguard.core.firewall import Firewall
from pyguard.core.logger import get_logger
from pyguard.core.packet_sniffer import PacketSniffer, SCAPY_AVAILABLE
from pyguard.core.rule_engine import Rule, RuleEngine
from pyguard.core.rate_limiter import RateLimiter
from pyguard.utils.helpers import get_logs_dir, get_rules_path


# Global references for start/stop
_firewall: Firewall = None
_sniffer: PacketSniffer = None


@click.group()
def cli():
    """PyGuard – Python Based Intelligent Firewall. Start, stop, rules, simulate, logs."""


@cli.command("start")
@click.option("--interface", "-i", default=None, help="Network interface to sniff (default: all).")
@click.option("--filter", "filter_expr", default="ip", help="BPF filter for capture (default: ip).")
def start_firewall(interface, filter_expr):
    """Start the firewall (packet capture + rule engine + rate limiter)."""
    global _firewall, _sniffer
    if not SCAPY_AVAILABLE:
        click.echo("Error: Scapy is required. Install with: pip install scapy", err=True)
        raise SystemExit(1)
    _firewall = Firewall(rule_engine=RuleEngine(), rate_limiter=RateLimiter())
    logger = get_logger()
    logger.log_info("Firewall started via CLI", interface=interface, filter=filter_expr)

    def on_packet(packet_info):
        _firewall.process_packet(packet_info)

    _sniffer = PacketSniffer(
        packet_callback=on_packet,
        interface=interface,
        filter_expr=filter_expr,
    )
    _sniffer.start()
    click.echo("PyGuard firewall started. Press Ctrl+C to stop.")
    try:
        while _sniffer._thread.is_alive():
            _sniffer._thread.join(timeout=0.5)
    except KeyboardInterrupt:
        stop_firewall_cmd()


def stop_firewall_cmd():
    """Stop the running firewall (used by start on Ctrl+C and by stop command)."""
    global _sniffer
    if _sniffer:
        _sniffer.stop()
        _sniffer = None
        get_logger().log_info("Firewall stopped via CLI")
        click.echo("PyGuard firewall stopped.")


@cli.command("stop")
def stop_firewall():
    """Stop the firewall (when running in background, kill the process)."""
    stop_firewall_cmd()


@cli.command("add-rule")
@click.option("--id", "rule_id", required=True, help="Unique rule ID.")
@click.option("--action", type=click.Choice(["allow", "block", "rate_limit"]), default="block")
@click.option("--source-ip", default=None, help="Source IP to match.")
@click.option("--dst-ip", default=None, help="Destination IP to match.")
@click.option("--dst-port", default=None, type=int, help="Destination port (single).")
@click.option("--src-port", default=None, type=int, help="Source port (single).")
@click.option("--protocol", type=click.Choice(["tcp", "udp", "icmp"]), default=None)
@click.option("--max-pps", default=None, type=int, help="For rate_limit: max packets per second.")
@click.option("--description", default="", help="Rule description.")
def add_rule(rule_id, action, source_ip, dst_ip, dst_port, src_port, protocol, max_pps, description):
    """Add a firewall rule (saved to config/rules.json; reloaded automatically)."""
    engine = RuleEngine(rules_path=get_rules_path())
    dst_port_list = [dst_port] if dst_port is not None else None
    src_port_list = [src_port] if src_port is not None else None
    rule = Rule(
        rule_id=rule_id,
        action=action,
        enabled=True,
        description=description,
        source_ip=source_ip,
        dst_ip=dst_ip,
        dst_port=dst_port_list,
        src_port=src_port_list,
        protocol=protocol,
        max_packets_per_second=max_pps,
    )
    engine.add_rule(rule)
    click.echo(f"Rule '{rule_id}' added (action={action}). Rules are reloaded by the firewall automatically.")


@cli.command("list-rules")
def list_rules():
    """List current firewall rules (from config/rules.json)."""
    engine = RuleEngine(rules_path=get_rules_path())
    for r in engine.get_rules():
        click.echo(f"  {r.id}: action={r.action} enabled={r.enabled} desc={r.description!r}")


@cli.command("remove-rule")
@click.option("--id", "rule_id", required=True, help="Rule ID to remove.")
def remove_rule(rule_id):
    """Remove a firewall rule by ID."""
    engine = RuleEngine(rules_path=get_rules_path())
    if engine.remove_rule(rule_id):
        click.echo(f"Rule '{rule_id}' removed.")
    else:
        click.echo(f"Rule '{rule_id}' not found.", err=True)
        raise SystemExit(1)


@cli.command("simulate")
@click.option("--type", "sim_type", type=click.Choice(["port_scan", "brute_force", "flood"]), required=True)
@click.option("--target", default="127.0.0.1", help="Target (localhost only: 127.0.0.1).")
@click.option("--port", default=22, type=int, help="Port for brute_force or flood.")
@click.option("--duration", default=2.0, type=float, help="Duration in seconds (flood).")
def simulate(sim_type, target, port, duration):
    """Run attack simulation (local testing only: use 127.0.0.1)."""
    if sim_type == "port_scan":
        result = run_port_scan(target=target)
    elif sim_type == "brute_force":
        result = run_brute_force_simulation(target=target, port=port)
    else:
        result = run_packet_flood(target=target, port=port, duration_sec=duration)
    if result.get("error"):
        click.echo(result["error"], err=True)
        raise SystemExit(1)
    click.echo("Simulation completed: " + str(result))


@cli.command("logs")
@click.option("--lines", "-n", default=50, type=int, help="Number of recent log lines to show.")
@click.option("--path", "log_path", default=None, type=click.Path(path_type=Path), help="Log file path.")
def view_logs(lines, log_path):
    """View recent log entries (JSON lines)."""
    path = log_path or (get_logs_dir() / "pyguard.log")
    if not path.exists():
        click.echo("No log file found at " + str(path))
        return
    with open(path, "r", encoding="utf-8") as f:
        all_lines = f.readlines()
    for line in all_lines[-lines:]:
        click.echo(line.rstrip())

@cli.command("web")
@click.option("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0).")
@click.option("--port", "-p", default=5000, type=int, help="Port to listen on (default: 5000).")
@click.option("--debug", is_flag=True, default=False, help="Enable Flask debug mode.")
def web_dashboard(host, port, debug):
    """Launch the PyGuard web dashboard (browser UI)."""
    from pyguard.web.app import run_dashboard
    run_dashboard(host=host, port=port, debug=debug)


if __name__ == "__main__":
    cli()
