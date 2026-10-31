"""
PyGuard packet sniffer.

Uses Scapy for Python-based packet capturing with real-time inspection.
Supports TCP, UDP, and ICMP analysis. Delivers packets to the firewall
for allow/block decision.
"""

import threading
import time
from typing import Callable, Optional

from pyguard.core.logger import get_logger

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
    from scapy.config import conf
    SCAPY_AVAILABLE = True
    if conf is not None:
        conf.use_pcap = True
except ImportError:
    SCAPY_AVAILABLE = False
    sniff = None
    IP = TCP = UDP = ICMP = Ether = None
    conf = None


# Packet info passed to firewall (protocol-agnostic)
class PacketInfo:
    """Normalized packet info for rule engine and logging."""

    __slots__ = ("source_ip", "dst_ip", "src_port", "dst_port", "protocol", "raw_summary", "tcp_flags")

    def __init__(
        self,
        source_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        raw_summary: str = "",
        tcp_flags: Optional[int] = None,
    ):
        self.source_ip = source_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.raw_summary = raw_summary
        self.tcp_flags = tcp_flags


def _extract_packet_info(pkt) -> Optional[PacketInfo]:
    """Extract PacketInfo from Scapy packet; return None if not IP."""
    if not SCAPY_AVAILABLE or pkt is None:
        return None
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    src_ip = ip.src if hasattr(ip, "src") else None
    dst_ip = ip.dst if hasattr(ip, "dst") else None
    protocol = "unknown"
    src_port = dst_port = None
    tcp_flags = None

    if pkt.haslayer(TCP):
        protocol = "tcp"
        t = pkt[TCP]
        src_port = getattr(t, "sport", None)
        dst_port = getattr(t, "dport", None)
        try:
            tcp_flags = int(t.flags)
        except (TypeError, ValueError):
            tcp_flags = None
    elif pkt.haslayer(UDP):
        protocol = "udp"
        u = pkt[UDP]
        src_port = getattr(u, "sport", None)
        dst_port = getattr(u, "dport", None)
    elif pkt.haslayer(ICMP):
        protocol = "icmp"

    try:
        raw_summary = pkt.summary() or ""
    except Exception:
        raw_summary = ""

    return PacketInfo(
        source_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        raw_summary=raw_summary,
        tcp_flags=tcp_flags,
    )


class PacketSniffer:
    """
    Captures packets via Scapy and passes PacketInfo to a callback.
    Runs in a daemon thread. Real-time TCP, UDP, and ICMP analysis.
    """

    def __init__(
        self,
        packet_callback: Callable[[PacketInfo], None],
        interface: Optional[str] = None,
        filter_expr: Optional[str] = None,
    ):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Install with: pip install scapy")
        self._callback = packet_callback
        self._interface = interface
        self._filter = filter_expr or "ip"
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[str] = None
        self._logger = get_logger()

    def _process_packet(self, pkt) -> None:
        """Called by Scapy for each packet; extract info and call firewall callback."""
        info = _extract_packet_info(pkt)
        if info is not None:
            try:
                self._callback(info)
            except Exception as e:
                self._logger.log_info("packet_callback_error", error=str(e))

    def start(self) -> None:
        """Start sniffing in a background thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._error = None
        self._thread = threading.Thread(
            target=self._run_sniff,
            daemon=True,
            name="PyGuard-Sniffer",
        )
        self._thread.start()
        self._logger.log_info("Packet sniffer started", interface=self._interface, filter=self._filter)

    def _run_sniff(self) -> None:
        """Run Scapy sniff in a loop with timeout so stop_event is checked regularly."""
        try:
            if conf is not None:
                conf.use_pcap = True
                capture_interface = self._interface or conf.iface
            else:
                capture_interface = self._interface
            while not self._stop_event.is_set():
                sniff(
                    iface=capture_interface,
                    filter=self._filter,
                    prn=self._process_packet,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    store=False,
                    timeout=1,
                )
        except Exception as e:
            if not self._stop_event.is_set():
                self._error = str(e)
                self._logger.log_alert("sniffer_error", str(e), severity="high")

    def wait_until_started(self, timeout: float = 0.5) -> bool:
        """Return whether the capture thread remains alive after startup."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._thread is not None and self._thread.is_alive():
                return True
            if self._error:
                return False
            time.sleep(0.01)
        return self._thread is not None and self._thread.is_alive()

    @property
    def error(self) -> Optional[str]:
        """Return the last capture error, if startup or capture failed."""
        return self._error

    def stop(self) -> None:
        """Signal sniffer to stop (Scapy stop_filter will break out)."""
        self._stop_event.set()
        self._logger.log_info("Packet sniffer stop requested")
