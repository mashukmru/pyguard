"""Best-effort local address discovery and packet direction classification."""

import ipaddress
import socket
from typing import Any, Dict, Iterable, Set


def discover_local_addresses() -> Set[str]:
    """Return assigned host addresses across available interfaces where possible."""
    addresses = {"127.0.0.1", "::1"}

    try:
        from scapy.all import get_if_addr, get_if_list

        for interface in get_if_list():
            try:
                address = get_if_addr(interface)
                if address and address != "0.0.0.0":
                    addresses.add(str(ipaddress.ip_address(address)))
            except (OSError, ValueError):
                continue
    except (ImportError, OSError):
        pass

    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            address = item[4][0].split("%", 1)[0]
            parsed = ipaddress.ip_address(address)
            if not parsed.is_unspecified:
                addresses.add(str(parsed))
    except (OSError, ValueError):
        pass

    # A UDP connect selects the active route/interface without sending a packet.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            address = probe.getsockname()[0]
            if address and address != "0.0.0.0":
                addresses.add(str(ipaddress.ip_address(address)))
    except (OSError, ValueError):
        pass

    return addresses


def classify_address(value: Any, local_addresses: Iterable[str]) -> Dict[str, Any]:
    """Classify an address by scope and whether it is assigned to this host."""
    if value is None:
        return {"scope": "unknown", "is_local": False}
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return {"scope": "invalid", "is_local": False}

    local_set = set(local_addresses)
    is_local = str(address) in local_set
    if address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link_local"
    elif address.is_private:
        scope = "private"
    elif address.is_global:
        scope = "public"
    elif address.is_multicast:
        scope = "multicast"
    elif address.is_unspecified:
        scope = "unspecified"
    else:
        scope = "reserved"
    return {"scope": scope, "is_local": is_local}


def classify_traffic(source_ip: Any, destination_ip: Any, local_addresses: Iterable[str]) -> Dict[str, Any]:
    """Describe packet direction and endpoint scopes without asserting safety."""
    local_set = set(local_addresses)
    source = classify_address(source_ip, local_set)
    destination = classify_address(destination_ip, local_set)
    if source["is_local"] and destination["is_local"]:
        direction = "local_to_local"
    elif source["is_local"]:
        direction = "local_originated"
    elif destination["is_local"]:
        direction = "remote_to_local"
    elif source["scope"] == "unknown" or destination["scope"] == "unknown":
        direction = "unknown"
    else:
        direction = "not_assigned_to_local_host"

    return {
        "direction": direction,
        "source_scope": source["scope"],
        "destination_scope": destination["scope"],
        "source_is_local": source["is_local"],
        "destination_is_local": destination["is_local"],
    }
