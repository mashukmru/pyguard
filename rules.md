# PyGuard Firewall Rules

## Purpose

Rules describe how PyGuard classifies observed packets. A `block` action records a PyGuard decision; it does not install or trigger an operating-system packet drop.

## Fields and matching

Rules in `pyguard/config/rules.json` use these fields:

- `id`: rule identifier.
- `action`: `allow`, `block` or `rate_limit`.
- `source_ip`, `dst_ip`: optional exact IPv4 address strings.
- `src_port`, `dst_port`: optional exact port values; the matcher accepts an integer or list of integers.
- `protocol`: optional `tcp`, `udp` or `icmp` value.
- `max_pps`: per-rule packet-per-second limit used by a `rate_limit` rule.
- `description`: readable rule description.
- `enabled`: whether the rule participates in matching.

Unset match fields act as wildcards. IP matching is exact string equality; CIDR notation and subnet matching are not supported. Port values must be in the valid 0–65535 range. The parser handles IPv4 TCP, UDP and ICMP.

## Priority and default policy

Enabled rules are checked in list order and the first matching rule wins. If nothing matches, the configured `default_policy` is `allow`.

The shipped configuration ends with a catch-all `rate_limit_global` rule, with no match fields and `max_pps` 100. It therefore matches any packet not matched earlier, so the fallback policy is generally not reached. Rules appended after this catch-all are unreachable. Insert specific rules before it if editing the JSON directly, and review order after using rule management features.

## Current starter configuration

The JSON file contains these sample identifiers: `block_blacklisted_ip`, `block_telnet`, `allow_http_https`, `block_ftp`, `allow_dns`, `block_dns_tcp`, `block_rdp`, `allow_ssh`, `block_smb`, `rate_limit_icmp`, `block_suspicious_subnet`, and `rate_limit_global`. Names and descriptions are sample configuration, not verified threat intelligence. In particular, `block_suspicious_subnet` matches one configured source address, not a subnet.

Configured rate settings include `global_max_pps` 1000, `per_ip_max_pps` 100, `port_scan_threshold` 10, `brute_force_threshold` 5 and `flood_threshold_pps` 500. The first four are used by current processing paths; `flood_threshold_pps` is present in configuration but is not used by the current detector. The catch-all rule's 100 PPS is a per-source rule limit, not the global 1000 PPS limiter.

## Add and manage rules

The CLI and dashboard support adding, listing and removing rules. The add-rule interface accepts an identifier, action, source/destination addresses, source/destination ports, protocol, rate limit and description; its CLI port options accept a single port. Use the dashboard rule form or edit the JSON for list-valued match fields. See [commands.md](commands.md) for CLI commands. Rule changes are checked during packet processing; they do not require a restart, but reload is checked during processing rather than continuously in the background.

Example rule object, using an address reserved for documentation:

```json
{
  "id": "example-block",
  "action": "block",
  "source_ip": "203.0.113.10",
  "dst_ip": null,
  "src_port": null,
  "dst_port": null,
  "protocol": "tcp",
  "description": "Illustrative exact source match",
  "enabled": true
}
```

Keep specific rules ahead of the catch-all rule. Back up the JSON before manual edits and preserve valid JSON syntax.

## Test rules

The dashboard Rule Tester and Custom Packet Tester call API evaluation endpoints with synthetic packet data. They show how the rule engine classifies the supplied example; they do not send traffic or verify packet capture. The built-in packet simulator sends limited traffic to loopback only, and generated traffic is not guaranteed to be observed or trigger an alert.

## Troubleshooting and limitations

- A rule that never appears to match may be disabled, ordered after a catch-all, or using a different exact IP/protocol/port value.
- A subnet written as CIDR will not match as a range.
- `allow` does not bypass global/per-source rate limiting.
- `block` and detection decisions are application logs, not OS-level packet enforcement.
- The configured sample descriptions do not establish that any address is malicious.

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for environment and dashboard diagnostics.
