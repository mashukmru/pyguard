# PyGuard

PyGuard is an educational Python application for observing supported IPv4 traffic, evaluating configurable rules, recording rate-limit and suspicious-activity events, and presenting status in a local Flask dashboard. Its decisions are logged; it does not drop packets through the operating system firewall.

## Table of contents

- [Overview](#overview)
- [Key features](#key-features)
- [Technology stack](#technology-stack)
- [System requirements](#system-requirements)
- [Installation and setup](#installation-and-setup)
- [Run PyGuard](#run-pyguard)
- [Access the dashboard](#access-the-dashboard)
- [Use the main features](#use-the-main-features)
- [Project structure](#project-structure)
- [Logs and alerts](#logs-and-alerts)
- [Troubleshooting](#troubleshooting)
- [Testing and validation](#testing-and-validation)
- [Security and operational limitations](#security-and-operational-limitations)
- [Documentation](#documentation)
- [Project status](#project-status)

## Overview

PyGuard combines Scapy packet capture, first-match rule evaluation, in-process rate limiting and basic suspicious-activity checks. Packet capture is started by the operator. The dashboard and CLI provide ways to inspect rules, run local simulations, and view recorded events.

## Key features

- Capture and parse IPv4 TCP, UDP and ICMP packets through Scapy.
- Evaluate configured source/destination addresses, ports and protocols.
- Apply per-source and global rate checks, and detect selected port-scan and brute-force patterns.
- Write JSON Lines events to a local log.
- Manage and test rules through the CLI and dashboard.
- Run constrained simulator actions against loopback addresses.

## Technology stack

- Python package and Click command-line interface
- Scapy for packet capture
- Flask for the dashboard and API
- Requests for optional IP geolocation lookups
- JSON configuration and JSON Lines event logging

## System requirements

The repository does not declare or test a supported Python version. Python 3.11 is a practical starting point for a fresh setup, but it is a recommendation, not a verified compatibility boundary. Dependencies are listed in `requirements.txt` without upper bounds.

On Windows, Scapy packet capture requires [Npcap](https://npcap.com/). Linux capture may require libpcap and suitable privileges/capabilities. The Flask dashboard can run without successful packet capture. PyGuard currently parses IPv4 only.

## Installation and setup

1. Download and extract the project ZIP, or use your existing project checkout.
2. Open PowerShell in the folder containing `README.md` and the `pyguard` directory.
3. Create and activate a virtual environment, then install the dependencies listed in `requirements.txt`. Copyable setup steps are in [commands.md](commands.md).

4. Install Npcap on Windows if packet capture is needed, then reopen the terminal. Capture may also need elevated permissions depending on the system.

The repository does not pin or test a Python version; clean-machine installation has not been verified as part of this documentation update.

## Run PyGuard

Start the web application from the project root using the steps in [commands.md](commands.md). Keep its terminal open while the server runs and stop it from that terminal. The CLI supports capture, rule management, simulation and log viewing. Packet capture started through the CLI should be stopped in the same process; a separate CLI process does not control that in-memory sniffer.

Starting the dashboard does not automatically start packet capture. Start capture using the dashboard control or the CLI from a separate terminal. Successful capture depends on Scapy, a capture provider, an available interface and permissions.

## Access the dashboard

With the server running, open:

- Homepage: <http://127.0.0.1:5000/>
- Dashboard: <http://127.0.0.1:5000/dashboard>
- About page: <http://127.0.0.1:5000/about>

The built-in Flask server currently binds to `0.0.0.0` by default. Use it only on a trusted local network; the application has no authentication and is not configured as a production server.

## Use the main features

- **Monitoring:** Start or stop packet capture in the dashboard. Capture status depends on host prerequisites.
- **Rules:** Review, create, test and remove rules. See [rules.md](rules.md) for match semantics and the catch-all rule caveat.
- **Simulator:** Use the built-in simulator only with loopback targets. Simulated connections do not guarantee corresponding captured alerts.
- **Logs:** Inspect the event log and dashboard log view. Rule tester actions create synthetic evaluations rather than sending network packets.
- **Geolocation:** Country lookup is optional and requires an `IPGEO_API_KEY` or provider key configured for the lookup service. Do not place secrets in shared documentation.

See the [demo guide](DEMO_GUIDE.md) for a safe walkthrough.

## Project structure

```text
pyguard/
├── __main__.py                 # Module entry point
├── main.py                     # Click CLI
├── config/                     # Rule and geolocation configuration
├── core/                       # Capture, firewall processing, rules, rate limits, logging
├── web/                        # Flask app, API, templates and static assets
├── attack_simulator/           # Loopback-constrained traffic simulators
├── utils/                      # Shared helpers
└── logs/                       # Runtime log directory, created as needed
```

## Logs and alerts

Events are written as JSON Lines to `pyguard/logs/pyguard.log`. The logger creates the directory when needed. The log has no configured rotation, so monitor its size during extended use. A recorded `block` decision is an application event, not proof that the operating system discarded the packet.

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for Windows-focused diagnostics, capture prerequisites and dashboard guidance.

## Testing and validation

No Python test suite or test command was found in the repository during documentation review. This update checked source references and Markdown links; it did not run the app, capture packets, or perform a clean installation. See the [project report](PROJECT_REPORT.md) for the evidence and limitations.

## Security and operational limitations

- PyGuard observes and records decisions; it does not enforce packet drops through Windows Firewall, iptables or nftables.
- Packet capture is operator-started, requires Scapy plus host-specific capture support, and covers IPv4 only.
- The Flask development server binds to all interfaces by default, with no authentication. Keep it on a trusted network and do not expose it as a production service.
- Rule matching uses exact IP strings and exact ports; CIDR matching is not implemented.
- Built-in simulator endpoints are constrained to loopback, but still generate local traffic. Use them only in a controlled environment.
- Detection thresholds are heuristics and have not been benchmarked for accuracy.

## Documentation

- [How PyGuard works](HOW_IT_WORKS.md)
- [Firewall rules](rules.md)
- [Demo guide](DEMO_GUIDE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Project report](PROJECT_REPORT.md)

## Project status

PyGuard is an educational prototype for local traffic observation, rule evaluation and demonstration. Its current scope and unverified operational requirements are described above; it should not be treated as a production firewall or intrusion-prevention system.
