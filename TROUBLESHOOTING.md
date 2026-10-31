# PyGuard Troubleshooting

Use this guide for Windows setup, capture and dashboard issues. Command examples are kept in [commands.md](commands.md). The repository does not declare a supported Python version; Python 3.11 is a practical suggested starting point, not a tested compatibility guarantee.

## Python command is not found

**Symptoms:** `python` or `py` is not recognized.

**Likely cause:** Python is not installed or its launcher is unavailable in `PATH`.

**Steps:** Install Python from the official Python distribution, enable the launcher/PATH options, and reopen PowerShell. Use [commands.md](commands.md) for setup steps.

## Virtual environment activation fails

**Symptoms:** `Activate.ps1` is blocked or the environment does not activate.

**Likely cause:** PowerShell execution policy or an incomplete `.venv`.

**Steps:** Recreate the virtual environment using the setup steps in [commands.md](commands.md). If activation is unavailable, use the environment's Python executable directly. Follow your organization's PowerShell execution policy.

## Dependency installation fails

**Symptoms:** pip reports build, network or package errors.

**Likely cause:** unsupported interpreter, unavailable package index/network, or missing platform build prerequisites.

**Steps:** Confirm Python is available, update pip inside the environment, and install the dependencies listed in `requirements.txt`. The dependency list is not pinned to upper versions; this project has no verified clean-install matrix. Setup steps are in [commands.md](commands.md).

## `No module named pyguard` or wrong working directory

**Symptoms:** startup fails to import the package.

**Likely cause:** command was run outside the repository root.

**Steps:** Confirm the current folder contains both `README.md` and the `pyguard` directory. Change to the project folder, activate the environment, and follow the startup steps in [commands.md](commands.md).

## Dashboard does not open

**Symptoms:** browser connection is refused or the page keeps loading.

**Likely cause:** the Flask process stopped, startup failed, or port 5000 is unavailable.

**Steps:** Read the server terminal for a traceback and confirm it still runs. Check whether another local service occupies port 5000. If occupied, stop that service or select another available port using the web command's port option.

## Port 5000 is already in use

**Symptoms:** Flask reports that the address/port is in use.

**Likely cause:** another process is listening on that port.

**Steps:** Identify the process using port 5000, stop that service if appropriate, or choose another available port through the web command's port option. Use the matching port in the browser.

## Packet capture provider unavailable

**Symptoms:** Scapy reports that no capture provider/libpcap/Npcap is available.

**Likely cause:** Npcap is missing on Windows or libpcap is missing on Linux.

**Steps:** On Windows, install [Npcap](https://npcap.com/), reopen PowerShell, then retry capture. On Linux, install the distribution's libpcap package and verify Scapy can access it. The dashboard itself does not require successful capture.

## No interfaces or capture permission errors

**Symptoms:** capture cannot open an interface, or access is denied.

**Likely cause:** incorrect interface name, unavailable adapter, missing privileges or provider configuration.

**Steps:** Check the network adapter names and select the correct interface in PyGuard. Confirm Npcap is installed and permitted to capture. On Linux, inspect available interfaces and capture capabilities. Elevated privileges may be required. Avoid changing system firewall policy as a diagnostic shortcut.

## Capture starts but no traffic appears

**Symptoms:** status indicates capture but the event stream remains quiet.

**Likely cause:** wrong interface, no matching IPv4 traffic, or the default BPF filter (`ip`) excludes traffic of interest.

**Steps:** Verify the selected interface is active and that it carries IPv4 traffic. Check capture logs for errors. PyGuard does not parse IPv6. Packet capture visibility can vary for loopback traffic and virtual adapters.

## Rule display or match is unexpected

**Symptoms:** an added rule does not appear to take effect or rules differ from expected.

**Likely cause:** invalid JSON, disabled rule, exact-match mismatch or first-match ordering. The shipped final catch-all can shadow appended rules.

**Steps:** Inspect `pyguard/config/rules.json`, validate its JSON syntax, check `enabled`, and place specific rules before catch-all. See [rules.md](rules.md). IP ranges in CIDR notation are not supported.

## Empty logs or missing alerts

**Symptoms:** the log file is absent/empty or a demo generated no alert.

**Likely cause:** no capture/simulation/test event has occurred, capture is unavailable, or detector thresholds were not reached.

**Steps:** Run a supported local simulator or use a dashboard rule tester, then inspect `pyguard/logs/pyguard.log`. Rule tests are synthetic; simulator traffic may not be visible to capture. Absence of an alert does not show that a packet was blocked. The logger creates the directory when writing an event. Log viewing steps are in [commands.md](commands.md).

## Dashboard API or display errors

**Symptoms:** a dashboard section fails to update or reports an error.

**Likely cause:** server-side exception, malformed configuration or unavailable optional geolocation provider.

**Steps:** Inspect the Flask terminal and log file. Restart only after recording the error. Geolocation requires a valid provider key (`IPGEO_API_KEY` or configured key); basic dashboard features do not. Never share API keys in logs or screenshots.

## Configuration file is missing or invalid

**Symptoms:** rules cannot load or a feature reports a configuration error.

**Likely cause:** the file was moved, edited with invalid JSON, or command was run from an unexpected location.

**Steps:** Confirm `pyguard/config/rules.json` exists. Restore the project's version if needed, then make small edits while preserving valid JSON. Do not publish secrets from geolocation configuration.

## Stopping a process

Stop the web or CLI capture process from the terminal that owns it. The CLI stop action in a separate process does not control the foreground sniffer's in-memory state. See [commands.md](commands.md) for the shutdown key sequence.
