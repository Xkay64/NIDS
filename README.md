# Simple Network Intrusion Detection System — NIDS v2

A lightweight Python-based Network Intrusion Detection System built with
Scapy for monitoring network traffic and detecting suspicious activity in
real time.

NIDS v2 expands the original project with time-based detection, modular
detectors, structured alerting, external configuration, automated testing,
and continuous integration.

## Features

- Real-time network packet monitoring
- Suspicious destination-port detection
- SYN-volume scan detection
- Unique destination-port scan detection
- Time-window-based detection
- Alert deduplication and cooldown
- Severity-based alert classification
- Human-readable text alerts
- Structured JSONL alerts
- External TOML configuration
- Quiet / alert-only monitoring mode
- Modular detector architecture
- Automated tests with pytest
- GitHub Actions continuous integration
- Startup and configuration validation

## Detection Rules

### Suspicious Port Detection

Monitors TCP traffic for configured suspicious destination ports.

Default ports:

- 23 — Telnet
- 4444 — commonly associated with reverse shells/backdoors
- 31337 — commonly associated with backdoor activity

### SYN Scan Detection

Detects high volumes of TCP SYN packets from a source IP within a
configured time window.

Default configuration:

- Threshold: 100 SYN packets
- Window: 10 seconds

### Unique-Port Scan Detection

Detects a source probing multiple unique destination ports on the same
target within a configured time period.

Default configuration:

- Threshold: 20 unique destination ports
- Window: 10 seconds

## Project Structure

```text
NIDS/
├── simple_nids.py
├── config.py
├── logger.py
├── nids.toml
├── detectors/
│   ├── __init__.py
│   ├── suspicious_ports.py
│   ├── syn_scan.py
│   └── port_scan.py
├── tests/
├── requirements.txt
├── requirements-dev.txt
└── .github/
    └── workflows/
        └── tests.yml

## Architecture

Traffic is captured using Scapy and passed to independent detection
modules.

Network Interface
       |
       v
 simple_nids.py
       |
       +------------------------+
       |                        |
       v                        v
TCP/UDP parsing          Detector modules
                                |
                 +--------------+--------------+
                 |              |              |
                 v              v              v
          Suspicious Port    SYN Scan      Port Scan
                 |              |              |
                 +--------------+--------------+
                                |
                                v
                            logger.py
                           /         \
                          v           v
                    alerts.log   alerts.jsonl

Detection thresholds and logging settings are loaded from nids.toml.

## Installation

Clone the repository:
git clone git@github.com:Xkay64/NIDS.git
cd NIDS

Create a virtual environment:
python3 -m venv .venv
source .venv/bin/activate

Install runtime dependencies:
pip install -r requirements.txt

For development and testing:
pip install -r requirements-dev.txt

## Usage

Display help:
python3 simple_nids.py --help

Monitor an interface:
sudo .venv/bin/python simple_nids.py --interface eth0
                     or 
sudo .venv/bin/python simple_nids.py -i eth0

Alert-only quiet mode:
sudo .venv/bin/python simple_nids.py -i eth0 --quiet
                     or
sudo .venv/bin/python simple_nids.py -i eth0 --quiet

## Configuration
Detection settings can be changed without modifying Python source code.

Example nids.toml:
[logging]
text_log = "alerts.log"
json_log = "alerts.jsonl"
alert_cooldown_seconds = 60

[detection.suspicious_ports]
ports = [23, 4444, 31337]

[detection.syn_scan]
threshold = 100
time_window_seconds = 10

[detection.port_scan]
threshold = 20
time_window_seconds = 10

## Alert Output

Human-readable example:

[HIGH] [SYN_SCAN] Possible SYN scan from 192.168.1.10:
101 SYN packets within 10 seconds

JSONL example:

{
  "severity": "HIGH",
  "event_type": "SYN_SCAN",
  "source_ip": "192.168.1.10",
  "syn_count": 101,
  "window_seconds": 10,
  "protocol": "TCP"
}

## Testing

Run the automated test suite:
.venv/bin/python -m pytest -v

GitHub Actions automatically runs the test suite on configured pushes and
pull requests.

## Lab Testing

Development testing was performed in an isolated virtual lab using Kali
Linux and intentionally vulnerable lab systems.

Detection behavior was validated with tools including:

Nmap
hping3
Netcat

Examples included:

high-volume SYN activity
unique-port scanning
suspicious TCP port access
below-threshold negative tests

Only systems owned or explicitly authorized for testing should be scanned.

## NIDS v1 to v2

NIDS v2 adds:

time-windowed SYN analysis
alert deduplication
unique-port scan detection
structured severity and event types
JSONL logging
external configuration
modular architecture
automated testing
continuous integration
command-line options
quiet monitoring
startup validation and error handling

## Disclaimer

This project is designed for educational, laboratory, and defensive
security research purposes.

It is not intended to replace a production-grade IDS/IPS platform.

## Author

Ganiyu Ridwan Olayiwola

GitHub: Xkay64
