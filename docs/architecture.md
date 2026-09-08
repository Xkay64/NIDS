# NIDS v2 Architecture

## Overview

NIDS v2 follows a modular architecture designed to separate packet
capture, detection logic, configuration, and alert generation.

## Packet Processing Flow

```text
Network Interface
       |
       v
Scapy Packet Capture
       |
       v
simple_nids.py
       |
       +-- Extract source/destination IP
       +-- Identify TCP/UDP
       +-- Extract ports and TCP flags
       |
       v
Detection Modules
       |
       +-- suspicious_ports.py
       +-- syn_scan.py
       +-- port_scan.py
       |
       v
logger.py
       |
       +-- Alert cooldown
       +-- Severity
       +-- Event type
       |
       +----------+
       |          |
       v          v
 alerts.log   alerts.jsonl

## Modules

# simple_nids.py

Acts as the packet-capture and orchestration layer.

Responsibilities:

* CLI argument handling
* network interface validation
* packet capture
* protocol extraction
* forwarding traffic to detection modules
* quiet-mode console control

# config.py

Loads and validates nids.toml.

Responsibilities:

* log paths
* detection thresholds
* time windows
* suspicious ports
* alert cooldown

# logger.py

Central alert-processing component.

Responsibilities:

* duplicate suppression
* human-readable alerts
* JSONL alerts
* severity and event classification

## detectors/suspicious_ports.py

Detects configured suspicious TCP destination ports.

## detectors/syn_scan.py

Tracks recent SYN timestamps per source and detects high-volume SYN
activity inside the configured time window.

## detectors/port_scan.py

Tracks unique destination ports for each source/destination pair and
detects rapid multi-port probing.

## Design Goal

The modular design allows individual detection rules to be changed or
extended without modifying packet capture or logging logic.
