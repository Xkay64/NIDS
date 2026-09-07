# NIDS v2 configuration

# Alert output files
ALERT_LOG = "alerts.log"
JSON_ALERT_LOG = "alerts.jsonl"

# Suspicious destination ports
SUSPICIOUS_PORTS = {
    23,     # Telnet
    4444,   # Common reverse shell / backdoor port
    31337   # Common backdoor port
}

# SYN-volume detection
SYN_ONLY_THRESHOLD = 100
SYN_TIME_WINDOW_SECONDS = 10

# Unique-port scan detection
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_TIME_WINDOW_SECONDS = 10

# Duplicate alert suppression
ALERT_COOLDOWN_SECONDS = 60
