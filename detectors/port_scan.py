from datetime import datetime, timedelta

from config import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW_SECONDS,
)
from logger import log_alert


PORT_SCAN_TIME_WINDOW = timedelta(
    seconds=PORT_SCAN_TIME_WINDOW_SECONDS
)

# Tracks recent destination ports for each source/destination pair
port_scan_activity = {}


def detect_port_scan(ip_src, ip_dst, dport):
    now = datetime.now()
    scan_key = (ip_src, ip_dst)

    if scan_key not in port_scan_activity:
        port_scan_activity[scan_key] = []

    # Record current destination port and timestamp
    port_scan_activity[scan_key].append((now, dport))

    # Remove activity outside the detection window
    cutoff_time = now - PORT_SCAN_TIME_WINDOW
    port_scan_activity[scan_key] = [
        (timestamp, port)
        for timestamp, port in port_scan_activity[scan_key]
        if timestamp >= cutoff_time
    ]

    # Count unique destination ports
    unique_ports = {
        port
        for _, port in port_scan_activity[scan_key]
    }

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        alert_key = f"port_scan:{ip_src}:{ip_dst}"

        log_alert(
            f"Possible port scan from {ip_src} to {ip_dst}: "
            f"{len(unique_ports)} unique destination ports within "
            f"{int(PORT_SCAN_TIME_WINDOW.total_seconds())} seconds",
            alert_key,
            severity="HIGH",
            event_type="PORT_SCAN",
            details={
                "source_ip": ip_src,
                "destination_ip": ip_dst,
                "unique_ports": len(unique_ports),
                "window_seconds": int(
                    PORT_SCAN_TIME_WINDOW.total_seconds()
                ),
                "protocol": "TCP",
            },
        )
