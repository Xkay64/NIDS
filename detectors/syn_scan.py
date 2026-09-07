from datetime import datetime, timedelta

from config import (
    SYN_ONLY_THRESHOLD,
    SYN_TIME_WINDOW_SECONDS,
)
from logger import log_alert


SYN_TIME_WINDOW = timedelta(seconds=SYN_TIME_WINDOW_SECONDS)

# Stores recent SYN timestamps for each source IP
syn_timestamps = {}


def detect_syn_scan(ip_src):
    now = datetime.now()

    if ip_src not in syn_timestamps:
        syn_timestamps[ip_src] = []

    # Record current SYN packet
    syn_timestamps[ip_src].append(now)

    # Remove timestamps outside the detection window
    cutoff_time = now - SYN_TIME_WINDOW
    syn_timestamps[ip_src] = [
        timestamp
        for timestamp in syn_timestamps[ip_src]
        if timestamp >= cutoff_time
    ]

    # Alert if SYN volume exceeds threshold
    if len(syn_timestamps[ip_src]) > SYN_ONLY_THRESHOLD:
        alert_key = f"syn_scan:{ip_src}"

        log_alert(
            f"Possible SYN scan from {ip_src}: "
            f"{len(syn_timestamps[ip_src])} SYN packets within "
            f"{int(SYN_TIME_WINDOW.total_seconds())} seconds",
            alert_key,
            severity="HIGH",
            event_type="SYN_SCAN",
            details={
                "source_ip": ip_src,
                "syn_count": len(syn_timestamps[ip_src]),
                "window_seconds": int(
                    SYN_TIME_WINDOW.total_seconds()
                ),
                "protocol": "TCP",
            },
        )
