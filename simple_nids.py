from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timedelta

from config import (
    ALERT_LOG,
    JSON_ALERT_LOG,
    SUSPICIOUS_PORTS,
    SYN_ONLY_THRESHOLD,
    SYN_TIME_WINDOW_SECONDS,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW_SECONDS,
    ALERT_COOLDOWN_SECONDS,
)

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timedelta

from config import (
    SUSPICIOUS_PORTS,
    SYN_ONLY_THRESHOLD,
    SYN_TIME_WINDOW_SECONDS,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW_SECONDS,
)

from logger import log_alert

SYN_TIME_WINDOW = timedelta(seconds=SYN_TIME_WINDOW_SECONDS)
PORT_SCAN_TIME_WINDOW = timedelta(
    seconds=PORT_SCAN_TIME_WINDOW_SECONDS
)

syn_timestamps = {}
port_scan_activity = {}

def detect_intrusion(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        pkt_len = len(packet)

        sport = dport = flags = None
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags

            # Detect suspicious destination ports
            if dport in SUSPICIOUS_PORTS:
                alert_key = f"suspicious_port:{ip_src}:{ip_dst}:{dport}"
                log_alert(
                    f"Suspicious port access from {ip_src} to {ip_dst} "
                    f"on destination port {dport}",
                    alert_key,
                    severity="MEDIUM",
                    event_type="SUSPICIOUS_PORT",
                    details={
                        "source_ip": ip_src,
                        "destination_ip": ip_dst,
                        "destination_port": dport,
                        "protocol": "TCP"
                    }
                )

            # Detect SYN-based suspicious activity
            if flags == "S":
                now = datetime.now()

                # SYN volume detection
                if ip_src not in syn_timestamps:
                    syn_timestamps[ip_src] = []

                syn_timestamps[ip_src].append(now)

                cutoff_time = now - SYN_TIME_WINDOW
                syn_timestamps[ip_src] = [
                    timestamp
                    for timestamp in syn_timestamps[ip_src]
                    if timestamp >= cutoff_time
                ]

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
                            "protocol": "TCP"
                        }
                    )

                # Unique destination port scan detection
                scan_key = (ip_src, ip_dst)

                if scan_key not in port_scan_activity:
                    port_scan_activity[scan_key] = []

                port_scan_activity[scan_key].append((now, dport))

                port_cutoff = now - PORT_SCAN_TIME_WINDOW
                port_scan_activity[scan_key] = [
                    (timestamp, port)
                    for timestamp, port in port_scan_activity[scan_key]
                    if timestamp >= port_cutoff
                ]

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
                            "protocol": "TCP"
                        }
                    )

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        print(
            f"[*] {ip_src}:{sport} -> {ip_dst}:{dport} | "
            f"Proto: {proto} | Len: {pkt_len}"
        )


def start_sniff(interface="eth0"):
    print(f"[~] Starting NIDS on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=detect_intrusion, store=False)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: sudo python3 simple_nids.py <interface>")
        print("Example: sudo python3 simple_nids.py eth0")
        sys.exit(1)
    start_sniff(sys.argv[1])
