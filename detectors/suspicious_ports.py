from config import SUSPICIOUS_PORTS
from logger import log_alert


def detect_suspicious_port(ip_src, ip_dst, dport):
    if dport not in SUSPICIOUS_PORTS:
        return

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
            "protocol": "TCP",
        },
    )
