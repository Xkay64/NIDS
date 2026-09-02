from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timedelta

ALERT_LOG = "alerts.log"
SUSPICIOUS_PORTS = [4444, 31337, 23]  # Backdoor/Telnet
SYN_ONLY_THRESHOLD = 100  # SYN packets per IP before flagging
syn_counter = {}

ALERT_COOLDOWN = timedelta(seconds=60)
last_alert_time = {}

def log_alert(message, alert_key):
    now = datetime.now()

    if alert_key in last_alert_time:
        if now - last_alert_time[alert_key] < ALERT_COOLDOWN:
            return

    last_alert_time[alert_key] = now

    timestamp = now.strftime("[%Y-%m-%d %H:%M:%S]")
    log_entry = f"{timestamp} {message}"

    print(log_entry)

    with open(ALERT_LOG, "a") as log_file:
        log_file.write(log_entry + "\n")

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
                    f"[!] Suspicious port access from {ip_src} to port {dport}",
                    alert_key
                )

            # Detect SYN scan
            if flags == "S":
                syn_counter[ip_src] = syn_counter.get(ip_src, 0) + 1
                if syn_counter[ip_src] > SYN_ONLY_THRESHOLD:
                    alert_key = f"syn_scan:{ip_src}"
                    log_alert(
                        f"[!] Possible SYN scan from {ip_src}",
                        alert_key
                    )

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        print(f"[*] {ip_src}:{sport} -> {ip_dst}:{dport} | Proto: {proto} | Len: {pkt_len}")

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
