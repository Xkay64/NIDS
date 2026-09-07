from scapy.all import sniff, IP, TCP, UDP

from detectors.suspicious_ports import detect_suspicious_port
from detectors.syn_scan import detect_syn_scan
from detectors.port_scan import detect_port_scan

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

            detect_suspicious_port(ip_src, ip_dst, dport)

            # Detect SYN-based suspicious activity
            if flags == "S":
                detect_syn_scan(ip_src)
            detect_port_scan(ip_src, ip_dst, dport)

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
