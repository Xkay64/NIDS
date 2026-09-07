import argparse

from scapy.all import sniff, IP, TCP, UDP

from detectors.suspicious_ports import detect_suspicious_port
from detectors.syn_scan import detect_syn_scan
from detectors.port_scan import detect_port_scan


def detect_intrusion(packet, quiet=False):
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

            if flags == "S":
                detect_syn_scan(ip_src)
                detect_port_scan(ip_src, ip_dst, dport)

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        if not quiet:
            print(
                f"[*] {ip_src}:{sport} -> {ip_dst}:{dport} | "
                f"Proto: {proto} | Len: {pkt_len}"
            )


def start_sniff(interface, quiet=False):
    print(f"[~] Starting NIDS on {interface}... Press Ctrl+C to stop.")

    if quiet:
        print("[~] Quiet mode enabled: displaying alerts only.")

    sniff(
        iface=interface,
        prn=lambda packet: detect_intrusion(packet, quiet=quiet),
        store=False
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Simple Network Intrusion Detection System"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface to monitor, e.g. eth0"
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress normal packet output and display alerts only"
    )

    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    start_sniff(
        interface=args.interface,
        quiet=args.quiet
    )
