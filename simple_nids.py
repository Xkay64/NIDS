import argparse
import sys

from scapy.all import IP, TCP, UDP, get_if_list, sniff
from scapy.error import Scapy_Exception

from detectors.suspicious_ports import detect_suspicious_port
from detectors.syn_scan import detect_syn_scan
from detectors.port_scan import detect_port_scan


def detect_intrusion(packet, quiet=False):
    if IP not in packet:
        return

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


def validate_interface(interface):
    available_interfaces = get_if_list()

    if interface not in available_interfaces:
        available = ", ".join(available_interfaces)

        if not available:
            available = "none detected"

        raise ValueError(
            f"network interface '{interface}' was not found. "
            f"Available interfaces: {available}"
        )


def start_sniff(interface, quiet=False):
    try:
        validate_interface(interface)

    except ValueError as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 2

    print(
        f"[~] Starting NIDS on {interface}... "
        "Press Ctrl+C to stop."
    )

    if quiet:
        print(
            "[~] Quiet mode enabled: displaying alerts only."
        )

    try:
        sniff(
            iface=interface,
            prn=lambda packet: detect_intrusion(
                packet,
                quiet=quiet
            ),
            store=False
        )

    except PermissionError:
        print(
            "[!] Permission denied while opening the "
            f"'{interface}' interface. Try running with sudo.",
            file=sys.stderr
        )
        return 1

    except Scapy_Exception as exc:
        print(
            f"[!] Scapy error while monitoring "
            f"'{interface}': {exc}",
            file=sys.stderr
        )
        return 1

    except OSError as exc:
        print(
            f"[!] Operating system error while monitoring "
            f"'{interface}': {exc}",
            file=sys.stderr
        )
        return 1

    except KeyboardInterrupt:
        print("\n[~] NIDS stopped by user.")

    return 0


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

    sys.exit(
        start_sniff(
            interface=args.interface,
            quiet=args.quiet
        )
    )
