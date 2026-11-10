import time
import os
import csv
from pathlib import Path
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP

from capture.packet_parser import parse_packet
from capture.traffic_logger import save_packet
from detection.tcp_connection_tracker import TCPConnectionTracker


# ==========================================
# CONFIGURATION
# ==========================================

INTERFACE = os.getenv("FIREWALL_INTERFACE", "wlo1")
WINDOW_SECONDS = 5

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BEHAVIOR_FILE = PROJECT_ROOT / "logs" / "behavior_live.csv"

FEATURE_COLUMNS = [
    "time_window",
    "packets_per_second",
    "bytes_per_second",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "unique_source_ips",
    "unique_destination_ips",
    "unique_destination_ports",
    "new_tcp_connections",
    "active_tcp_connections",
    "long_lived_tcp_connections",
    "mean_connection_age_seconds",
    "max_connection_age_seconds",
]

tcp_tracker = TCPConnectionTracker(
    connection_timeout=300,
    long_lived_threshold=30,
)


# ==========================================
# PACKET CALLBACK
# ==========================================

def process_packet(packet):
    """Track and log each packet captured by Scapy."""

    tcp_tracker.process_packet(packet)

    data = parse_packet(packet)

    if data:
        save_packet(data)


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def extract_window_features(packets):
    """Calculate traffic features for one observation window."""

    packet_count = len(packets)
    total_bytes = sum(len(packet) for packet in packets)

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    source_ips = set()
    destination_ips = set()
    destination_ports = set()

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]

        source_ips.add(ip_layer.src)
        destination_ips.add(ip_layer.dst)

        if packet.haslayer(TCP):
            tcp_count += 1
            destination_ports.add(int(packet[TCP].dport))

        elif packet.haslayer(UDP):
            udp_count += 1
            destination_ports.add(int(packet[UDP].dport))

        elif ip_layer.proto == 1:
            icmp_count += 1

    # Call exactly once per window because this resets the
    # tracker's new-connection counter.
    connection_stats = tcp_tracker.get_statistics()

    return {
        "time_window": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "packets_per_second": packet_count / WINDOW_SECONDS,
        "bytes_per_second": total_bytes / WINDOW_SECONDS,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "unique_destination_ports": len(destination_ports),
        **connection_stats,
    }


# ==========================================
# FEATURE LOGGING
# ==========================================

def save_behavior_row(features):
    """Append one feature row to behavior_live.csv."""

    BEHAVIOR_FILE.parent.mkdir(parents=True, exist_ok=True)

    file_exists = BEHAVIOR_FILE.exists()
    write_header = not file_exists or BEHAVIOR_FILE.stat().st_size == 0

    with BEHAVIOR_FILE.open("a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FEATURE_COLUMNS)

        if write_header:
            writer.writeheader()

        writer.writerow(features)


# ==========================================
# CAPTURE LOOP
# ==========================================

def main():
    print("================================")
    print(" AI FIREWALL FEATURE COLLECTOR")
    print("================================")
    print(f"Interface: {INTERFACE}")
    print(f"Window: {WINDOW_SECONDS} seconds")
    print(f"Feature output: {BEHAVIOR_FILE}")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            window_start = datetime.now()
            monotonic_start = time.monotonic()

            packets = sniff(
                iface=INTERFACE,
                timeout=WINDOW_SECONDS,
                prn=process_packet,
                store=True,
            )

            elapsed = time.monotonic() - monotonic_start
            remaining = WINDOW_SECONDS - elapsed

            if remaining > 0:
                time.sleep(remaining)

            features = extract_window_features(packets)
            features["time_window"] = window_start.strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )

            save_behavior_row(features)

            print(
                f"[{features['time_window']}] "
                f"packets={len(packets)}, "
                f"TCP={features['tcp_count']}, "
                f"UDP={features['udp_count']}, "
                f"new_connections={features['new_tcp_connections']}, "
                f"active_connections={features['active_tcp_connections']}"
            )

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
