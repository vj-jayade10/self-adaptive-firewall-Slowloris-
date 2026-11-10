import csv
import os
import time
import uuid

from pathlib import Path
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP
from detection.tcp_connection_tracker import TCPConnectionTracker


# ==========================================
# CONFIGURATION
# ==========================================

INTERFACE = os.getenv("FIREWALL_INTERFACE", "wlo1")

WINDOW_SECONDS = 5

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_FILE = PROJECT_ROOT / "data" / "normal_test_sessions.csv"

SESSION_ID = str(uuid.uuid4())

SESSION_LABEL = "candidate_normal_unverified"


# ==========================================
# TCP CONNECTION TRACKER
# ==========================================

tcp_tracker = TCPConnectionTracker(
    connection_timeout=300,
    long_lived_threshold=30
)


# ==========================================
# CSV COLUMNS
# ==========================================

COLUMNS = [
    "timestamp",
    "session_id",
    "session_label",
    "interface",
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
    "max_connection_age_seconds"
]


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def collect_features(packets, elapsed):

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    total_bytes = 0

    source_ips = set()
    destination_ips = set()
    destination_ports = set()

    for packet in packets:

        total_bytes += len(packet)

        tcp_tracker.process_packet(packet)

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

    tcp_stats = tcp_tracker.get_statistics()

    return {

        "timestamp": datetime.now().isoformat(),

        "session_id": SESSION_ID,

        "session_label": SESSION_LABEL,

        "interface": INTERFACE,

        "packets_per_second": len(packets) / elapsed,

        "bytes_per_second": total_bytes / elapsed,

        "tcp_count": tcp_count,

        "udp_count": udp_count,

        "icmp_count": icmp_count,

        "unique_source_ips": len(source_ips),

        "unique_destination_ips": len(destination_ips),

        "unique_destination_ports": len(destination_ports),

        "new_tcp_connections": tcp_stats.get("new_tcp_connections", 0),

        "active_tcp_connections": tcp_stats.get("active_tcp_connections", 0),

        "long_lived_tcp_connections": tcp_stats.get("long_lived_tcp_connections", 0),

        "mean_connection_age_seconds": tcp_stats.get("mean_connection_age_seconds", 0),

        "max_connection_age_seconds": tcp_stats.get("max_connection_age_seconds", 0)

    }


# ==========================================
# SAVE DATA
# ==========================================

def save_features(features):

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    file_exists = OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0

    with OUTPUT_FILE.open("a", newline="") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=COLUMNS
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(features)


# ==========================================
# MAIN COLLECTION LOOP
# ==========================================

def main():

    print("======================================")
    print(" INDEPENDENT NORMAL TRAFFIC COLLECTOR")
    print("======================================")

    print("Interface:", INTERFACE)
    print("Session ID:", SESSION_ID)
    print("Output:", OUTPUT_FILE)
    print("Window:", WINDOW_SECONDS, "seconds")

    print("\nCollection label:", SESSION_LABEL)

    print("\nPress CTRL+C to stop collection.\n")

    try:

        while True:

            start = time.monotonic()

            packets = sniff(
                iface=INTERFACE,
                timeout=WINDOW_SECONDS,
                store=True
            )

            elapsed = time.monotonic() - start

            features = collect_features(
                packets,
                max(elapsed, 0.001)
            )

            save_features(features)

            print(
                "Packets/sec:",
                round(features["packets_per_second"], 2),
                "| TCP:",
                features["tcp_count"],
                "| UDP:",
                features["udp_count"],
                "| Active TCP:",
                features["active_tcp_connections"]
            )

    except KeyboardInterrupt:

        print("\nCollection stopped.")

        print("Session ID:", SESSION_ID)

        print("Data saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
