from detection.tcp_stream_reassembler import TCPStreamReassembler
from detection.http_slowloris_detector import HTTPSlowlorisDetector
from scapy.all import sniff, IP, TCP, UDP
from pathlib import Path
from datetime import datetime
import pandas as pd
import joblib
import os

from firewall.firewall_controller import execute_action
from detection.attack_analyzer import analyze_attack
from detection.risk_engine import calculate_risk
from firewall.decision_engine import make_firewall_decision
from detection.tcp_connection_tracker import TCPConnectionTracker

# ==========================================
# CONFIGURATION
# ==========================================

INTERFACE = os.getenv(
    "FIREWALL_INTERFACE",
     "wlo1"
)
LOCAL_IP = os.getenv(
    "FIREWALL_LOCAL_IP",
    "192.168.1.135"
)
WINDOW_SECONDS = 5

# Track TCP connections across detection windows.
tcp_tracker = TCPConnectionTracker(
    connection_timeout=300,
    long_lived_threshold=30
)
# TCP stream reconstruction
tcp_reassembler = TCPStreamReassembler(
    connection_timeout=60,
    maximum_buffer=262144
)

# HTTP-aware Slowloris detection
http_detector = HTTPSlowlorisDetector(
    header_timeout=10,
    minimum_incomplete_requests=3,
    connection_timeout=60
)

# Plaintext HTTP ports monitored initially
# ==========================================
# HTTP CONFIGURATION
# ==========================================

HTTP_PORTS = {80, 8080}

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ==========================================
# FINAL EXPERIMENTAL MODEL
# ==========================================

MODEL_FILE = (
    PROJECT_ROOT /
    "models" /
    "trained" /
    "isolation_forest_experimental_20261031.pkl"
)


# ==========================================
# FEATURES USED BY ISOLATION FOREST
# ==========================================

FEATURES = [
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
# LOAD MODEL
# ==========================================

print("==========================================")
print("       AI FIREWALL LIVE DETECTOR")
print("==========================================\n")
print("==========================================")
print("       AI FIREWALL LIVE DETECTOR")
print("==========================================\n")

print("Loading AI model...")

model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")

print(f"Interface : {INTERFACE}")
print(f"Window    : {WINDOW_SECONDS} seconds")

print("\nStarting live detection...\n")


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def analyze_packets(packets):

    packet_count = len(packets)

    total_bytes = sum(len(packet) for packet in packets)

    tcp_count = 0
    udp_count = 0
    outgoing_tcp_syn_count = 0
    icmp_count = 0

    tcp_syn_count = 0
    tcp_rst_count = 0

    source_ports = set()
    outgoing_tcp_destination_ports = set()
    source_ips = set()
    destination_ips = set()
    destination_ports = set()

    for packet in packets:

        tcp_tracker.process_packet(packet)

        # HTTP-aware TCP stream processing
        if packet.haslayer(IP) and packet.haslayer(TCP):

            tcp = packet[TCP]

            connection_id = (
                packet[IP].src,
                int(tcp.sport),
                packet[IP].dst,
                int(tcp.dport)
            )

            reverse_id = (
                packet[IP].dst,
                int(tcp.dport),
                packet[IP].src,
                int(tcp.sport)
            )

            stream_result = tcp_reassembler.process_packet(packet)

            if int(tcp.dport) in HTTP_PORTS:

                if tcp_reassembler.is_ambiguous(connection_id):

                    http_detector.close_connection(connection_id)

                elif stream_result is not None:

                    stream_id, payload = stream_result

                    if payload:

                        http_detector.process_payload(
                            stream_id[0],
                            stream_id,
                            payload
                        )

            # TCP FIN or RST
            flags = int(tcp.flags)

            if flags & 0x05:

                http_detector.close_connection(connection_id)
                http_detector.close_connection(reverse_id)

        if not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]

        source_ips.add(ip_layer.src)
        destination_ips.add(ip_layer.dst)

        if packet.haslayer(TCP):

            tcp_count += 1

            flags = int(packet[TCP].flags)

            destination_ports.add(packet[TCP].dport)

            if ip_layer.src == LOCAL_IP and flags & 0x02:

                outgoing_tcp_destination_ports.add(
                    packet[TCP].dport
                )

            source_ports.add(packet[TCP].sport)

            if (flags & 0x02) and not (flags & 0x10):
                tcp_syn_count += 1

            if flags & 0x02 and ip_layer.src == LOCAL_IP:
                outgoing_tcp_syn_count += 1

            if flags & 0x04:
                tcp_rst_count += 1

        elif packet.haslayer(UDP):

            udp_count += 1

            destination_ports.add(packet[UDP].dport)

        elif ip_layer.proto == 1:

            icmp_count += 1

    return {

        "packets_per_second":
            packet_count / WINDOW_SECONDS,

        "bytes_per_second":
            total_bytes / WINDOW_SECONDS,

        "tcp_count":
            tcp_count,

        "udp_count":
            udp_count,

        "icmp_count":
            icmp_count,

        "unique_source_ips":
            len(source_ips),

        "unique_destination_ips":
            len(destination_ips),

        "unique_destination_ports":
            len(destination_ports),

        "tcp_syn_count":
            tcp_syn_count,

        "outgoing_tcp_syn_count":
            outgoing_tcp_syn_count,

        "outgoing_tcp_destination_ports":
            len(outgoing_tcp_destination_ports),

        "tcp_rst_count":
            tcp_rst_count,

        "unique_source_ports":
            len(source_ports),

        **tcp_tracker.get_statistics()
    }


# ==========================================
# LIVE DETECTION LOOP
# ==========================================

while True:

    print("------------------------------------------")

    print(
        f"Capturing traffic for "
        f"{WINDOW_SECONDS} seconds..."
    )

    start_time = datetime.now()

    # Capture traffic
    packets = sniff(
        iface=INTERFACE,
        timeout=WINDOW_SECONDS,
        store=True
    )

    # Extract features
    features = analyze_packets(
        packets
    )



    # ======================================
    # 1. ISOLATION FOREST
    # ======================================

    X = pd.DataFrame(
        [features],
        columns=FEATURES
    )

    prediction = model.predict(X)[0]

    score = model.decision_function(X)[0]

    if prediction == 1:
        result = "NORMAL"
    else:
        result = "ANOMALY"


    ai_result = {
        "status": result,
        "anomaly_score": float(score)
    }


    # ======================================
    # 2. ATTACK ANALYZER
    # ======================================

    attack_result = analyze_attack(
        features
    )



    # ======================================
    # HTTP-AWARE SLOWLORIS DETECTION
    # ======================================

    http_result = http_detector.get_statistics()

    if http_result["alerts"]:

        for alert in http_result["alerts"]:

            attack_result["attack_type"] = "Possible HTTP Slowloris"

            attack_result["risk_score"] = max(
                attack_result["risk_score"],
                40
            )

            reason = (
                f"HTTP Slowloris detected from "
                f"{alert['client_ip']}: "
                f"{alert['incomplete_requests']} incomplete requests"
            )

            if reason not in attack_result["reasons"]:
                attack_result["reasons"].append(reason)

    print("\nHTTP DETECTION")

    print(
        "Incomplete HTTP requests:",
        http_result["incomplete_http_requests"]
    )

    print(
        "HTTP Slowloris alerts:",
        len(http_result["alerts"])
    )


    # ======================================
    # 3. RISK ENGINE
    # ======================================

    risk_result = calculate_risk(
        ai_result,
        attack_result
    )


    # ======================================
    # 4. FIREWALL DECISION
    # ======================================

    firewall_result = make_firewall_decision(
        risk_result,
        attack_result
    )



    # ======================================
    # DISPLAY TRAFFIC FEATURES
    # ======================================

    print("\nTraffic Features:")

    for key, value in features.items():

        print(
            f"{key}: {value}"
        )


    # ======================================
    # AI RESULT
    # ======================================

    print("\nAI RESULT")

    print(
        f"Status        : {result}"
    )

    print(
        f"Anomaly Score : {score:.4f}"
    )


    # ======================================
    # ATTACK ANALYSIS
    # ======================================

    print("\nATTACK ANALYSIS")

    print(
        f"Attack Type   : "
        f"{attack_result['attack_type']}"
    )

    print(
        f"Attack Risk   : "
        f"{attack_result['risk_score']}"
    )

    if attack_result["reasons"]:

        print("Reasons       :")

        for reason in attack_result["reasons"]:

            print(
                f"  - {reason}"
            )


    # ======================================
    # RISK ENGINE
    # ======================================

    print("\nRISK ENGINE")

    print(
        f"Risk Score    : "
        f"{risk_result['risk_score']}"
    )

    print(
        f"Severity      : "
        f"{risk_result['severity']}"
    )


    # ======================================
    # FIREWALL DECISION
    # ======================================

    print("\nFIREWALL DECISION")

    print(
        f"Action        : "
        f"{firewall_result['action']}"
    )

    print(
        f"Window Time   : "
        f"{start_time.strftime('%H:%M:%S')}"
    )
    execute_action(firewall_result)

