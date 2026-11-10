from detection.attack_analyzer import analyze_attack


normal_features = {

    "outgoing_tcp_destination_ports": 25,

    "outgoing_tcp_syn_count": 40,

    "unique_destination_ports": 25,

    "tcp_syn_count": 40,

    "packets_per_second": 80,

    "per_ip_statistics": {}
}

result = analyze_attack(
    normal_features
)

# =================================
# NORMAL TRAFFIC TEST
# =================================

normal_traffic = {
    "unique_destination_ports": 3,
    "tcp_syn_count": 2,
    "packets_per_second": 5,
    "per_ip_statistics": {}
}

normal_result = analyze_attack(normal_traffic)

print("\nNORMAL TRAFFIC TEST")
print(normal_result)


# =================================
# SLOWLORIS TEST
# =================================

slowloris_traffic = {
    "unique_destination_ports": 3,
    "tcp_syn_count": 2,
    "packets_per_second": 5,

    "per_ip_statistics": {
        "192.168.1.10": {
            "active_tcp_connections": 35,
            "long_lived_tcp_connections": 25,
            "mean_connection_age_seconds": 90
        }
    }
}

slowloris_result = analyze_attack(slowloris_traffic)

print("\nSLOWLORIS TEST")
print(slowloris_result)


print("================================")
print(" ATTACK ANALYZER TEST")
print("================================")

print(
    f"Attack Type: "
    f"{result['attack_type']}"
)

print(
    f"Risk Score: "
    f"{result['risk_score']}"
)

print(
    f"Reasons: "
    f"{result['reasons']}"
)

