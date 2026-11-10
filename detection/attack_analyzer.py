def analyze_attack(features):

    reasons = []

    risk = 0


    # --------------------------------
    # High number of destination ports
    # --------------------------------

    if features["unique_destination_ports"] >= 15:

        risk += 40

        reasons.append(
            "Many destination ports"
        )


    # --------------------------------
    # Large number of SYN packets
    # --------------------------------

    if features["tcp_syn_count"] >= 20:

        risk += 25

        reasons.append(
            "High TCP SYN activity"
        )


    # --------------------------------
    # High packet rate
    # --------------------------------

    if features["packets_per_second"] >= 50:

        risk += 25

        reasons.append(
            "High packet rate"
        )
        # --------------------------------
    # New: Slowloris indicators
    # Check each source IP separately
    # --------------------------------

    per_ip_statistics = features.get(
        "per_ip_statistics", {}
    )

    slowloris_detected = False

    for client_ip, stats in per_ip_statistics.items():

        if (
            stats["active_tcp_connections"] >= 30
            and stats["long_lived_tcp_connections"] >= 20
            and stats["mean_connection_age_seconds"] >= 60
        ):

            slowloris_detected = True

            reasons.append(
                f"Possible Slowloris behavior from {client_ip}"
            )

    if slowloris_detected:
        risk += 40

    # --------------------------------
    # Determine behavior
    # --------------------------------


    if slowloris_detected:

        attack_type = "Possible Slowloris"

    elif (
    features.get("outgoing_tcp_destination_ports", 0) >= 15
    and
    features.get("outgoing_tcp_syn_count", 0) >= 20
):

        attack_type = "Possible Port Scan"

    elif features["packets_per_second"] >= 50:

        attack_type = "Traffic Spike"

    else:

        attack_type = "Unknown"

    # --------------------------------
    # Limit risk
    # --------------------------------

    risk = min(risk, 100)


    return {
        "attack_type": attack_type,
        "risk_score": risk,
        "reasons": reasons
    }
