import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP


class TCPConnectionTracker:
    def __init__(self, connection_timeout=300, long_lived_threshold=30):
        self.connection_timeout = connection_timeout
        self.long_lived_threshold = long_lived_threshold

        # Stores currently tracked TCP connections.
        self.connections = {}

        # Counts new connections observed in the current window.
        self.new_connections_this_window = 0

    def process_packet(self, packet):
        """Track TCP connections and retain their initiating client IP."""

        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        current_time = time.time()

        source = (ip_layer.src, int(tcp_layer.sport))
        destination = (ip_layer.dst, int(tcp_layer.dport))
        connection_key = tuple(sorted((source, destination)))

        flags = int(tcp_layer.flags)

        is_initial_syn = bool(flags & 0x02) and not bool(flags & 0x10)
        is_fin = bool(flags & 0x01)
        is_rst = bool(flags & 0x04)
        is_pure_ack = flags == 0x10 and len(tcp_layer.payload) == 0

        if is_initial_syn:
            if connection_key not in self.connections:
                self.connections[connection_key] = {
                    "start_time": current_time,
                    "last_seen": current_time,
                    "packets": 1,
                    "bytes": len(packet),
                    "fin_senders": set(),
                    "syn_observed": True,
                    "client_ip": ip_layer.src,
                }
                self.new_connections_this_window += 1

            else:
                connection = self.connections[connection_key]
                connection["last_seen"] = current_time
                connection["packets"] += 1
                connection["bytes"] += len(packet)

                if not connection["syn_observed"]:
                    connection["syn_observed"] = True
                    connection["client_ip"] = ip_layer.src

        elif connection_key in self.connections:
            connection = self.connections[connection_key]
            connection["last_seen"] = current_time
            connection["packets"] += 1
            connection["bytes"] += len(packet)

        elif not is_fin and not is_rst and not is_pure_ack:
            self.connections[connection_key] = {
                "start_time": current_time,
                "last_seen": current_time,
                "packets": 1,
                "bytes": len(packet),
                "fin_senders": set(),
                "syn_observed": False,
                "client_ip": None,
            }

        if connection_key in self.connections:
            connection = self.connections[connection_key]

            if is_rst:
                self.connections.pop(connection_key, None)

            elif is_fin:
                connection["fin_senders"].add(source)

                if len(connection["fin_senders"]) >= 2:
                    self.connections.pop(connection_key, None)

        self._remove_expired_connections(current_time)

    def _remove_expired_connections(self, current_time):
        """Remove connections exceeding the inactivity timeout."""

        expired = [
            key
            for key, connection in self.connections.items()
            if current_time - connection["last_seen"]
            > self.connection_timeout
        ]

        for key in expired:
            del self.connections[key]

    def get_statistics(self):
        """Return aggregate and per-client-IP TCP statistics."""

        current_time = time.time()
        self._remove_expired_connections(current_time)

        connection_ages = [
            current_time - connection["start_time"]
            for connection in self.connections.values()
        ]

        long_lived_count = sum(
            age >= self.long_lived_threshold
            for age in connection_ages
        )

        if connection_ages:
            mean_age = sum(connection_ages) / len(connection_ages)
            max_age = max(connection_ages)
        else:
            mean_age = 0.0
            max_age = 0.0

        # Group connections by their initiating client IP.
        per_ip_connections = defaultdict(list)

        for connection in self.connections.values():
            client_ip = connection["client_ip"]

            # Exclude connections whose initial SYN was not observed.
            if client_ip is not None:
                age = current_time - connection["start_time"]
                per_ip_connections[client_ip].append(age)

        per_ip_statistics = {}

        for client_ip, ages in per_ip_connections.items():
            per_ip_statistics[client_ip] = {
                "active_tcp_connections": len(ages),
                "long_lived_tcp_connections": sum(
                    age >= self.long_lived_threshold for age in ages
                ),
                "mean_connection_age_seconds": round(
                    sum(ages) / len(ages), 2
                ),
                "max_connection_age_seconds": round(max(ages), 2),
            }

        new_connections = self.new_connections_this_window
        self.new_connections_this_window = 0

        return {
            "new_tcp_connections": new_connections,
            "active_tcp_connections": len(self.connections),
            "long_lived_tcp_connections": long_lived_count,
            "mean_connection_age_seconds": round(mean_age, 2),
            "max_connection_age_seconds": round(max_age, 2),
            "per_ip_statistics": per_ip_statistics,
        }
