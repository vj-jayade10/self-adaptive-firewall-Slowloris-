import time
from collections import defaultdict


class HTTPSlowlorisDetector:
    def __init__(
        self,
        header_timeout=10,
        minimum_incomplete_requests=3,
        connection_timeout=60,
        maximum_header_size=65536,
        header_idle_timeout=5,
        maximum_slow_header_bytes=55,
    ):
        self.header_timeout = header_timeout
        self.minimum_incomplete_requests = minimum_incomplete_requests
        self.connection_timeout = connection_timeout
        self.maximum_header_size = maximum_header_size
        self.header_idle_timeout = header_idle_timeout
        self.maximum_slow_header_bytes = maximum_slow_header_bytes

        self.connections = {}

    def process_payload(self, client_ip, connection_id, payload):
        if not payload:
            return

        current_time = time.time()

        if connection_id not in self.connections:
            self.connections[connection_id] = {
                "client_ip": client_ip,
                "buffer": b"",
                "request_start": None,
                "last_seen": current_time,
                "last_progress": None,
            }

        connection = self.connections[connection_id]

        connection["last_seen"] = current_time
        connection["last_progress"] = current_time

        if connection["request_start"] is None:
            connection["request_start"] = current_time

        connection["buffer"] += payload

        if b"\r\n\r\n" in connection["buffer"]:
            remaining_data = connection["buffer"].split(
                b"\r\n\r\n", 1
            )[1]

            connection["buffer"] = b""
            connection["request_start"] = None
            connection["last_progress"] = None

            if remaining_data:
                connection["buffer"] = remaining_data
                connection["request_start"] = current_time
                connection["last_progress"] = current_time

        if len(connection["buffer"]) > self.maximum_header_size:
            self.connections.pop(connection_id, None)

    def close_connection(self, connection_id):
        self.connections.pop(connection_id, None)

    def cleanup_expired_connections(self):
        current_time = time.time()

        expired_connections = []

        for connection_id, connection in self.connections.items():
            age = current_time - connection["last_seen"]

            if age > self.connection_timeout:
                expired_connections.append(connection_id)

        for connection_id in expired_connections:
            self.connections.pop(connection_id, None)

    def get_statistics(self):
        self.cleanup_expired_connections()

        current_time = time.time()

        incomplete_by_ip = defaultdict(int)
        oldest_incomplete_by_ip = defaultdict(float)

        for connection in self.connections.values():

            request_start = connection["request_start"]

            if request_start is None:
                continue

            age = current_time - request_start

            last_progress = connection["last_progress"]

            if last_progress is None:
                continue

            idle_age = current_time - last_progress
            header_size = len(connection["buffer"])

            client_ip = connection["client_ip"]

            idle_condition = (
                idle_age >= self.header_idle_timeout
            )

            small_header_condition = (
                header_size <= self.maximum_slow_header_bytes
            )

            if (
                age >= self.header_timeout
                and (
                    idle_condition
                    or small_header_condition
                )
            ):
                incomplete_by_ip[client_ip] += 1

                oldest_incomplete_by_ip[client_ip] = max(
                    oldest_incomplete_by_ip[client_ip],
                    age,
                )

        alerts = []

        for client_ip, count in incomplete_by_ip.items():

            if count >= self.minimum_incomplete_requests:
                alerts.append({
                    "client_ip": client_ip,
                    "incomplete_requests": count,
                    "oldest_incomplete_seconds": round(
                        oldest_incomplete_by_ip[client_ip], 2
                    ),
                    "attack_type": "Possible HTTP Slowloris",
                })

        total_incomplete = sum(incomplete_by_ip.values())

        return {
            "incomplete_http_requests": total_incomplete,
            "alerts": alerts,
        }
