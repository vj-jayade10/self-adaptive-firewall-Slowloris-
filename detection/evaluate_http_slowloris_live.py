import socket
import threading
import time

from scapy.all import sniff, IP, TCP, Raw

from detection.http_slowloris_detector import HTTPSlowlorisDetector


HOST = "127.0.0.2"
PORT = 8080
INTERFACE = "lo"


def run_test(label, traffic_function):
    detector = HTTPSlowlorisDetector(
        header_timeout=10,
        minimum_incomplete_requests=3,
    )

    stop_capture = threading.Event()

    def capture_packets():
        def handle_packet(packet):
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return

            tcp = packet[TCP]

            if not packet.haslayer(Raw):
                return

            # Only inspect traffic sent by the HTTP client.
            if tcp.dport != PORT:
                return

            connection_id = (
                packet[IP].src,
                int(tcp.sport),
                packet[IP].dst,
                int(tcp.dport),
            )

            detector.process_payload(
                packet[IP].src,
                connection_id,
                bytes(packet[Raw].load),
            )

        sniff(
            iface=INTERFACE,
            filter=f"tcp port {PORT}",
            prn=handle_packet,
            store=False,
            stop_filter=lambda packet: stop_capture.is_set(),
        )

    capture_thread = threading.Thread(
        target=capture_packets,
        daemon=True,
    )

    print(f"\nStarting {label} test.")

    capture_thread.start()
    time.sleep(2)

    try:
        traffic_function(detector)
        time.sleep(4)
        result = detector.get_statistics()

    finally:
        stop_capture.set()

    print(f"{label} result: {result}")

    return result


def normal_http_traffic(detector=None):
    import requests

    for _ in range(10):
        try:
            requests.get(
                f"http://{HOST}:{PORT}/",
                timeout=3,
            )
        except requests.RequestException as exc:
            print(f"Normal request error: {exc}")


def slow_http_traffic(detector=None):
    sockets = []

    try:
        for _ in range(3):
            sock = socket.create_connection(
                (HOST, PORT),
                timeout=3,
            )

            sockets.append(sock)

            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.2\r\n"
                b"X-Test: "
            )

        print("Three incomplete HTTP requests sent.")

        time.sleep(12)

    finally:
        for sock in sockets:
            sock.close()
def legitimate_slow_http_traffic(detector):
    sockets = []

    try:
        print("Opening three legitimate slow HTTP connections.")

        for _ in range(3):
            sock = socket.create_connection(
                (HOST, PORT),
                timeout=5,
            )
            sock.settimeout(5)
            sockets.append(sock)

            sock.sendall(b"GET / HTTP/1.1\r\n")

        print("First HTTP header fragment sent.")
        time.sleep(2)

        for sock in sockets:
            sock.sendall(b"Host: 127.0.0.2\r\n")

        print("Second HTTP header fragment sent.")
        time.sleep(4)

        for sock in sockets:
            sock.sendall(b"User-Agent: LegitimateSlowClient\r\n")

        print("Third HTTP header fragment sent.")
        time.sleep(4)

        # Check detector while requests are still incomplete.
        during_result = detector.get_statistics()

        print(
            "Detector result while requests are incomplete:",
            during_result,
        )

        # Complete all HTTP headers.
        for sock in sockets:
            sock.sendall(b"Connection: close\r\n\r\n")

        print("All HTTP headers completed.")

        for sock in sockets:
            try:
                response = sock.recv(4096)

                if b"200 OK" in response:
                    print("Legitimate slow HTTP response: 200 OK")
                else:
                    print("Received response:", response[:100])

            except socket.timeout:
                print("HTTP response timed out.")

        time.sleep(1)

    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

        print("Legitimate slow HTTP connections closed.")

if __name__ == "__main__":

    normal_result = run_test(
        "NORMAL HTTP",
        normal_http_traffic,
    )

    legitimate_result = run_test(
        "LEGITIMATE SLOW HTTP",
        legitimate_slow_http_traffic,
    )

    slow_result = run_test(
        "SLOWLORIS",
        slow_http_traffic,
    )

    print("\n===== COMPLETE HTTP EVALUATION =====")

    print("Normal HTTP alerts:", len(normal_result["alerts"]))

    print(
        "Legitimate slow HTTP alerts while incomplete:",
        len(legitimate_result["alerts"]),
    )

    print("Slowloris alerts:", len(slow_result["alerts"]))
