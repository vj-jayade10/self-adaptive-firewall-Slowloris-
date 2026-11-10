import socket
import threading
import time

import requests
from scapy.all import sniff, IP, TCP

from detection.tcp_stream_reassembler import TCPStreamReassembler
from detection.http_slowloris_detector import HTTPSlowlorisDetector


HOST = "127.0.0.2"
PORT = 8080
INTERFACE = "lo"


def run_test(label, traffic_function):
    reassembler = TCPStreamReassembler()

    detector = HTTPSlowlorisDetector(
        header_timeout=3,
        minimum_incomplete_requests=3,
    )

    capture_ready = threading.Event()
    capture_error = []
    saved_result = {}

    def take_snapshot():
        # Allow packet capture to process recently sent data.
        time.sleep(0.5)
        saved_result.update(detector.get_statistics())

    def handle_packet(packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        tcp = packet[TCP]

        connection_id = (
            packet[IP].src,
            int(tcp.sport),
            packet[IP].dst,
            int(tcp.dport),
        )

        reverse_id = (
            packet[IP].dst,
            int(tcp.dport),
            packet[IP].src,
            int(tcp.sport),
        )

        if tcp.dport == PORT:
            result = reassembler.process_packet(packet)

            if result is not None:
                stream_id, payload = result

                if payload:
                    detector.process_payload(
                        stream_id[0],
                        stream_id,
                        payload,
                    )

        # Remove state only when the connection actually closes.
        flags = int(tcp.flags)

        if flags & 0x05:
            detector.close_connection(connection_id)
            detector.close_connection(reverse_id)

    def capture():
        try:
            capture_ready.set()

            sniff(
                iface=INTERFACE,
                filter=f"tcp port {PORT}",
                prn=handle_packet,
                store=False,
                timeout=20,
            )

        except Exception as exc:
            capture_error.append(str(exc))

    print(f"\nStarting {label} test.")

    capture_thread = threading.Thread(
        target=capture,
        daemon=True,
    )

    capture_thread.start()

    if not capture_ready.wait(timeout=3):
        raise RuntimeError("Packet capture failed to start.")

    time.sleep(2)

    try:
        traffic_function(take_snapshot)

    finally:
        capture_thread.join(timeout=23)

    if capture_thread.is_alive():
        raise RuntimeError("Packet capture did not finish.")

    if capture_error:
        raise RuntimeError(capture_error[0])

    result = saved_result

    print(f"{label} result: {result}")

    return result


def normal_http_traffic(snapshot):
    for _ in range(10):
        try:
            response = requests.get(
                f"http://{HOST}:{PORT}/",
                timeout=3,
            )

            print("Normal HTTP status:", response.status_code)

        except requests.RequestException as exc:
            print("Normal request failed:", exc)

    snapshot()


def slow_http_traffic(snapshot):
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

        time.sleep(5)

        # IMPORTANT: Collect results before closing sockets.
        snapshot()

    finally:
        for sock in sockets:
            sock.close()

        print("Slow test connections closed.")


if __name__ == "__main__":

    normal_result = run_test(
        "NORMAL HTTP",
        normal_http_traffic,
    )

    slow_result = run_test(
        "SLOWLORIS",
        slow_http_traffic,
    )

    print("\n===== COMPLETE HTTP PIPELINE RESULTS =====")

    print("Normal HTTP alerts:", len(normal_result["alerts"]))
    print("Slowloris alerts:", len(slow_result["alerts"]))

    if (
        len(normal_result["alerts"]) == 0
        and len(slow_result["alerts"]) > 0
    ):
        print("PIPELINE TEST PASSED")
    else:
        print("PIPELINE TEST NEEDS INVESTIGATION")
