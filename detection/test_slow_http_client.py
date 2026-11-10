import socket
import time

HOST = "127.0.0.2"
PORT = 8080
CONNECTIONS = 3


def main():
    sockets = []

    try:
        print("Connecting to the local test server...")

        for i in range(CONNECTIONS):
            sock = socket.create_connection(
                (HOST, PORT),
                timeout=3,
            )
            sock.settimeout(2)

            # Send an intentionally incomplete HTTP request header.
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: 127.0.0.2\r\n"
                b"X-Test: "
            )

            sockets.append(sock)
            print(f"Opened slow test connection {i + 1}")

        print(
            "\nThree incomplete HTTP requests are now open briefly."
        )
        time.sleep(5)

    except OSError as exc:
        print(f"Connection error: {exc}")

    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

        print("All test connections closed.")
        print("This test targets only the local test server.")


if __name__ == "__main__":
    main()
