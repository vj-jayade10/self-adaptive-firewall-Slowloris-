import time
from scapy.all import IP, TCP

from detection.tcp_connection_tracker import TCPConnectionTracker


def test_new_tcp_connection():
    tracker = TCPConnectionTracker()

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="S")
    )

    tracker.process_packet(packet)

    stats = tracker.get_statistics()

    print("\nTest 1: New TCP connection")
    print(stats)

    assert stats["active_tcp_connections"] == 1

    print("PASS: TCP connection was tracked.")


def test_connection_age():
    tracker = TCPConnectionTracker()

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50001, dport=80, flags="S")
    )

    tracker.process_packet(packet)

    time.sleep(2)

    stats = tracker.get_statistics()

    print("\nTest 2: Connection age")
    print(stats)

    assert stats["active_tcp_connections"] == 1
    assert stats["max_connection_age_seconds"] >= 2

    print("PASS: Connection age was calculated.")



def test_connection_closure():
    tracker = TCPConnectionTracker()

    syn_packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50002, dport=80, flags="S")
    )

    tracker.process_packet(syn_packet)

    stats = tracker.get_statistics()

    assert stats["active_tcp_connections"] == 1

    print("\nTest 3: Connection closure")

    # First endpoint sends FIN.
    fin_from_client = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50002, dport=80, flags="FA")
    )

    tracker.process_packet(fin_from_client)

    stats = tracker.get_statistics()

    print("After first FIN:", stats)

    assert stats["active_tcp_connections"] == 1

    # The other endpoint sends FIN.
    fin_from_server = (
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=80, dport=50002, flags="FA")
    )

    tracker.process_packet(fin_from_server)

    stats = tracker.get_statistics()

    print("After second FIN:", stats)

    assert stats["active_tcp_connections"] == 0

    print("PASS: Connection remained tracked after the first FIN.")
    print("PASS: Connection was removed after FIN from both endpoints.")

def test_new_connections_per_window():
    tracker = TCPConnectionTracker()

    packet1 = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50010, dport=80, flags="S")
    )

    packet2 = (
        IP(src="192.168.1.11", dst="192.168.1.20")
        / TCP(sport=50011, dport=80, flags="S")
    )

    tracker.process_packet(packet1)
    tracker.process_packet(packet2)

    # First window: two new connections.
    first_window = tracker.get_statistics()

    print("\nTest 4: First observation window")
    print(first_window)

    assert first_window["new_tcp_connections"] == 2
    assert first_window["active_tcp_connections"] == 2

    # Second window: no new packets are processed.
    second_window = tracker.get_statistics()

    print("\nTest 4: Second observation window")
    print(second_window)

    assert second_window["new_tcp_connections"] == 0
    assert second_window["active_tcp_connections"] == 2

    print("PASS: New-connection counter resets correctly.")
def test_long_lived_connection():
    tracker = TCPConnectionTracker(long_lived_threshold=2)

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50020, dport=80, flags="S")
    )

    tracker.process_packet(packet)

    print("\nTest 5: Long-lived connection")

    # Immediately after opening, the connection is not long-lived.
    stats = tracker.get_statistics()
    print("Before threshold:", stats)

    assert stats["active_tcp_connections"] == 1
    assert stats["long_lived_tcp_connections"] == 0

    # Wait until the configured threshold has passed.
    time.sleep(2.1)

    stats = tracker.get_statistics()
    print("After threshold:", stats)

    assert stats["active_tcp_connections"] == 1
    assert stats["long_lived_tcp_connections"] == 1

    print("PASS: Long-lived connection was identified.")

def test_rst_connection_closure():
    tracker = TCPConnectionTracker()

    # Simulate a new TCP connection.
    syn_packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50030, dport=80, flags="S")
    )

    tracker.process_packet(syn_packet)

    stats = tracker.get_statistics()

    print("\nTest 6: TCP RST handling")
    print("Before RST:", stats)

    assert stats["active_tcp_connections"] == 1

    # Simulate an RST packet from the client.
    rst_packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50030, dport=80, flags="R")
    )

    tracker.process_packet(rst_packet)

    stats = tracker.get_statistics()

    print("After RST:", stats)

    assert stats["active_tcp_connections"] == 0

    print("PASS: TCP connection was removed after RST.")

def test_midstream_connection():
    tracker = TCPConnectionTracker()

    # Simulate observing a TCP ACK packet without seeing the
    # initial SYN packet.
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50040, dport=80, flags="PA")
        / b"midstream data"
    )

    tracker.process_packet(packet)

    stats = tracker.get_statistics()

    print("\nTest 7: Connection observed midstream")
    print(stats)

    assert stats["active_tcp_connections"] == 1
    assert stats["new_tcp_connections"] == 0

    connection = next(iter(tracker.connections.values()))
    assert connection["syn_observed"] is False

    print("PASS: Midstream TCP flow was tracked.")

def test_connection_timeout():
    tracker = TCPConnectionTracker(connection_timeout=1)

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50050, dport=80, flags="S")
    )

    tracker.process_packet(packet)

    print("\nTest 8: Inactivity timeout")
    print("Before timeout:", tracker.get_statistics())

    time.sleep(1.2)

    stats = tracker.get_statistics()
    print("After timeout:", stats)

    assert stats["active_tcp_connections"] == 0

    print("PASS: Stale connection was removed after timeout.")
def test_per_ip_connection_separation():
    tracker = TCPConnectionTracker()

    packets = [
        IP(src="192.168.1.10", dst="192.168.1.100") /
        TCP(sport=5001, dport=80, flags="S"),

        IP(src="192.168.1.20", dst="192.168.1.100") /
        TCP(sport=5002, dport=80, flags="S"),
    ]

    for packet in packets:
        tracker.process_packet(packet)

    stats = tracker.get_statistics()
    per_ip = stats["per_ip_statistics"]

    assert per_ip["192.168.1.10"]["active_tcp_connections"] == 1
    assert per_ip["192.168.1.20"]["active_tcp_connections"] == 1

    print("Test 9 passed: Per-IP connection separation")

if __name__ == "__main__":
    test_new_tcp_connection()
    test_connection_age()
    test_connection_closure()
    test_new_connections_per_window()
    test_long_lived_connection()
    test_rst_connection_closure()
    test_midstream_connection()
    test_connection_timeout()
    test_per_ip_connection_separation()


    print("\nAll basic TCP connection tracker tests passed!")
