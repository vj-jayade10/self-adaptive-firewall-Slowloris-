from scapy.all import IP, TCP, Raw

from detection.tcp_stream_reassembler import TCPStreamReassembler
from detection.http_slowloris_detector import HTTPSlowlorisDetector


reassembler = TCPStreamReassembler()

detector = HTTPSlowlorisDetector(
    header_timeout=2,
    minimum_incomplete_requests=1,
)

src = "127.0.0.1"
dst = "127.0.0.2"
sport = 5001
dport = 8080

sequence = 1000


def process(packet):
    result = reassembler.process_packet(packet)

    if result is None:
        return

    connection_id, payload = result

    if payload:
        detector.process_payload(
            connection_id[0],
            connection_id,
            payload,
        )


# Establish TCP connection.
process(
    IP(src=src, dst=dst) /
    TCP(
        sport=sport,
        dport=dport,
        flags="S",
        seq=sequence,
    )
)

sequence += 1

# Send three completed HTTP requests over the same connection.
for number in range(1, 4):

    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"X-Request: {number}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode()

    process(
        IP(src=src, dst=dst) /
        TCP(
            sport=sport,
            dport=dport,
            flags="PA",
            seq=sequence,
        ) /
        Raw(load=request)
    )

    sequence += len(request)

    print(f"Completed HTTP request {number}.")

# Check detector state.
result = detector.get_statistics()

print("\nKEEP-ALIVE RESULT:", result)

assert result["incomplete_http_requests"] == 0
assert len(result["alerts"]) == 0

# Simulate TCP connection closure.
process(
    IP(src=src, dst=dst) /
    TCP(
        sport=sport,
        dport=dport,
        flags="FA",
        seq=sequence,
    )
)

detector.close_connection(
    (src, sport, dst, dport)
)

print("\nHTTP KEEP-ALIVE TEST PASSED")
