import time

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


# Start TCP connection
process(
    IP(src=src, dst=dst) /
    TCP(sport=sport, dport=dport, flags="S", seq=1000)
)

# Prepare correctly sequenced HTTP fragments
payload1 = b"GET / HTTP/1.1\r\nHost:"
payload2 = b" localhost\r\n"
payload3 = b"\r\n"

seq1 = 1001
seq2 = seq1 + len(payload1)
seq3 = seq2 + len(payload2)

# Send incomplete headers
process(
    IP(src=src, dst=dst) /
    TCP(sport=sport, dport=dport, flags="PA", seq=seq1) /
    Raw(load=payload1)
)

process(
    IP(src=src, dst=dst) /
    TCP(sport=sport, dport=dport, flags="PA", seq=seq2) /
    Raw(load=payload2)
)

time.sleep(3)

before = detector.get_statistics()
print("Before header completion:", before)

assert before["incomplete_http_requests"] == 1
assert len(before["alerts"]) == 1

# Complete HTTP headers
process(
    IP(src=src, dst=dst) /
    TCP(sport=sport, dport=dport, flags="PA", seq=seq3) /
    Raw(load=payload3)
)

after = detector.get_statistics()
print("After header completion:", after)

assert after["incomplete_http_requests"] == 0
assert len(after["alerts"]) == 0

print("\nHTTP + TCP INTEGRATION TEST PASSED")
