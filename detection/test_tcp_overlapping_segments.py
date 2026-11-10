from scapy.all import IP, TCP, Raw

from detection.tcp_stream_reassembler import TCPStreamReassembler

reassembler = TCPStreamReassembler()

src = "127.0.0.1"
dst = "127.0.0.2"
sport = 5004
dport = 8080

sequence = 1000

# Establish TCP connection.
syn = (
    IP(src=src, dst=dst)
    / TCP(sport=sport, dport=dport, flags="S", seq=sequence)
)

reassembler.process_packet(syn)
sequence += 1

# First segment.
first_payload = b"GET / HTTP/1.1\r\nHost: local"

first_packet = (
    IP(src=src, dst=dst)
    / TCP(sport=sport, dport=dport, flags="PA", seq=sequence)
    / Raw(load=first_payload)
)

first_result = reassembler.process_packet(first_packet)
assert first_result is not None

# Second segment starts with the same final five bytes: b"local".
overlapping_payload = b"localhost\r\n\r\n"
overlap_sequence = sequence + len(first_payload) - 5

assert first_payload[-5:] == overlapping_payload[:5]

second_packet = (
    IP(src=src, dst=dst)
    / TCP(
        sport=sport,
        dport=dport,
        flags="PA",
        seq=overlap_sequence,
    )
    / Raw(load=overlapping_payload)
)

second_result = reassembler.process_packet(second_packet)
assert second_result is not None

combined = first_result[1] + second_result[1]
expected = first_payload + overlapping_payload[5:]

print("First segment:", first_result[1])
print("New bytes from overlapping segment:", second_result[1])
print("Combined output:", combined)

assert combined == expected

print("\nTCP OVERLAPPING SEGMENTS TEST PASSED")
