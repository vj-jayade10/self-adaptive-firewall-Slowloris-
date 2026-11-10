from scapy.all import IP, TCP, Raw

from detection.tcp_stream_reassembler import TCPStreamReassembler


reassembler = TCPStreamReassembler()

src = "127.0.0.1"
dst = "127.0.0.2"

sport = 5002
dport = 8080

# Start close to the maximum 32-bit TCP sequence number.
sequence = 0xFFFFFFFC

# Establish the connection.
syn = (
    IP(src=src, dst=dst)
    / TCP(
        sport=sport,
        dport=dport,
        flags="S",
        seq=sequence,
    )
)

reassembler.process_packet(syn)

# SYN consumes one sequence number.
sequence = (sequence + 1) & 0xFFFFFFFF

first_payload = b"GET / HTTP/1.1\r\n"
second_payload = b"Host: localhost\r\n\r\n"

# Send first segment.
first_packet = (
    IP(src=src, dst=dst)
    / TCP(
        sport=sport,
        dport=dport,
        flags="PA",
        seq=sequence,
    )
    / Raw(load=first_payload)
)

first_result = reassembler.process_packet(first_packet)

# Advance sequence number, including wraparound.
sequence = (sequence + len(first_payload)) & 0xFFFFFFFF

# Send second segment.
second_packet = (
    IP(src=src, dst=dst)
    / TCP(
        sport=sport,
        dport=dport,
        flags="PA",
        seq=sequence,
    )
    / Raw(load=second_payload)
)

second_result = reassembler.process_packet(second_packet)

assert first_result is not None
assert second_result is not None

combined_payload = first_result[1] + second_result[1]

print("Reassembled payload:", combined_payload)

assert combined_payload == first_payload + second_payload

print("\nTCP SEQUENCE WRAPAROUND TEST PASSED")
