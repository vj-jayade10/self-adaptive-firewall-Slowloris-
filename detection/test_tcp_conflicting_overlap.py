from scapy.all import IP, TCP, Raw

from detection.tcp_stream_reassembler import TCPStreamReassembler

reassembler = TCPStreamReassembler()

src = "127.0.0.1"
dst = "127.0.0.2"
sport = 5005
dport = 8080

connection_id = (src, sport, dst, dport)
sequence = 1000

# Establish connection.
syn = (
    IP(src=src, dst=dst)
    / TCP(sport=sport, dport=dport, flags="S", seq=sequence)
)

reassembler.process_packet(syn)
sequence += 1

# Original segment.
first_payload = b"GET / HTTP/1.1\r\nHost: local"

first_packet = (
    IP(src=src, dst=dst)
    / TCP(sport=sport, dport=dport, flags="PA", seq=sequence)
    / Raw(load=first_payload)
)

first_result = reassembler.process_packet(first_packet)

# Conflicting segment: XXXXX replaces the overlapping bytes.
conflicting_payload = b"XXXXXhost\r\n\r\n"
overlap_sequence = sequence + len(first_payload) - 5

second_packet = (
    IP(src=src, dst=dst)
    / TCP(
        sport=sport,
        dport=dport,
        flags="PA",
        seq=overlap_sequence,
    )
    / Raw(load=conflicting_payload)
)

second_result = reassembler.process_packet(second_packet)

# Verify conflict detection.
print("First segment:", first_result[1])
print("Conflicting segment result:", second_result)
print("Connection ambiguous:", reassembler.is_ambiguous(connection_id))
print("Recorded conflicts:", reassembler.get_conflicts(connection_id))

assert first_result is not None
assert second_result is None
assert reassembler.is_ambiguous(connection_id)
assert len(reassembler.get_conflicts(connection_id)) > 0

print("\nCONFLICTING OVERLAP DETECTION PASSED")
