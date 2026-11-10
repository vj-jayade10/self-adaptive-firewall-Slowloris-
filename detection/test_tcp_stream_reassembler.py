from scapy.all import IP, TCP, Raw

from detection.tcp_stream_reassembler import TCPStreamReassembler


reassembler = TCPStreamReassembler()

src = "192.168.1.10"
dst = "192.168.1.20"
sport = 5000
dport = 8080
initial_seq = 1000

# Test 1: In-order data
print("\nTEST 1: In-order packets")

syn = IP(src=src, dst=dst) / TCP(
    sport=sport, dport=dport, flags="S", seq=initial_seq
)
reassembler.process_packet(syn)

packet1 = IP(src=src, dst=dst) / TCP(
    sport=sport, dport=dport, flags="PA", seq=1001
) / Raw(load=b"Hello ")

packet2 = IP(src=src, dst=dst) / TCP(
    sport=sport, dport=dport, flags="PA", seq=1007
) / Raw(load=b"World")

result1 = reassembler.process_packet(packet1)
result2 = reassembler.process_packet(packet2)

assert result1[1] == b"Hello "
assert result2[1] == b"World"

print("PASS: In-order data reconstructed")


# Test 2: Out-of-order data
print("\nTEST 2: Out-of-order packets")

reassembler = TCPStreamReassembler()

reassembler.process_packet(
    IP(src=src, dst=dst) /
    TCP(sport=sport, dport=dport, flags="S", seq=2000)
)

second = IP(src=src, dst=dst) / TCP(
    sport=sport, dport=dport, flags="PA", seq=2007
) / Raw(load=b"World")

first = IP(src=src, dst=dst) / TCP(
    sport=sport, dport=dport, flags="PA", seq=2001
) / Raw(load=b"Hello ")

result_second = reassembler.process_packet(second)
assert result_second is None

result_first = reassembler.process_packet(first)

assert result_first[1] == b"Hello World"

print("PASS: Out-of-order data reconstructed")


# Test 3: Duplicate retransmission
print("\nTEST 3: Duplicate retransmission")

reassembler = TCPStreamReassembler()

reassembler.process_packet(
    IP(src=src, dst=dst) /
    TCP(sport=sport, dport=dport, flags="S", seq=3000)
)

packet = IP(src=src, dst=dst) / TCP(
    sport=sport, dport=dport, flags="PA", seq=3001
) / Raw(load=b"Hello")

first_result = reassembler.process_packet(packet)
duplicate_result = reassembler.process_packet(packet)

assert first_result[1] == b"Hello"
assert duplicate_result is None

print("PASS: Duplicate retransmission ignored")

print("\nALL TCP REASSEMBLY TESTS PASSED")
