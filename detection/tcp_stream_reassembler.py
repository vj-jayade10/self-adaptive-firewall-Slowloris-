import time
from collections import OrderedDict

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


class TCPStreamReassembler:
    def __init__(
        self,
        connection_timeout=60,
        maximum_buffer=262144,
    ):
        self.connection_timeout = connection_timeout
        self.maximum_buffer = maximum_buffer
        self.streams = {}

    def _new_stream(self, next_sequence, current_time):
        return {
            "next_sequence": next_sequence,
            "pending": {},
            "buffered_bytes": 0,
            "last_seen": current_time,
            "history": OrderedDict(),
            "ambiguous": False,
            "conflicts": [],
        }

    def _remember_payload(self, stream, sequence, payload):
        """Remember recently delivered bytes for overlap comparisons."""

        history = stream["history"]

        for index, byte in enumerate(payload):
            position = (sequence + index) & 0xFFFFFFFF

            history[position] = byte
            history.move_to_end(position)

        while len(history) > self.maximum_buffer:
            history.popitem(last=False)

    def _mark_conflict(
        self,
        stream,
        sequence,
        existing_byte,
        incoming_byte,
    ):
        """Mark a stream ambiguous when overlapping bytes disagree."""

        stream["ambiguous"] = True

        stream["conflicts"].append({
            "sequence": sequence,
            "existing_byte": existing_byte,
            "incoming_byte": incoming_byte,
        })

    def is_ambiguous(self, connection_id):
        """Check whether a connection has conflicting TCP data."""

        stream = self.streams.get(connection_id)

        return bool(stream and stream["ambiguous"])

    def get_conflicts(self, connection_id):
        """Return recorded overlap conflicts for a connection."""

        stream = self.streams.get(connection_id)

        if stream is None:
            return []

        return list(stream["conflicts"])

    def process_packet(self, packet):
        """
        Reassemble contiguous TCP payload bytes.

        Returns:
            (connection_id, payload) when new contiguous data is available.
            None when no new data is available or the stream is ambiguous.
        """

        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return None

        ip = packet[IP]
        tcp = packet[TCP]

        connection_id = (
            ip.src,
            int(tcp.sport),
            ip.dst,
            int(tcp.dport),
        )

        sequence = int(tcp.seq)
        flags = int(tcp.flags)
        payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""

        current_time = time.time()

        # Initialize sequence tracking from SYN.
        if flags & 0x02:
            self.streams[connection_id] = self._new_stream(
                (sequence + 1) & 0xFFFFFFFF,
                current_time,
            )

        elif connection_id not in self.streams and payload:
            # Midstream capture.
            self.streams[connection_id] = self._new_stream(
                sequence,
                current_time,
            )

        stream = self.streams.get(connection_id)

        if stream is None:
            return None

        stream["last_seen"] = current_time

        output = b""

        # Do not process more payload from an ambiguous stream.
        if payload and not stream["ambiguous"]:

            expected = stream["next_sequence"]

            difference = self._sequence_difference(
                sequence,
                expected,
            )

            if difference == 0:
                output += payload

                self._remember_payload(
                    stream,
                    expected,
                    payload,
                )

                stream["next_sequence"] = (
                    expected + len(payload)
                ) & 0xFFFFFFFF

                # Append buffered segments that now fit exactly.
                while stream["next_sequence"] in stream["pending"]:

                    pending_sequence = stream["next_sequence"]

                    next_payload = stream["pending"].pop(
                        pending_sequence
                    )

                    stream["buffered_bytes"] -= len(next_payload)

                    output += next_payload

                    self._remember_payload(
                        stream,
                        pending_sequence,
                        next_payload,
                    )

                    stream["next_sequence"] = (
                        stream["next_sequence"] + len(next_payload)
                    ) & 0xFFFFFFFF

            elif difference > 0:
                # Future segment: buffer until missing bytes arrive.
                if sequence in stream["pending"]:

                    existing_payload = stream["pending"][sequence]

                    if existing_payload != payload:
                        self._mark_conflict(
                            stream,
                            sequence,
                            existing_payload,
                            payload,
                        )

                elif (
                    stream["buffered_bytes"] + len(payload)
                    <= self.maximum_buffer
                ):
                    stream["pending"][sequence] = payload
                    stream["buffered_bytes"] += len(payload)

            else:
                # Old or overlapping segment.
                overlap = -difference

                # Compare overlapping bytes against delivered history.
                compare_length = min(overlap, len(payload))
                history = stream["history"]

                for index in range(compare_length):

                    position = (sequence + index) & 0xFFFFFFFF

                    if position not in history:
                        continue

                    existing_byte = history[position]
                    incoming_byte = payload[index]

                    if existing_byte != incoming_byte:
                        self._mark_conflict(
                            stream,
                            position,
                            existing_byte,
                            incoming_byte,
                        )
                        break

                # Append only bytes that extend beyond the current stream.
                if not stream["ambiguous"] and overlap < len(payload):

                    new_payload = payload[overlap:]

                    output += new_payload

                    self._remember_payload(
                        stream,
                        expected,
                        new_payload,
                    )

                    stream["next_sequence"] = (
                        expected + len(new_payload)
                    ) & 0xFFFFFFFF

        result = None

        if output and not stream["ambiguous"]:
            result = (connection_id, output)

        # FIN and RST close this directional stream.
        if flags & 0x05:
            self.streams.pop(connection_id, None)

        self.cleanup_expired()

        return result

    @staticmethod
    def _sequence_difference(sequence, expected):
        """Calculate signed TCP sequence distance, including wraparound."""

        difference = (sequence - expected) & 0xFFFFFFFF

        if difference >= 0x80000000:
            difference -= 0x100000000

        return difference

    def cleanup_expired(self):
        current_time = time.time()

        expired = [
            connection_id
            for connection_id, stream in self.streams.items()
            if current_time - stream["last_seen"]
            > self.connection_timeout
        ]

        for connection_id in expired:
            self.streams.pop(connection_id, None)
