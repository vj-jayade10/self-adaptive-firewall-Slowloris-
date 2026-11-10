from detection.http_slowloris_detector import HTTPSlowlorisDetector

detector = HTTPSlowlorisDetector(
    header_timeout=2,
    minimum_incomplete_requests=1,
)

connection_id = (
    "127.0.0.1",
    5001,
    "127.0.0.2",
    8080,
)

# Create an incomplete HTTP request.
detector.process_payload(
    "127.0.0.1",
    connection_id,
    b"GET / HTTP/1.1\r\nHost: localhost\r\n",
)

print("Before closing:", len(detector.connections))

# Simulate the TCP connection closing.
detector.close_connection(connection_id)

print("After closing:", len(detector.connections))

result = detector.get_statistics()

print("Cleanup result:", result)

assert len(detector.connections) == 0
assert result["incomplete_http_requests"] == 0
assert len(result["alerts"]) == 0

print("\nCONNECTION CLEANUP TEST PASSED")
