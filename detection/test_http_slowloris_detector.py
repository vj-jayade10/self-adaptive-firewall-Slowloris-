import time

from detection.http_slowloris_detector import HTTPSlowlorisDetector


# Test 1: Normal completed HTTP requests
normal_detector = HTTPSlowlorisDetector(
    header_timeout=2,
    minimum_incomplete_requests=3,
)

for port in (5001, 5002, 5003):
    normal_detector.process_payload(
        "127.0.0.1",
        ("127.0.0.1", port),
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )

time.sleep(3)

normal_result = normal_detector.get_statistics()
print("NORMAL HTTP TEST:", normal_result)

assert len(normal_result["alerts"]) == 0
print("NORMAL HTTP TEST PASSED")


# Test 2: Incomplete HTTP requests
slow_detector = HTTPSlowlorisDetector(
    header_timeout=2,
    minimum_incomplete_requests=3,
    header_idle_timeout=1,
)

for port in (6001, 6002, 6003):
    slow_detector.process_payload(
        "127.0.0.1",
        ("127.0.0.1", port),
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: ",
    )

time.sleep(3)

slow_result = slow_detector.get_statistics()
print("SLOWLORIS TEST:", slow_result)

assert len(slow_result["alerts"]) == 1
print("SLOWLORIS TEST PASSED")

from detection.http_slowloris_detector import HTTPSlowlorisDetector


slow_detector = HTTPSlowlorisDetector(
    header_timeout=2,
    minimum_incomplete_requests=3,
    header_idle_timeout=1,
)

client_ip = "127.0.0.1"

for port in (5001, 5002, 5003):
    connection_id = (client_ip, port)
    slow_detector.process_payload(
        client_ip,
        connection_id,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: ",
    )

print("Three incomplete HTTP requests created.")

time.sleep(3)

result = slow_detector.get_statistics()
print(result)

assert result["incomplete_http_requests"] == 3
assert len(result["alerts"]) == 1

print("TEST PASSED")

# Test 4: Legitimate slow HTTP requests that eventually complete

legitimate_detector = HTTPSlowlorisDetector(
    header_timeout=10,
    minimum_incomplete_requests=3,
)

sockets = []

client_ip = "127.0.0.1"

for port in (7001, 7002, 7003):

    connection_id = (client_ip, port)

    legitimate_detector.process_payload(
        client_ip,
        connection_id,
        b"GET / HTTP/1.1\r\n",
    )

    legitimate_detector.process_payload(
        client_ip,
        connection_id,
        b"Host: localhost\r\n",
    )

    legitimate_detector.process_payload(
        client_ip,
        connection_id,
        b"User-Agent: LegitimateClient\r\n",
    )

# Simulate a short delay before completing headers.
time.sleep(2)

for port in (7001, 7002, 7003):

    connection_id = (client_ip, port)

    legitimate_detector.process_payload(
        client_ip,
        connection_id,
        b"Connection: close\r\n\r\n",
    )

legitimate_result = legitimate_detector.get_statistics()

print("LEGITIMATE SLOW HTTP TEST:", legitimate_result)

assert legitimate_result["incomplete_http_requests"] == 0
assert len(legitimate_result["alerts"]) == 0

print("LEGITIMATE SLOW HTTP TEST PASSED")

# Test 5: Legitimate slow HTTP requests completed within 8 seconds

slow_legitimate_detector = HTTPSlowlorisDetector(
    header_timeout=10,
    minimum_incomplete_requests=3,
)

client_ip = "127.0.0.1"

for port in (8001, 8002, 8003):
    connection_id = (client_ip, port)

    slow_legitimate_detector.process_payload(
        client_ip,
        connection_id,
        b"GET / HTTP/1.1\r\n",
    )

print("First fragments sent.")
time.sleep(4)

for port in (8001, 8002, 8003):
    connection_id = (client_ip, port)

    slow_legitimate_detector.process_payload(
        client_ip,
        connection_id,
        b"Host: localhost\r\n",
    )

print("Second fragments sent.")
time.sleep(4)

for port in (8001, 8002, 8003):
    connection_id = (client_ip, port)

    slow_legitimate_detector.process_payload(
        client_ip,
        connection_id,
        b"User-Agent: LegitimateClient\r\n\r\n",
    )

slow_legitimate_result = slow_legitimate_detector.get_statistics()

print("8-SECOND LEGITIMATE HTTP TEST:", slow_legitimate_result)

assert slow_legitimate_result["incomplete_http_requests"] == 0
assert len(slow_legitimate_result["alerts"]) == 0

print("8-SECOND LEGITIMATE HTTP TEST PASSED")

# Test 6: Legitimate slow HTTP requests completed after 11 seconds

legitimate_11s_detector = HTTPSlowlorisDetector(
    header_timeout=10,
    minimum_incomplete_requests=3,
)

client_ip = "127.0.0.1"

for port in (9001, 9002, 9003):
    connection_id = (client_ip, port)

    legitimate_11s_detector.process_payload(
        client_ip,
        connection_id,
        b"GET / HTTP/1.1\r\n",
    )

print("First HTTP fragments sent.")
time.sleep(4)

for port in (9001, 9002, 9003):
    connection_id = (client_ip, port)

    legitimate_11s_detector.process_payload(
        client_ip,
        connection_id,
        b"Host: localhost\r\n",
    )

print("Second HTTP fragments sent.")
time.sleep(4)

for port in (9001, 9002, 9003):
    connection_id = (client_ip, port)

    legitimate_11s_detector.process_payload(
        client_ip,
        connection_id,
        b"User-Agent: LegitimateClient\r\n",
    )

print("Third HTTP fragments sent.")
time.sleep(3)

# Check for an alert before completing the headers.
during_result = legitimate_11s_detector.get_statistics()

print("11-second incomplete HTTP result:", during_result)

# Now complete all three requests.
for port in (9001, 9002, 9003):
    connection_id = (client_ip, port)

    legitimate_11s_detector.process_payload(
        client_ip,
        connection_id,
        b"\r\n",
    )

final_result = legitimate_11s_detector.get_statistics()

print("11-SECOND LEGITIMATE HTTP FINAL RESULT:", final_result)

assert final_result["incomplete_http_requests"] == 0
assert len(final_result["alerts"]) == 0

print("11-SECOND LEGITIMATE HTTP COMPLETION TEST PASSED")
