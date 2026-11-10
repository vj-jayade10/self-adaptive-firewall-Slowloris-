from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


class LocalTestHandler(BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"

    def send_json(self, data):
        body = json.dumps(data).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def do_GET(self):

        if self.path == "/":
            self.send_json({
                "status": "ok",
                "message": "Local firewall evaluation server is running"
            })

        elif self.path == "/health":
            self.send_json({
                "status": "healthy"
            })

        else:
            body = b'{"error": "Not found"}'

            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)


if __name__ == "__main__":

    server = ThreadingHTTPServer(
        ("127.0.0.2", 8080),
        LocalTestHandler
    )

    print("Local HTTP test server running at 127.0.0.2:8080")
    print("HTTP/1.1 persistent connections enabled")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopping...")
    finally:
        server.server_close()
