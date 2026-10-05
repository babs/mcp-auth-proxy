"""Test-only upstream for the forwarding-mode Keycloak e2e test.

Answers every request with the Authorization and X-User-* headers it
received, so the test can inspect the token the proxy forwards. Never
deploy it anywhere: echoing a bearer token back to the caller is exactly
what a real upstream must not do.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Echo(BaseHTTPRequestHandler):
    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = json.dumps({
            "authorization": self.headers.get("Authorization", ""),
            "x_user_sub": self.headers.get("X-User-Sub", ""),
            "x_user_email": self.headers.get("X-User-Email", ""),
            "x_user_groups": self.headers.get("X-User-Groups", ""),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, *args):
        # Keep tokens out of the container log.
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Echo).serve_forever()
