"""Deterministic local HTTP transfer fixture; publish only on host loopback."""
import http.server
import time

PAYLOAD = bytes(range(256)) * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ready":
            self.send_response(200)
            self.end_headers()
            return
        offset = 0
        requested = self.headers.get("Range", "")
        if requested and self.path != "/ignore-range":
            if not requested.startswith("bytes=") or not requested.endswith("-"):
                self.send_error(400)
                return
            offset = int(requested[6:-1])
        self.send_response(206 if offset else 200)
        self.send_header("Content-Length", str(len(PAYLOAD) - offset))
        if offset:
            self.send_header("Content-Range", f"bytes {offset}-{len(PAYLOAD)-1}/{len(PAYLOAD)}")
        self.end_headers()
        if self.path == "/stall":
            self.wfile.write(PAYLOAD[offset:offset + 65536])
            self.wfile.flush()
            time.sleep(10)  # Deliberately stalled response for curl's speed guard.
            return
        try:
            self.wfile.write(PAYLOAD[offset:])
        except (BrokenPipeError, ConnectionResetError):
            pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
