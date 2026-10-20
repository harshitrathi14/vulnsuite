"""Unprivileged HTTP serving of sanitized snapshots only."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import time

STATE = Path('/var/lib/vulnsuite-monitor')
ROOT = Path(__file__).parent
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?',1)[0]
        code = 200
        if path in ('/VulnSuite/', '/VulnSuite'):
            data = (ROOT/'index.html').read_bytes()
            content_type = 'text/html; charset=utf-8'
        elif path in ('/VulnSuite/api/status','/VulnSuite/api/history','/VulnSuite/health'):
            content_type = 'application/json'
            try:
                snapshot = json.loads((STATE/'snapshot.json').read_text())
                stale = time.time()-snapshot['collected_at']>180
                if path.endswith('/health'):
                    code = 503 if stale else 200
                    data = json.dumps({'status':'stale' if stale else 'ok'}).encode()
                elif path.endswith('/history'):
                    data = (STATE/'history.json').read_bytes()
                else:
                    snapshot['stale'] = stale
                    data = json.dumps(snapshot).encode()
            except (OSError,ValueError,KeyError):
                code, data = 503, b'{"error":"Telemetry is not available yet"}'
        else:
            code, data, content_type = 404, b'Not found', 'text/plain'
        self.send_response(code)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8136),Handler).serve_forever()
