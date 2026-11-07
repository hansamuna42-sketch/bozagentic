#!/usr/bin/env python3
"""Mock vulnerable PHP target for smoke-testing the php2shell chain.
Simulates: EOL PHP banner, LFI via ?page=, open upload endpoint."""
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler

UPLOAD_DIR = "/tmp/php2shell_test/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class VulnHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"
    sys_version = ""

    def _send(self, code, body=b"", ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/5.6.40")  # EOL — auditor should flag
        self.send_header("Server", "Apache/2.4.29 (Ubuntu)")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        query = self.path.split("?")[1] if "?" in self.path else ""

        if path == "/index.php":
            from urllib.parse import unquote
            params = {k: unquote(v) for k, v in
                      (p.split("=", 1) for p in query.split("&") if "=" in p)}
            page = params.get("page", params.get("id", "home"))
            # LFI: classic include($_GET['page']) — no sanitization at all
            if ".." in page or page.startswith("/"):
                try:
                    with open(page.lstrip("/") if page.startswith("/") else page, "rb") as f:
                        return self._send(200, f.read())
                except Exception:
                    return self._send(200, b"File not found")
            return self._send(200, b"<html><body>Welcome home</body></html>")

        if path == "/upload.php":
            return self._send(200, b"""<html><body><h2>Upload</h2>
                <form method="POST" enctype="multipart/form-data">
                <input type="file" name="file"><input type="submit"></form></body></html>""")

        if path.startswith("/uploads/"):
            fname = path.split("/")[-1]
            fpath = os.path.join(UPLOAD_DIR, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    content = f.read()
                # simulate PHP execution for uploaded shells
                # NOTE: shell=True is intentional — this is a deliberately
                # vulnerable mock target used to test shell-upload detection.
                if b"system(" in content and "c=" in self.path:
                    import subprocess
                    cmd = self.path.split("c=", 1)[1].split("&")[0]
                    from urllib.parse import unquote
                    cmd = unquote(cmd)
                    try:
                        out = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                        return self._send(200, out.stdout + out.stderr)
                    except Exception as e:
                        return self._send(200, str(e).encode())
                return self._send(200, content)
            return self._send(404, b"not found")

        self._send(404, b"Not Found")

    def do_POST(self):
        if self.path.startswith("/upload.php"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            # proper multipart parse: find Content-Disposition part header
            m = re.search(rb'Content-Disposition: form-data; name="([^"]+)"; filename="([^"]+)"', body)
            if m:
                fname = os.path.basename(m.group(2).decode("utf-8", "ignore"))
                # content = between the part's blank line and the next boundary
                after = body[m.end():]
                parts = after.split(b"\r\n\r\n", 1)
                content = parts[1] if len(parts) > 1 else b""
                content = content.rsplit(b"\r\n--", 1)[0]
                with open(os.path.join(UPLOAD_DIR, fname), "wb") as f:
                    f.write(content)
                return self._send(200, f"Uploaded: /uploads/{fname}".encode())
            return self._send(400, b"no file")
        self._send(404, b"Not Found")

    def log_message(self, fmt, *args):
        pass  # quiet


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 8888), VulnHandler)
    print("[mock] vulnerable target on http://127.0.0.1:8888/")
    srv.serve_forever()
