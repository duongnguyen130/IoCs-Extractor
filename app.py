#!/usr/bin/env python3
"""
CISA IOC Extractor: local web app.

Upload CISA STIX 2.x JSON bundles (or plain-text IOC lists) and get:
  * categorized, de-duplicated IOC lists ready to paste into Excel
  * the CVEs referenced
  * a recommended broad Splunk search for each category

Standard library only. Run:
    python app.py                 # http://127.0.0.1:8080
    python app.py --port 9000
    python app.py --host 0.0.0.0  # expose on the LAN (no auth, so be careful)
"""

import argparse
import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from ioc.extractor import extract_from_files
from ioc import splunk

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = (BASE_DIR / "static").resolve()
TEMPLATE_DIR = (BASE_DIR / "templates").resolve()
MAX_BODY = 50 * 1024 * 1024  # 50 MB total upload

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; "
                               "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "CISA-IOC-Extractor/1.0"

    # ---- helpers ---------------------------------------------------------
    def _headers(self, status, ctype, length):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _file(self, path: Path):
        ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        data = path.read_bytes()
        self._headers(200, ctype, len(data))
        self.wfile.write(data)

    def _not_found(self):
        self._json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    # ---- routes ----------------------------------------------------------
    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            return self._file(TEMPLATE_DIR / "index.html")
        if path == "/api/health":
            return self._json(200, {"status": "ok"})
        if path.startswith("/static/"):
            target = (STATIC_DIR / path[len("/static/"):]).resolve()
            if STATIC_DIR in target.parents and target.is_file():
                return self._file(target)
        return self._not_found()

    def do_POST(self):
        path = urlsplit(self.path).path
        if path != "/api/extract":
            return self._not_found()
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._json(400, {"error": "empty request"})
        if length > MAX_BODY:
            return self._json(413, {"error": f"upload too large (max {MAX_BODY // 1024 // 1024} MB)"})
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._json(400, {"error": "invalid JSON body"})

        files = payload.get("files") or []
        if not isinstance(files, list) or not files:
            return self._json(400, {"error": "no files provided"})
        opts = payload.get("options") or {}

        result = extract_from_files(files)
        categories, master = splunk.build(
            result,
            scope=str(opts.get("scope") or "index=*")[:500],
            earliest=str(opts.get("earliest") or "-90d")[:40],
        )
        total = sum(len(c["items"]) for c in categories)
        return self._json(200, {
            "reports": result["reports"],
            "errors": result["errors"],
            "categories": categories,
            "master": master,
            "total": total,
        })


def main():
    ap = argparse.ArgumentParser(description="CISA STIX IOC extractor + Splunk hunt query generator")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="port (default 8080)")
    args = ap.parse_args()

    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("text/css", ".css")

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"CISA IOC Extractor running at http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
