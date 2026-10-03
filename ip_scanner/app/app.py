"""Small dependency-free HTTP API and HA Ingress-only web application."""
import argparse
import csv
import html
import io
import ipaddress
import json
import logging
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from network import discover_networks, select_network
from scanner import ScanManager
from storage import Store

LOG = logging.getLogger(__name__)
WEB = Path(__file__).parent / "web"
INGRESS_PEER = "172.30.32.2"
DEFAULTS = {"network": "auto", "scan_on_start": True, "scan_interval": 300,
            "scan_timeout": 180, "mdns": True}


def load_options(path):
    options = {**DEFAULTS, **(json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {})}
    for key, minimum, maximum in (("scan_interval", 0, 86400), ("scan_timeout", 30, 600)):
        if type(options[key]) is not int or not minimum <= options[key] <= maximum:
            raise ValueError(f"Invalid option: {key}")
    for key in ("mdns", "scan_on_start"):
        if type(options[key]) is not bool:
            raise ValueError(f"Invalid option: {key}")
    if not isinstance(options["network"], str):
        raise ValueError("Invalid option: network")
    return options


class Context:
    def __init__(self, directory, options, demo=False):
        self.lock = threading.RLock()
        self.options, self.demo = options, demo
        self.store = Store(directory)
        self.error = None
        self.selected = None
        self.networks = []
        self.shutdown = threading.Event()
        if demo:
            from demo import DEMO_NETWORK, DemoManager, seed_demo
            self.networks = [dict(DEMO_NETWORK)]
            self.selected = self.networks[0]
            seed_demo(self.store)
            self.scanner = DemoManager(self.store)
        else:
            self.scanner = ScanManager(self.store, options["scan_timeout"], options["mdns"])
            self.refresh()

    def refresh(self, requested=None):
        if self.demo:
            return
        with self.lock:
            try:
                self.networks = discover_networks()
                value = requested or (self.selected["cidr"] if self.selected else self.options["network"])
                self.selected = select_network(value, self.networks)
                self.error = None
            except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
                self.error = str(exc)
                if requested:
                    raise ValueError(self.error) from exc

    def payload(self):
        with self.lock:
            scan = self.scanner.state()
            return {"demo": self.demo, "networks": self.networks, "selected": self.selected,
                    "network_error": self.error, "scan": scan,
                    "scan_interval": self.options["scan_interval"],
                    "snapshot": self.store.snapshot(self.selected["cidr"]) if self.selected else None}

    def start_scan(self):
        with self.lock:
            self.refresh()
            if self.error or not self.selected:
                raise ValueError(self.error or "לא נמצאה רשת לסריקה")
            self.scanner.start(self.selected)

    def scheduler(self):
        if self.options["scan_on_start"]:
            try:
                self.start_scan()
            except ValueError as exc:
                LOG.warning("Startup scan: %s", exc)
        interval = self.options["scan_interval"]
        if interval:
            while not self.shutdown.wait(interval):
                if not self.scanner.state()["running"]:
                    try:
                        self.start_scan()
                    except ValueError as exc:
                        LOG.warning("Scheduled scan: %s", exc)


def make_handler(context):
    class Handler(BaseHTTPRequestHandler):
        server_version = "IPScanner"

        def allowed(self):
            # Trust the socket peer, never a client-supplied X-Forwarded-For.
            peer = self.client_address[0]
            return peer == INGRESS_PEER or (context.demo and peer in ("127.0.0.1", "::1"))

        def respond(self, code, content, content_type="application/json; charset=utf-8", extra=None):
            body = content if isinstance(content, bytes) else (
                json.dumps(content, ensure_ascii=False).encode("utf-8") if isinstance(content, dict)
                else content.encode("utf-8"))
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                             "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
                             "object-src 'none'; base-uri 'self'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self.allowed():
                self.respond(403, {"error": "Access is available through Home Assistant Ingress only"})
                return
            path = urlsplit(self.path).path
            if path == "/api/state":
                self.respond(200, context.payload())
            elif path == "/api/export.csv":
                payload = context.payload()
                snapshot = payload["snapshot"]
                if not snapshot:
                    self.respond(409, {"error": "לא נבחרה רשת"})
                    return
                text = io.StringIO(newline="")
                writer = csv.writer(text)
                keys = ("ip", "status", "name", "hostname", "mac", "vendor", "last_seen")
                writer.writerow(keys)
                for row in snapshot["rows"]:
                    # Spreadsheet formula injection can originate from discovered device names.
                    writer.writerow([("'" + str(row.get(k) or "")) if str(row.get(k) or "").lstrip().startswith(
                        ("=", "+", "-", "@")) else row.get(k) or "" for k in keys])
                self.respond(200, ("\ufeff" + text.getvalue()).encode("utf-8"), "text/csv; charset=utf-8",
                             {"Content-Disposition": 'attachment; filename="ip-scanner.csv"'})
            elif path in ("/", "/index.html"):
                base = self.headers.get("X-Ingress-Path", "/").rstrip("/") + "/"
                if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*", base):
                    self.respond(400, {"error": "Invalid Ingress path"})
                    return
                content = (WEB / "index.html").read_text(encoding="utf-8")
                self.respond(200, content.replace("__BASE_PATH__", html.escape(base, quote=True)),
                             "text/html; charset=utf-8")
            elif path in ("/styles.css", "/app.js", "/api.js", "/demo.js"):
                asset = WEB / path.lstrip("/")
                self.respond(200, asset.read_bytes(), "application/javascript; charset=utf-8"
                             if asset.suffix == ".js" else "text/css; charset=utf-8")
            else:
                self.respond(404, {"error": "Not found"})

        def do_POST(self):
            if not self.allowed():
                self.respond(403, {"error": "Ingress only"})
                return
            if self.headers.get("X-IP-Scanner") != "1" or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                self.respond(403, {"error": "Invalid request headers"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError("Invalid request size")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("Expected an object")
                path = urlsplit(self.path).path
                if path == "/api/scan":
                    context.start_scan()
                elif path == "/api/stop":
                    context.scanner.stop()
                elif path == "/api/network":
                    with context.lock:
                        if context.scanner.state()["running"]:
                            raise ValueError("המתן לסיום הסריקה לפני החלפת רשת")
                        requested = body.get("cidr")
                        if not isinstance(requested, str):
                            raise ValueError("Missing network")
                        if context.demo and requested != context.selected["cidr"]:
                            raise ValueError("ברשת ההדגמה יש טווח אחד")
                        context.refresh(requested)
                elif path == "/api/alias":
                    with context.lock:
                        if not context.selected:
                            raise ValueError("לא נבחרה רשת")
                        value, alias = body.get("ip"), body.get("alias")
                        if not isinstance(value, str) or not isinstance(alias, str) or len(alias) > 80:
                            raise ValueError("שם המכשיר מוגבל ל־80 תווים")
                        ip = ipaddress.ip_address(value)
                        network = ipaddress.ip_network(context.selected["cidr"])
                        if ip.version != 4 or ip not in network or ip in (network.network_address, network.broadcast_address):
                            raise ValueError("הכתובת אינה בטווח הרשת")
                        alias = alias.strip()
                        if any(ord(char) < 32 for char in alias):
                            raise ValueError("השם מכיל תווים לא תקינים")
                        context.store.set_alias(context.selected["cidr"], str(ip), alias)
                else:
                    self.respond(404, {"error": "Not found"})
                    return
                self.respond(200, context.payload())
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self.respond(400, {"error": str(exc)})
            except Exception:
                LOG.exception("API write failed")
                self.respond(500, {"error": "לא ניתן לשמור את השינוי; בדוק את יומן התוסף"})

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, format_, *args):
            if not self.path.startswith("/api/state"):
                LOG.info("%s %s", self.client_address[0], format_ % args)
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--data", default=os.environ.get("SCANNER_DATA", "/data"))
    parser.add_argument("--options", default="/data/options.json")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    options = load_options(args.options)
    context = Context(args.data, options, args.demo)
    server = ThreadingHTTPServer(("127.0.0.1" if args.demo else "0.0.0.0", args.port), make_handler(context))
    if not args.demo:
        threading.Thread(target=context.scheduler, daemon=True).start()
    LOG.info("IP Scanner listening on %s; demo=%s", args.port, args.demo)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        context.shutdown.set()
        context.scanner.stop()
        server.server_close()


if __name__ == "__main__":
    main()
