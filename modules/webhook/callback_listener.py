"""
modules/webhook/callback_listener.py

Emula interactsh: ascolta su un host:port locale per ricevere callback
da payload OOB (SSRF, XXE, SSTI con curl, ecc.).
Scrive ogni ping ricevuto in reports/<service>/webhook_callbacks.json.

Avviato come thread daemon dall'orchestratore se settings.webhook_url è configurato.
Lo start.py stampa l'URL locale da usare come payload nei test OOB.

Usage (da orchestratore):
    from modules.webhook.callback_listener import WebhookListener
    listener = WebhookListener(report_dir, settings)
    listener.start()   # thread daemon
    print("OOB URL:", listener.url)
    ...
    listener.stop()
"""

import http.server
import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_HOST = "0.0.0.0"
_DEFAULT_PORT = 18080


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler: accetta qualsiasi richiesta e logga il ping."""

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        ping = {
            "timestamp": datetime.now(datetime.timezone.utc).isoformat(),
            "remote_addr": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "body": body[:512],
        }
        logger.info("WEBHOOK PING: %s %s from %s", self.command, self.path, self.client_address[0])
        self.server.listener._record(ping)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, fmt, *args):
        pass  # suppress default httpd logging


class _ReusableTCPServer(http.server.HTTPServer):
    allow_reuse_address = True


class WebhookListener:
    def __init__(self, report_dir: str, settings: dict):
        self.report_dir = Path(report_dir)
        port = int(settings.get("webhook_port", _DEFAULT_PORT))
        host = settings.get("webhook_bind", _DEFAULT_HOST)
        self._port = port
        self._host = host
        self._server: _ReusableTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._pings: list[dict] = []
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"

    def start(self):
        handler_class = _CallbackHandler
        server = _ReusableTCPServer((self._host, self._port), handler_class)
        server.listener = self  # back-reference for handler
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True, name="webhook-listener")
        self._thread.start()
        logger.info("WebhookListener started on %s", self.url)

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._flush()

    def _record(self, ping: dict):
        with self._lock:
            self._pings.append(ping)
        self._flush()

    def _flush(self):
        with self._lock:
            data = list(self._pings)
        out = self.report_dir / "webhook_callbacks.json"
        out.write_text(json.dumps(data, indent=2))

    def wait_for_ping(self, timeout: float = 10.0) -> dict | None:
        """Blocca fino a ricevere un ping (utile nei test OOB attivi)."""
        t0 = time.monotonic()
        start_count = len(self._pings)
        while time.monotonic() - t0 < timeout:
            with self._lock:
                if len(self._pings) > start_count:
                    return self._pings[-1]
            time.sleep(0.2)
        return None
