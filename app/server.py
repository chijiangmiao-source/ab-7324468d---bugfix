"""HTTP front door (stdlib only): JSON routes over :mod:`app.service`."""
from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from . import service
from .service import ApiError
from .store import Store

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB cap on any request body


def _make_handler(store: Store) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "LxeConfigSeal/1.0"

        def log_message(self, fmt: str, *args) -> None:  # route through logging
            log.info("%s - %s", self.address_string(), fmt % args)

        # -- helpers --------------------------------------------------------
        def _send_json(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_error(self, status: int, code: str, detail: str) -> None:
            self._send_json(status, {"error": code, "detail": detail})

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                raise ApiError(400, "bad_request", "request body is required")
            if length > MAX_BODY_BYTES:
                raise ApiError(413, "body_too_large", "request body exceeds limit")
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ApiError(400, "bad_json", f"body must be valid UTF-8 JSON: {exc}") from exc
            if not isinstance(body, dict):
                raise ApiError(400, "bad_request", "JSON object expected")
            return body

        # -- routing --------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            parts = [unquote(p) for p in urlsplit(self.path).path.split("/") if p]
            try:
                if parts == ["healthz"] or parts == ["health"]:
                    self._send_json(200, {"status": "ok"})
                    return
                if parts == ["v1", "groups"]:
                    raise ApiError(405, "method_not_allowed", "use POST /v1/groups")
                if len(parts) == 3 and parts[0] == "v1" and parts[1] == "groups":
                    status, payload = service.get_group(store, parts[2])
                    self._send_json(status, payload)
                    return
                if (
                    len(parts) == 4
                    and parts[0] == "v1" and parts[1] == "groups"
                    and parts[3] == "packages"
                ):
                    status, payload = service.list_packages(store, parts[2])
                    self._send_json(status, payload)
                    return
                self._send_error(404, "not_found", f"no route for {self.path}")
            except ApiError as exc:
                self._send_error(exc.status, exc.code, exc.detail)

        def do_POST(self) -> None:  # noqa: N802
            parts = [unquote(p) for p in urlsplit(self.path).path.split("/") if p]
            try:
                if parts == ["v1", "groups"]:
                    body = self._read_json()
                    status, payload = service.create_group(store, body)
                    self._send_json(status, payload)
                    return
                if (
                    len(parts) == 4
                    and parts[0] == "v1" and parts[1] == "groups"
                    and parts[3] == "packages"
                ):
                    body = self._read_json()
                    status, payload = service.submit_package(store, parts[2], body)
                    self._send_json(status, payload)
                    return
                self._send_error(404, "not_found", f"no route for {self.path}")
            except ApiError as exc:
                self._send_error(exc.status, exc.code, exc.detail)

    return Handler


def build_server(host: str, port: int, db_path: str) -> tuple[ThreadingHTTPServer, Store]:
    store = Store(db_path)
    httpd = ThreadingHTTPServer((host, port), _make_handler(store))
    httpd.daemon_threads = True
    return httpd, store
