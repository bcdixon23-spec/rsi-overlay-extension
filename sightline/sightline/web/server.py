"""A small local web dashboard: start scans, watch progress, browse history.

Security posture (this tool can launch scans, so the UI itself must be safe):
  * binds to 127.0.0.1 by default
  * a random access token is required whenever it listens on another interface
  * state-changing requests need a custom header + JSON body (blocks CSRF from web pages)
  * the Host header is validated on localhost to block DNS-rebinding attacks
"""

from __future__ import annotations

import hmac
import json
import secrets
import sys
import threading
import traceback
import uuid
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from sightline import __version__
from sightline.config import scans_path, vulndb_path
from sightline.knowledge import help_payload
from sightline.netscan import parse_ports
from sightline.report.html import render_html
from sightline.scanner import ScanOptions, run_scan
from sightline.settings import load as settings_load
from sightline.settings import update as settings_update
from sightline.storage import ScanStore
from sightline.vulndb.store import VulnDB
from sightline.web.dashboard import DASHBOARD_HTML

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
MAX_LOG = 400


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _start_job(payload: dict) -> str:
    targets = [t for t in str(payload.get("targets", "")).replace(",", " ").split() if t]
    local = bool(payload.get("local"))
    if not targets and not local:
        raise ValueError("enter at least one target or choose 'scan this machine'")
    for t in targets:
        if t.startswith("@"):
            raise ValueError("target files (@file) are only supported from the command line")
    ssh_user = (payload.get("ssh_user") or "").strip() or None
    ssh_key = (payload.get("ssh_key") or "").strip() or None
    opts = ScanOptions(
        targets=targets,
        name=(payload.get("name") or "").strip(),
        ports=parse_ports((payload.get("ports") or "default").strip()),
        local=local,
        ssh=bool(ssh_user or ssh_key or payload.get("ssh")),
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        sudo=bool(payload.get("sudo")),
        network=not payload.get("no_network"),
    )
    job_id = uuid.uuid4().hex[:10]
    job = {"id": job_id, "status": "running", "started": _now(), "log": [], "scan_id": None,
           "targets": targets or ["localhost"], "error": None}  # fmt: skip
    with JOBS_LOCK:
        JOBS[job_id] = job

    def log(msg: str) -> None:
        with JOBS_LOCK:
            job["log"].append(msg)
            del job["log"][:-MAX_LOG]

    def work() -> None:
        store = ScanStore(scans_path())
        try:
            result = run_scan(opts, progress=log, store=store)
            with JOBS_LOCK:
                job["status"] = "done"
                job["scan_id"] = result.scan_id
                job["summary"] = result.summary()
        except Exception as exc:  # noqa: BLE001
            log(traceback.format_exc(limit=2))
            with JOBS_LOCK:
                job["status"] = "failed"
                job["error"] = str(exc)
        finally:
            store.close()
            with JOBS_LOCK:
                job["finished"] = _now()

    threading.Thread(target=work, name=f"scan-{job_id}", daemon=True).start()
    return job_id


class Handler(BaseHTTPRequestHandler):
    server_version = f"Sightline/{__version__}"
    token: str | None = None
    loopback_only = True

    def log_message(self, fmt, *args):  # quieter than the default
        if "--debug" in sys.argv:
            super().log_message(fmt, *args)

    # ------------------------------------------------------------ plumbing

    def _send(self, code: int, body: bytes | str, ctype: str = "application/json", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "charset" not in ctype else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, data) -> None:
        self._send(code, json.dumps(data))

    def _authorized(self) -> bool:
        if self.loopback_only:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            if host not in ("127.0.0.1", "localhost", "::1"):
                return False  # DNS rebinding protection
        if not self.token:
            return True
        query = parse_qs(urlparse(self.path).query)
        candidates = [
            (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip(),
            (query.get("token") or [""])[0],
        ]
        cookie = SimpleCookie(self.headers.get("Cookie") or "")
        if "sightline_token" in cookie:
            candidates.append(cookie["sightline_token"].value)
        return any(c and hmac.compare_digest(c, self.token) for c in candidates)

    def _deny(self) -> None:
        self._send(401, "Unauthorized: open the URL with ?token=... printed at startup.", "text/plain")

    def _store(self) -> ScanStore:
        return ScanStore(scans_path())

    # -------------------------------------------------------------- routes

    def do_GET(self):  # noqa: N802
        if not self._authorized():
            return self._deny()
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        extra = {}
        if self.token and "token" in parse_qs(url.query):
            extra["Set-Cookie"] = f"sightline_token={self.token}; HttpOnly; SameSite=Strict; Path=/"
        if not parts:
            return self._send(200, DASHBOARD_HTML, "text/html", extra)
        if parts == ["api", "scans"]:
            store = self._store()
            try:
                return self._json(200, store.list(100))
            finally:
                store.close()
        if len(parts) == 3 and parts[:2] == ["api", "scans"]:
            store = self._store()
            try:
                result = store.get(parts[2])
            finally:
                store.close()
            if not result:
                return self._json(404, {"error": "not found"})
            return self._json(200, result.to_dict())
        if len(parts) == 2 and parts[0] == "scans":
            store = self._store()
            try:
                result = store.get(parts[1])
            finally:
                store.close()
            if not result:
                return self._send(404, "Scan not found", "text/plain")
            return self._send(200, render_html(result, settings_load()), "text/html", extra)
        if parts == ["api", "settings"]:
            return self._json(200, settings_load().to_dict())
        if parts == ["api", "help"]:
            return self._json(200, help_payload())
        if parts == ["api", "jobs"]:
            with JOBS_LOCK:
                jobs = sorted(JOBS.values(), key=lambda j: j["started"], reverse=True)[:20]
                return self._json(200, json.loads(json.dumps(jobs)))
        if parts == ["api", "db"]:
            db = VulnDB(vulndb_path())
            try:
                return self._json(200, db.stats())
            finally:
                db.close()
        return self._send(404, "Not found", "text/plain")

    def _mutation_allowed(self) -> bool:
        if not self._authorized():
            self._deny()
            return False
        # Browsers cannot add custom headers cross-origin without a CORS preflight,
        # which this server never approves - so this blocks CSRF.
        if self.headers.get("X-Sightline") != "1":
            self._json(403, {"error": "missing X-Sightline header"})
            return False
        return True

    def _read_json(self) -> dict:
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ValueError("JSON body required")
        length = int(self.headers.get("Content-Length") or 0)
        if length > 65536:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):  # noqa: N802
        if not self._mutation_allowed():
            return
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/settings":
            try:
                payload = self._read_json()
                settings = settings_update(**{k: v for k, v in payload.items()})
            except (ValueError, TypeError) as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(200, settings.to_dict())
        if path != "/api/scans":
            return self._json(404, {"error": "not found"})
        try:
            payload = self._read_json()
            job_id = _start_job(payload)
        except (ValueError, TypeError) as exc:
            return self._json(400, {"error": str(exc)})
        return self._json(202, {"job": job_id})

    def do_DELETE(self):  # noqa: N802
        if not self._mutation_allowed():
            return
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        if len(parts) == 3 and parts[:2] == ["api", "scans"]:
            store = self._store()
            try:
                ok = store.delete(parts[2])
            finally:
                store.close()
            return self._json(200 if ok else 404, {"deleted": ok})
        return self._json(404, {"error": "not found"})


def serve(host: str = "127.0.0.1", port: int = 8077, token: str | None = None) -> int:
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not token:
        token = secrets.token_urlsafe(18)
    Handler.token = token
    Handler.loopback_only = loopback
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"sightline: cannot listen on {host}:{port}: {exc}", file=sys.stderr)
        return 1
    url = f"http://{'127.0.0.1' if loopback else host}:{port}/"
    if token:
        url += f"?token={token}"
    print(f"Sightline dashboard running at {url}  (Ctrl+C to stop)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
