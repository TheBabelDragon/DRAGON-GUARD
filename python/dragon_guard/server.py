#!/usr/bin/env python3
"""DRAGON//GUARD local lab API + dashboard (stdlib only)."""
from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard" / "index.html"
SCHEMA_VERSION = "dragon-guard/observation/0.1"

_lock = threading.Lock()
_registry: Dict[str, Any] = {
    "assets": {},
    "observations": [],
    "executions": [],
}
_scope = {
    "allow_hosts": ["127.0.0.1", "localhost", "::1"],
    "allow_cidrs": ["127.0.0.0/8"],
    "require_authorized_asset": False,
}


def authorize_target(raw: str) -> str:
    import ipaddress

    h = raw.strip()
    if not h:
        raise ValueError("empty target")
    if h.isdigit():
        raise ValueError("integer-form IP targets are not allowed")
    if "0x" in h.lower():
        raise ValueError("hex-form IP targets are not allowed")
    try:
        norm = str(ipaddress.ip_address(h))
    except ValueError:
        norm = h.rstrip(".").lower()
    hosts = {x.lower() for x in _scope["allow_hosts"]}
    if norm.lower() in hosts:
        return norm
    try:
        ip = ipaddress.ip_address(norm)
        for cidr in _scope["allow_cidrs"]:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return norm
    except ValueError:
        pass
    raise ValueError(f"target out of scope: {raw}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[dragon-guard] {self.address_string()} {fmt % args}")

    def _json(self, code: int, obj: Any):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Any:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n).decode() or "null")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            data = DASHBOARD.read_bytes() if DASHBOARD.exists() else b"<h1>DRAGON//GUARD</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/api/health":
            return self._json(
                200,
                {
                    "service": "dragon-guard",
                    "version": "0.1.0",
                    "schema_version": SCHEMA_VERSION,
                    "kali_required": False,
                },
            )
        with _lock:
            if path == "/api/assets":
                return self._json(200, list(_registry["assets"].values()))
            if path == "/api/observations":
                return self._json(200, list(_registry["observations"]))
            if path == "/api/executions":
                return self._json(200, list(_registry["executions"]))
            if path == "/api/scope":
                return self._json(200, _scope)
            if path == "/api/tools":
                nmap = None
                try:
                    out = subprocess.check_output(["nmap", "--version"], text=True, timeout=5)
                    nmap = out.splitlines()[0]
                except Exception:
                    pass
                return self._json(
                    200,
                    {
                        "nmap": {
                            "installed": nmap is not None,
                            "version_line": nmap,
                            "adapter": "python/dragon_guard/adapters/nmap_adapter.py",
                        }
                    },
                )
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except Exception:
            return self._json(400, {"error": "invalid json"})
        if path == "/api/scope/check":
            try:
                norm = authorize_target(body.get("target", ""))
                return self._json(200, {"allowed": True, "normalized": norm})
            except Exception as e:
                return self._json(403, {"allowed": False, "error": str(e)})
        if path == "/api/assets":
            try:
                for a in body.get("addresses") or []:
                    authorize_target(a)
            except Exception as e:
                return self._json(403, {"error": str(e)})
            asset = {
                "asset_id": body["asset_id"],
                "name": body.get("name", body["asset_id"]),
                "addresses": body.get("addresses") or [],
                "hostnames": body.get("hostnames") or [],
                "tags": [],
                "authorized": body.get("authorized", True),
                "notes": "",
            }
            with _lock:
                _registry["assets"][asset["asset_id"]] = asset
            return self._json(201, asset)
        if path == "/api/observations":
            obs = body.get("observation") or body
            if obs.get("schema_version") != SCHEMA_VERSION:
                return self._json(400, {"error": "schema_version mismatch"})
            with _lock:
                _registry["observations"].append(obs)
            return self._json(201, obs)
        if path == "/api/executions":
            with _lock:
                _registry["executions"].append(body)
            return self._json(201, body)
        self._json(404, {"error": "not found"})


def main():
    host = os.environ.get("DRAGON_GUARD_BIND", "127.0.0.1")
    port = int(os.environ.get("DRAGON_GUARD_PORT", "7700"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"DRAGON//GUARD listening on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
