"""API regression tests for DRAGON//GUARD stdlib server."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = "http://127.0.0.1:7701"  # distinct port to avoid collisions


def _req(method: str, path: str, body: bytes | None = None, content_type: str | None = None):
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(API + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main() -> None:
    env = dict(os.environ)
    env["DRAGON_GUARD_PORT"] = "7701"
    env["PYTHONPATH"] = str(ROOT / "python")
    proc = subprocess.Popen(
        [sys.executable, "-m", "dragon_guard.server"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        ready = False
        for _ in range(50):
            try:
                code, body = _req("GET", "/api/health")
                if code == 200 and "dragon-guard" in body:
                    ready = True
                    break
            except Exception:
                time.sleep(0.1)
        assert ready, "server failed to become ready"

        code, body = _req(
            "POST",
            "/api/scope/check",
            body=json.dumps({"target": "127.0.0.1"}).encode(),
            content_type="application/json",
        )
        assert code == 200, code
        data = json.loads(body)
        assert data.get("allowed") is True

        code, body = _req(
            "POST",
            "/api/scope/check",
            body=json.dumps({"target": "8.8.8.8"}).encode(),
            content_type="application/json",
        )
        assert code == 403, code
        data = json.loads(body)
        assert data.get("allowed") is False

        code, body = _req(
            "POST",
            "/api/scope/check",
            body=b"not-json",
            content_type="application/json",
        )
        assert code == 400, code

        code, _ = _req("GET", "/api/does-not-exist")
        assert code == 404, code

        print("api regression OK")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
