#!/usr/bin/env python3
"""Scoped Nmap adapter for DRAGON//GUARD."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

SCHEMA_VERSION = "dragon-guard/observation/0.1"
DEFAULT_API = os.environ.get("DRAGON_GUARD_API", "http://127.0.0.1:7700")


class ScopeError(Exception):
    pass


class ToolMissing(Exception):
    pass


def detect_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        raise ToolMissing("nmap not found on PATH")
    return path


def nmap_version(nmap: str) -> str:
    out = subprocess.check_output([nmap, "--version"], text=True, timeout=10)
    return out.splitlines()[0].strip() if out else "nmap"


def normalize_target(raw: str) -> str:
    h = raw.strip()
    if not h:
        raise ScopeError("empty target")
    if h.isdigit():
        raise ScopeError("integer-form IP targets are not allowed")
    if "0x" in h.lower():
        raise ScopeError("hex-form IP targets are not allowed")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return h.rstrip(".").lower()


def load_scope_from_api(api: str) -> Dict[str, Any]:
    with urllib.request.urlopen(api + "/api/scope", timeout=5) as resp:
        return json.loads(resp.read().decode())


def authorize(target: str, scope: Dict[str, Any]) -> str:
    norm = normalize_target(target)
    hosts: Set[str] = {h.lower() for h in scope.get("allow_hosts", [])}
    if norm.lower() in hosts or target.lower() in hosts:
        return norm
    try:
        ip = ipaddress.ip_address(norm)
    except ValueError:
        raise ScopeError(f"target out of scope: {target}")
    for cidr in scope.get("allow_cidrs", []):
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return norm
        except ValueError:
            continue
    raise ScopeError(f"target out of scope: {target}")


def run_nmap_xml(nmap: str, target: str, timeout_sec: int = 60):
    args = [nmap, "-sT", "-Pn", "-T3", "--top-ports", "20", "-oX", "-", target]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_sec, check=False)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"nmap failed rc={proc.returncode}: {proc.stderr.strip() or proc.stdout[:200]}")
    if not proc.stdout.strip():
        raise RuntimeError("nmap produced empty stdout; refusing to invent results")
    return proc.stdout, args


def parse_nmap_xml(xml_text: str, execution_id: str, tool_version: str) -> List[Dict[str, Any]]:
    root = ET.fromstring(xml_text)
    obs: List[Dict[str, Any]] = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr", "")
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            service = port.find("service")
            svc_name = service.get("name") if service is not None else None
            material = f"{addr}|{proto}|{portid}|{svc_name}|{execution_id}"
            oid = "obs-" + hashlib.sha256(material.encode()).hexdigest()[:16]
            obs.append(
                {
                    "observation_id": oid,
                    "schema_version": SCHEMA_VERSION,
                    "asset_id": f"host-{addr}",
                    "node_id": "local",
                    "source_tool": "nmap",
                    "observation_type": "service",
                    "timestamp": ts,
                    "clock_source": "wall",
                    "protocol": proto,
                    "target": addr,
                    "result": {"port": int(portid) if portid.isdigit() else portid, "state": "open", "service": svc_name},
                    "severity": "info",
                    "confidence": 0.85,
                    "evidence_refs": [{
                        "id": f"ev-{execution_id}",
                        "kind": "nmap_xml",
                        "path": None,
                        "content_sha256": hashlib.sha256(xml_text.encode()).hexdigest(),
                    }],
                    "execution_id": execution_id,
                    "provenance": {"tool_version": tool_version, "parser": "dragon_guard.adapters.nmap_adapter"},
                }
            )
    return obs


def post_json(api: str, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(api + path, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="DRAGON//GUARD scoped nmap adapter")
    p.add_argument("--target", required=True)
    p.add_argument("--api", default=DEFAULT_API)
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-post", action="store_true")
    p.add_argument("--xml-out", type=Path, default=None)
    args = p.parse_args(argv)

    try:
        nmap = detect_nmap()
        ver = nmap_version(nmap)
    except ToolMissing as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2

    try:
        scope = load_scope_from_api(args.api)
        target = authorize(args.target, scope)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 3

    if args.dry_run:
        print(json.dumps({"ok": True, "dry_run": True, "target": target, "nmap": ver}))
        return 0

    execution_id = f"exec-{int(time.time())}"
    try:
        xml_text, cmd = run_nmap_xml(nmap, target, timeout_sec=args.timeout)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e), "execution_id": execution_id}))
        return 4

    if args.xml_out:
        args.xml_out.write_text(xml_text)

    observations = parse_nmap_xml(xml_text, execution_id, ver)
    posted = []
    if not args.no_post:
        for obs in observations:
            try:
                post_json(args.api, "/api/observations", {"observation": obs})
                posted.append(obs["observation_id"])
            except Exception as e:
                print(json.dumps({"ok": False, "error": f"post failed: {e}"}), file=sys.stderr)

    print(json.dumps({
        "ok": True,
        "execution_id": execution_id,
        "target": target,
        "nmap": ver,
        "command": cmd,
        "observation_count": len(observations),
        "posted": posted,
        "observations": observations,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
