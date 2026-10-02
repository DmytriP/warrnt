#!/usr/bin/env python3
"""IN-6 console screen check: does the screen the jury sees actually show THIS node?

Boots the node on a free port with a clean state directory and then verifies, over real
HTTP, the three things that make the console a Design brick rather than a mockup:

  1. SERVED BY THE NODE      GET / returns the console HTML from the package.
  2. DATA IT RENDERS EXISTS  /api/state carries every field the page reads, and after the
                             demo vector it carries live allow/deny/revoked receipts.
  3. THE BUTTON IS REAL      the kill switch performs the exact request the page performs
                             (POST /revoke) and /api/state confirms the halt - a new
                             'revoked' receipt, the warrant pulled, one agent stopped,
                             the rest of the fleet still running.

    python3 scripts/console_check.py            # exits non-zero if any check fails
    python3 scripts/console_check.py --json out.json

It is deliberately independent of a browser: the browser is a renderer, not the contract.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warrnt import demo  # noqa: E402

STATE = ROOT / "state" / "console-check"
DENY = "crm.bulk_export"

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""), flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_raw(url: str, path: str, timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        with urllib.request.urlopen(url.rstrip("/") + path, timeout=timeout) as r:
            return r.status, r.headers.get("content-type", ""), r.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("content-type", ""), exc.read().decode()


def get_json(url: str, path: str) -> dict:
    _s, _c, body = get_raw(url, path)
    return json.loads(body)


def post_json(url: str, path: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url.rstrip("/") + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except Exception:  # noqa: BLE001
            return exc.code, {}


def wait_health(url: str, timeout: float = 25.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            code, _ctype, body = get_raw(url, "/health", timeout=2)
            if code == 200:
                return json.loads(body)
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"node never became healthy: {last}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="", help="also write a machine-readable report here")
    args = ap.parse_args()

    if STATE.exists():
        shutil.rmtree(STATE)
    STATE.mkdir(parents=True, exist_ok=True)

    port = free_port()
    url = f"http://127.0.0.1:{port}"
    env = {**os.environ, "WARRNT_DEV": "1", "WARRNT_HOME": str(STATE), "WARRNT_PORT": str(port)}
    env.pop("WARRNT_UPSTREAM", None)

    log = open(STATE / "server.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "warrnt", "serve", "--port", str(port)],
                            cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_health(url)
        print(f"node up at {url}\n", flush=True)

        # ---- 1. the screen is served by the node itself -------------------------
        code, ctype, html = get_raw(url, "/")
        check("GET / serves the console", code == 200, f"HTTP {code}")
        check("console is text/html", "text/html" in ctype, ctype)
        for marker in ('id="agBody"', 'id="wBody"', 'id="recFeed"', 'id="target"', 'id="revoke"'):
            check(f"screen has {marker}", marker in html)
        check("screen polls /api/state", "/api/state" in html)
        check("screen POSTs /revoke (real kill switch)", "'/revoke'" in html)
        check("screen states the thesis", "No warrant, no action" in html)

        # ---- 2. every field the page reads is in /api/state ---------------------
        st = get_json(url, "/api/state")
        for field in ("agents", "warrants", "receipts", "executor_calls", "chain",
                      "revoked", "last_stop"):
            check(f"/api/state has '{field}'", field in st)
        check("three seed agents are live", len(st["agents"]) == 3,
              f"{len(st['agents'])} agents")
        check("three signed warrants", len(st["warrants"]) == 3 and
              all(w["sig_ok"] for w in st["warrants"]))
        check("chain verifies at boot", st["chain"].get("ok") is True, json.dumps(st["chain"])[:80])

        # ---- the demo vector, so the screen has something real to show ----------
        demo.run(url)
        st = get_json(url, "/api/state")
        decisions = [r["decision"] for r in st["receipts"]]
        check("receipts carry allow", "allow" in decisions, f"{len(decisions)} receipts")
        check("receipts carry deny", "deny" in decisions)
        check("receipts carry revoked", "revoked" in decisions)
        ran = st["executor_calls"].get(DENY, 0)
        check("PII export never reached the upstream (counter == 0)", ran == 0, f"{DENY}={ran}")
        check("chain still verifies after the vector", st["chain"].get("ok") is True)
        check("stop latency measured by the node", st["last_stop"] is not None,
              f"last_stop={st['last_stop']}")

        anchored = get_json(url, "/anchor")
        check("head is anchored", anchored.get("verdict", {}).get("ok") is True,
              json.dumps(anchored.get("verdict"))[:80])

        # ---- 3. the button does what the button says ---------------------------
        # Exactly the request the page makes: fetch('/revoke', {body:{agent}})
        live_agents = [a for a in st["agents"] if a["state"] == "active"]
        target = live_agents[0]["id"]
        revoked_before = st["revoked"]
        code, body = post_json(url, "/revoke", {"agent": target})
        check(f"kill switch: POST /revoke {target} accepted", code == 200, json.dumps(body)[:100])
        st2 = get_json(url, "/api/state")
        check("agent is halted in the state the screen renders",
              next(a["state"] for a in st2["agents"] if a["id"] == target) == "halted")
        check("its warrant is revoked",
              next(w["state"] for w in st2["warrants"] if w["agent"] == target) == "revoked")
        check("a 'revoked' receipt is now the head",
              st2["receipts"] and st2["receipts"][0]["decision"] == "revoked",
              json.dumps(st2["receipts"][0])[:100] if st2["receipts"] else "no receipts")
        check("revoked counter advanced", st2["revoked"] == revoked_before + 1,
              f"{revoked_before} -> {st2['revoked']}")
        check("halted agent leaves the target list",
              sum(1 for a in st2["agents"] if a["state"] == "active") == len(live_agents) - 1)
        code2, _ = post_json(url, "/revoke", {"agent": target})
        check("revoke is idempotent (second press = 409)", code2 == 409, f"HTTP {code2}")
        check("chain survives the kill switch", get_json(url, "/api/state")["chain"].get("ok") is True)

        print()
        failed = [n for n, ok, _ in CHECKS if not ok]
        print(f"CONSOLE CHECK: {len(CHECKS) - len(failed)}/{len(CHECKS)} passed")
        if args.json:
            Path(args.json).write_text(json.dumps(
                {"checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in CHECKS],
                 "passed": len(CHECKS) - len(failed), "total": len(CHECKS)}, indent=2))
        return 0 if not failed else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
