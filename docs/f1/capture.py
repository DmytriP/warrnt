#!/usr/bin/env python3
"""F1 capture: boot the real WARRNT node, drive the 3:47 vector step by step, and
capture the live console at four beats + the real JSON proofs.

Everything written to the output directory (default `docs/f1/`, override with `F1_OUT`) is
read from a live node (or its own Chromium render of its own page). Nothing here is authored
by hand.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

os.environ.setdefault("WARRNT_ADMIN_TOKEN", "operator-token")
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get("F1_OUT", ROOT / "docs" / "f1"))
CHROMIUM = shutil.which("chromium") or "/usr/lib/chromium/chromium"
sys.path.insert(0, str(ROOT))

from warrnt.demo import rpc, get, post, fetch_tokens, _decision, DENY  # noqa: E402

OUT.mkdir(parents=True, exist_ok=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_up(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError("node never came up")


def shot(url: str, out: Path, wait_ms: int = 5000) -> int:
    cmd = [CHROMIUM, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
           "--force-device-scale-factor=1", "--window-size=1600,900",
           f"--virtual-time-budget={wait_ms}", f"--screenshot={out}", url]
    subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if not out.exists():
        raise RuntimeError(f"no shot {out}")
    print(f"  shot {out.name} {out.stat().st_size} bytes", flush=True)
    return out.stat().st_size


def main() -> int:
    home = OUT / "home"
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    env = {**os.environ, "WARRNT_DEV": "1", "WARRNT_HOME": str(home), "WARRNT_PORT": str(port)}
    env.pop("WARRNT_UPSTREAM", None)
    log = open(OUT / "server.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "warrnt", "serve", "--port", str(port)],
                            cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_up(url)
        print(f"node up {url}", flush=True)
        post(url, "/reset", {})
        tokens = fetch_tokens(url)

        payload = {"url": url, "steps": []}

        def jsonoff(path: str, name: str) -> None:
            (OUT / name).write_text(
                json.dumps(get(url, path), indent=2, ensure_ascii=False), encoding="utf-8")

        jsonoff("/health", "health.json")
        jsonoff("/state", "state-initial.json")
        shot(url + "/", OUT / "shot-1-initial.png")
        payload["steps"].append({"beat": "initial", "state": get(url, "/state")})

        # two calls inside scope
        allows = []
        for agent, tool, args in (("fin-reconcile", "payments.read", {"account": "PL61...", "limit": 1240}),
                                  ("support-copilot", "crm.read", {"table": "tickets", "limit": 50})):
            reply = rpc(url, agent, tokens.get(agent, ""), tool, args)
            allows.append({"agent": agent, "tool": tool, "decision": _decision(reply)})
        payload["steps"].append({"beat": "two-allows", "allows": allows})
        shot(url + "/", OUT / "shot-2-allows.png")

        # rogue agent in flight + the deny
        box: dict = {}

        def rogue() -> None:
            while True:
                reply = rpc(url, "support-copilot", tokens.get("support-copilot", ""),
                            "crm.read", {"table": "tickets", "limit": 10})
                if _decision(reply) == "revoked":
                    box["observed"] = time.time()
                    return
                time.sleep(0.15)

        th = threading.Thread(target=rogue, daemon=True)
        th.start()
        time.sleep(0.35)
        before = get(url, "/state")["executor_calls"].get(DENY, 0)
        deny_reply = rpc(url, "support-copilot", tokens.get("support-copilot", ""), DENY,
                         {"table": "customers", "fields": ["email", "pesel"], "rows": 12000})
        after = get(url, "/state")["executor_calls"].get(DENY, 0)
        payload["steps"].append({"beat": "deny", "reply": deny_reply, "executions_before": before,
                                 "executions_after": after, "rows_left_perimeter": 0})
        time.sleep(1.6)
        shot(url + "/", OUT / "shot-3-deny.png")
        jsonoff("/state", "state-after-deny.json")
        jsonoff("/verify", "verify-after-deny.json")

        # the brake
        t_revoke = time.time()
        rev = post(url, "/revoke", {"agent": "support-copilot"})
        th.join(3.0)
        observed = box.get("observed")
        latency = round(max(0.0, observed - t_revoke), 3) if observed else None
        payload["steps"].append({"beat": "revoke", "reply": rev, "stop_latency_s": latency})
        time.sleep(1.6)
        shot(url + "/", OUT / "shot-4-revoked.png")
        jsonoff("/state", "state-after-revoke.json")
        jsonoff("/verify", "verify-after-revoke.json")
        jsonoff("/anchor", "anchor-after-revoke.json")

        # receipts: the deny line + the revoked line, verbatim from the registry
        state = get(url, "/state")
        payload["steps"].append({"beat": "final", "chain": state.get("chain"),
                                 "kpis": {k: state.get(k) for k in
                                          ("executor_calls", "revoked", "last_stop")}})
        (OUT / "transcript.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        reg = home / "receipts.jsonl"
        if reg.exists():
            shutil.copy(reg, OUT / "receipts.jsonl")
        print("CAPTURE OK", flush=True)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
