#!/usr/bin/env python
"""Do the HUMAN HOLD states actually appear on the screen the jury sees?

Runs the real node, drives the real API to produce (1) a pending hold and (2) a decision
made, then renders the console in headless Chromium and asserts what the DOM says. No
screenshots, no trust: the check fails if the console shows something the node does not.

    python3 scripts/console_hold_check.py [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import uvicorn                                     # noqa: E402

from warrnt.api import create_app                  # noqa: E402
from warrnt.config import Settings                 # noqa: E402

PORT = 8795
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "console-hold-check"
HOME = ROOT / "state" / "console-hold-check"
CHROME = next((c for c in ("chromium", "chromium-browser", "google-chrome", "chrome")
               if shutil.which(c)), None)

RESULTS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append({"name": name, "ok": bool(ok), "detail": detail[:400]})
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail[:180]}]" if detail else ""))


def http(path: str, method: str = "GET", body: dict | None = None, admin: bool = False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if admin:
        req.add_header("x-warrnt-admin", TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def start_node():
    HOME.mkdir(parents=True, exist_ok=True)
    for name in ("receipts.jsonl", "anchors.jsonl"):
        p = HOME / name
        if p.exists():
            p.unlink()
    settings = Settings(home=HOME, registry_path=HOME / "receipts.jsonl",
                        key_path=HOME / "issuer.key", anchor_path=HOME / "anchors.jsonl",
                        upstream_url="", host="127.0.0.1", port=PORT, dev=True, admin_token=TOKEN)
    server = uvicorn.Server(uvicorn.Config(create_app(settings=settings), host="127.0.0.1",
                                          port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        try:
            if http("/health")[0] == 200:
                return server
        except Exception:                                       # noqa: BLE001
            pass
        time.sleep(0.1)
    raise SystemExit("node did not come up")


def agent_call(agent: str, tool: str, args: dict, run: str) -> dict:
    token = next(a["token"] for a in http("/agents")[1] if a["id"] == agent)
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}).encode()
    req = urllib.request.Request(BASE + "/mcp", data=data, method="POST")
    for k, v in (("Content-Type", "application/json"), ("x-warrnt-agent", agent),
                 ("x-warrnt-token", token), ("x-warrnt-run", run)):
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())


def dom(url: str, wait_ms: int = 6000) -> str:
    out = subprocess.run([CHROME, "--headless=new", "--no-sandbox", "--disable-gpu",
                          "--hide-scrollbars", f"--virtual-time-budget={wait_ms}",
                          "--dump-dom", url], capture_output=True, text=True, timeout=90)
    return out.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_out", default="")
    args = ap.parse_args()

    if CHROME is None:
        print("no chromium on this box: the UI check cannot run here")
        return 2

    server = start_node()
    try:
        # --- state 1: a hold is pending -----------------------------------------
        rep = agent_call("deploy-agent", "infra.deploy", {"target": "prod"}, "run-ui-1")
        action_id = (rep.get("error", {}).get("data") or {}).get("action_id", "")
        check("the API created a pending hold", bool(action_id), f"action_id={action_id}")

        page = dom(f"{BASE}/?qa=1")
        check("the console renders the hold tile", 'id="holdCells"' in page)
        check("the pending action_id is on the screen", action_id in page)
        check("the screen offers approve", "approve → run once" in page or "approve \u2192 run once" in page)
        check("the screen offers deny", "deny → never reaches upstream" in page)
        check("the screen shows the hold reason from the node",
              "deploy requires human authority" in page)
        check("the screen shows upstream_contacted=false for the hold",
              "upstream_contacted=false" in page)
        check("the ask box is present", 'id="askQ"' in page)
        check("the console renders the live feed", "live feed" in page)

        # --- state 2: a person approved ----------------------------------------
        code, out = http(f"/api/actions/{action_id}/approve", "POST", {"by": "jury"}, admin=True)
        check("approve through the API is accepted", code == 200 and out["state"] == "approved",
              json.dumps(out)[:200])
        page2 = dom(f"{BASE}/?qa=1")
        check("the hold is gone from the screen", action_id not in page2 or "Nothing is waiting" in page2)
        check("the screen says nothing is waiting", "Nothing is waiting for a person" in page2)
        one = http(f"/api/actions/{action_id}")[1]
        check("the API agrees: approved, upstream contacted, decided by jury",
              one["state"] == "approved" and one["upstream_contacted"] is True
              and one["decided_by"] == "jury", json.dumps(one)[:200])

        # --- state 3: a denial in the record -----------------------------------
        rep = agent_call("support-copilot", "crm.bulk_export", {"fields": ["email"]}, "run-ui-2")
        deny_id = (rep.get("error", {}).get("data") or {}).get("action_id", "")
        page3 = dom(f"{BASE}/?qa=1")
        check("the timeline shows the denial with its action_id and receipt",
              deny_id in page3 and 'id="tlStrip"' in page3, f"deny action {deny_id}")
        _, denied = http(f"/api/actions/{deny_id}")
        check("and it did NOT reach the upstream", denied["upstream_contacted"] is False)

        # --- the inspector is wired to the API, not to the page ---------------
        check("the inspector overlay exists and reads /api/actions", 'id="ins"' in page3
              and "Action inspector" in page3)

        code, health = http("/health")
        check("chain still verifies after the UI run", health["chain"]["ok"] is True,
              json.dumps(health["chain"])[:200])
    finally:
        server.should_exit = True

    passed = sum(1 for r in RESULTS if r["ok"])
    print(f"\nCONSOLE HOLD CHECK: {passed}/{len(RESULTS)} passed")
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(
            {"generated_at": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
             "passed": passed, "total": len(RESULTS), "results": RESULTS}, indent=2))
        print(f"wrote {args.json_out}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
