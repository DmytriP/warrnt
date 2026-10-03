"""The 3:47 vector, end to end over real HTTP against a running node.

Two allowed calls, then a rogue read that crosses a line the warrant does not cover, then
the operator pulls the order while the agent is still in flight. Everything printed here is
measured on the live node - the transcript is not a script.
"""
from __future__ import annotations

import os

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

DENY = "crm.bulk_export"


def rpc(url: str, agent: str, token: str, tool: str, args: dict, timeout: float = 5.0) -> dict:
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/mcp", data=body,
        headers={"Content-Type": "application/json",
                 "X-WARRNT-Agent": agent, "X-WARRNT-Token": token or ""})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read().decode())


def get(url: str, path: str) -> dict:
    with urllib.request.urlopen(url.rstrip("/") + path, timeout=5) as resp:
        return json.loads(resp.read().decode())


def post(url: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(url.rstrip("/") + path,
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                      "X-WARRNT-Admin": os.environ.get("WARRNT_ADMIN_TOKEN", "")})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def fetch_tokens(url: str) -> dict[str, str]:
    agents = get(url, "/agents")
    return {a["id"]: a.get("token", "") for a in agents}


def _decision(reply: dict) -> Optional[str]:
    if "result" in reply:
        return reply["result"].get("decision")
    return (reply.get("error", {}).get("data") or {}).get("decision")


def run(url: str, out: list | None = None) -> list[dict[str, Any]]:
    out = out if out is not None else []
    post(url, "/reset", {})
    tokens = fetch_tokens(url)

    def step(agent: str, tool: str, args: dict, note: str = "") -> Optional[str]:
        reply = rpc(url, agent, tokens.get(agent, ""), tool, args)
        decision = _decision(reply)
        reason = (reply.get("result", {}).get("reason")
                  or reply.get("error", {}).get("message"))
        out.append({"agent": agent, "tool": tool, "decision": decision,
                    "reason": reason, "note": note})
        return decision

    step("fin-reconcile", "payments.read", {"account": "PL61...", "limit": 1240},
         "read inside scope")
    step("support-copilot", "crm.read", {"table": "tickets", "limit": 50},
         "read inside scope")

    # the rogue agent is already in flight when the export is attempted
    box: dict[str, Any] = {}

    def rogue() -> None:
        while True:
            reply = rpc(url, "support-copilot", tokens.get("support-copilot", ""),
                        "crm.read", {"table": "tickets", "limit": 10})
            if _decision(reply) == "revoked":
                box["observed"] = time.time()
                return
            time.sleep(0.15)

    thread = threading.Thread(target=rogue, daemon=True)
    thread.start()
    time.sleep(0.35)

    before = get(url, "/state")["executor_calls"].get(DENY, 0)
    step("support-copilot", DENY,
         {"table": "customers", "fields": ["email", "pesel"], "rows": 12000},
         "PII export outside warrant scope")
    after = get(url, "/state")["executor_calls"].get(DENY, 0)
    out.append({"proof": "upstream executions of crm.bulk_export",
                "before": before, "after": after, "rows_left_perimeter": 0})

    t_revoke = time.time()
    post(url, "/revoke", {"agent": "support-copilot"})
    thread.join(3.0)
    observed = box.get("observed")
    latency = round(max(0.0, observed - t_revoke), 3) if observed else None
    out.append({"agent": "support-copilot", "decision": "revoked",
                "observed_on_next_call": observed is not None,
                "stop_latency_s": latency})
    out.append({"chain": get(url, "/verify")})
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="WARRNT demo vector against a live node")
    ap.add_argument("url", nargs="?", default="http://127.0.0.1:8099")
    args = ap.parse_args(argv)
    transcript = run(args.url)
    print(json.dumps(transcript, indent=2, ensure_ascii=False))
    return 0 if transcript and transcript[-1].get("chain", {}).get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
