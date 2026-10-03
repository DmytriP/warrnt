#!/usr/bin/env python
"""PR-14 evidence: run the human-hold slice against a REAL node over HTTP.

One command, one saved artifact. It starts the node (uvicorn, real sockets), drives the
whole path with HTTP only - no TestClient shortcuts - and writes:

    evidence/human_hold-<UTC stamp>.json    every check, with the fields a juror asks for
    evidence/human_hold-<UTC stamp>.md      the same as a table you can paste in a PR

Each check records: action_id, run_id, warrant, warrant_state, decision,
upstream_contacted, receipt - and whether /api/actions/{id} and /api/state agree.
The upstream calls are read from the node's own counter (/api/state.executor_calls), so
"deny did not reach the upstream" is the node's statement, not the script's.
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import uvicorn                                    # noqa: E402

from warrnt.api import create_app                 # noqa: E402
from warrnt.config import Settings                # noqa: E402

PORT = 8791
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "evidence-operator-token"
HOME = ROOT / "evidence" / ".node"


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


def start_node() -> uvicorn.Server:
    HOME.mkdir(parents=True, exist_ok=True)
    for name in ("receipts.jsonl", "issuer.key", "anchors.jsonl"):
        p = HOME / name
        if p.exists() and name != "issuer.key":
            p.unlink()
    settings = Settings(home=HOME, registry_path=HOME / "receipts.jsonl",
                        key_path=HOME / "issuer.key", anchor_path=HOME / "anchors.jsonl",
                        upstream_url="", host="127.0.0.1", port=PORT, dev=True,
                        admin_token=TOKEN)
    app = create_app(settings=settings)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        try:
            if http("/health")[0] == 200:
                return server
        except Exception:                                        # noqa: BLE001
            pass
        time.sleep(0.1)
    raise SystemExit("node did not come up")


def agent_token(agent: str) -> str:
    return next(a["token"] for a in http("/agents")[1] if a["id"] == agent)


def mcp(agent: str, tool: str, args: dict, run: str):
    code, body = http("/mcp", "POST", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                       "params": {"name": tool, "arguments": args}})
    return code, body


def call(agent: str, tool: str, args: dict, run: str) -> tuple[int, dict]:
    """A tools/call carrying the agent's own identity and token (the node's /mcp route)."""
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}).encode()
    req = urllib.request.Request(BASE + "/mcp", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-warrnt-agent", agent)
    req.add_header("x-warrnt-token", agent_token(agent))
    req.add_header("x-warrnt-run", run)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def detail(reply: dict) -> dict:
    return reply.get("result") or reply.get("error", {}).get("data") or {}


def upstream_calls() -> dict:
    return http("/api/state")[1]["executor_calls"]


def snapshot(action_id: str) -> dict:
    """Everything a juror wants about one action, from the node's own endpoints."""
    _, one = http(f"/api/actions/{action_id}")
    _, state = http("/api/state")
    logged = next((a for a in state["action_log"] if a["action_id"] == action_id), None)
    return {"api": one, "state": logged, "agree": bool(logged and logged == one),
            "receipts": len(http("/receipts")[1])}


def main() -> int:
    server = start_node()
    checks: list[dict] = []
    try:
        # 1. allow - a scoped read runs
        before = upstream_calls()
        _, rep = call("fin-reconcile", "payments.read", {"rows": 1240}, "run-fin-1")
        d = detail(rep)
        checks.append(dict(check="allow · scoped read runs", decision=d.get("decision"),
                           executed=d.get("executed"),
                           upstream_delta=upstream_calls().get("payments.read", 0)
                           - before.get("payments.read", 0), **snapshot(d["action_id"])))

        # 2. redact - the upstream is handed the request WITHOUT the personal fields
        before = upstream_calls()
        _, rep = call("support-copilot", "crm.read",
                      {"rows": 3, "fields": ["subject", "email", "pesel"]}, "run-support-2")
        d = detail(rep)
        checks.append(dict(check="redact · personal fields stripped before upstream",
                           decision=d.get("decision"), executed=d.get("executed"),
                           redacted=d.get("redacted"), upstream_received=d.get("upstream_params"),
                           upstream_delta=upstream_calls().get("crm.read", 0)
                           - before.get("crm.read", 0), **snapshot(d["action_id"])))

        # 3. deny - scope violation, upstream never contacted
        before = upstream_calls()
        _, rep = call("support-copilot", "crm.bulk_export",
                      {"rows": 12000, "fields": ["email", "pesel"]}, "run-support-3")
        d = detail(rep)
        checks.append(dict(check="deny · scope violation, before upstream",
                           decision=d.get("decision"), executed=d.get("executed"),
                           upstream_delta=upstream_calls().get("crm.bulk_export", 0)
                           - before.get("crm.bulk_export", 0), **snapshot(d["action_id"])))

        # 4. human hold -> APPROVE: held first, executed once, after the human receipt
        before = upstream_calls()
        _, rep = call("deploy-agent", "infra.deploy", {"target": "prod"}, "run-deploy-4")
        d = detail(rep)
        held = snapshot(d["action_id"])
        held.update(check="human · irreversible act is HELD (pending)", decision=d.get("decision"),
                    executed=d.get("executed"), upstream_delta=upstream_calls().get("infra.deploy", 0)
                    - before.get("infra.deploy", 0))
        checks.append(held)
        code, appr = http(f"/api/actions/{d['action_id']}/approve", "POST", {"by": "Indra"}, admin=True)
        approved = snapshot(d["action_id"])
        approved.update(check="human · APPROVED by a named person → executed once",
                        http_status=code, response=appr,
                        upstream_delta=upstream_calls().get("infra.deploy", 0)
                        - before.get("infra.deploy", 0))
        checks.append(approved)
        _, again = http(f"/api/actions/{d['action_id']}/approve", "POST", {"by": "Indra"}, admin=True)
        checks.append(dict(check="human · a hold is single-use (second approve refused)",
                           second_approve=again))

        # 5. human hold -> DENY: nothing is sent
        before = upstream_calls()
        _, rep = call("report-bot", "crm.bulk_export",
                      {"rows": 12000, "fields": ["email", "pesel"]}, "run-report-5")
        d = detail(rep)
        code, den = http(f"/api/actions/{d['action_id']}/deny", "POST", {"by": "Indra"}, admin=True)
        denied = snapshot(d["action_id"])
        denied.update(check="human · DENIED by a named person → upstream NOT contacted",
                      http_status=code, response=den,
                      upstream_delta=upstream_calls().get("crm.bulk_export", 0)
                      - before.get("crm.bulk_export", 0))
        checks.append(denied)

        # 6. revoke - the brake wins, including over a pending hold
        _, rep = call("deploy-agent", "infra.deploy", {"target": "prod"}, "run-deploy-6")
        held_id = detail(rep).get("action_id")
        before = upstream_calls()
        _, rev = http("/revoke", "POST", {"agent": "deploy-agent"}, admin=True)
        code, after = call("deploy-agent", "infra.deploy", {"target": "prod"}, "run-deploy-6b")
        d2 = detail(after)
        _, expired = http(f"/api/actions/{held_id}/approve", "POST", {"by": "Indra"}, admin=True)
        checks.append(dict(check="revoke · further calls refused; the stale hold expires",
                           revoke=rev, next_decision=d2.get("decision"),
                           next_executed=d2.get("executed"),
                           stale_hold=expired.get("state"),
                           upstream_delta=upstream_calls().get("infra.deploy", 0)
                           - before.get("infra.deploy", 0), **snapshot(d2["action_id"])))

        # 7. Hermes Control - the answers are fields of the record, or an admission
        asks = []
        for q in ["What is happening?", "Why was support-copilot blocked?",
                  "Which action is waiting for me?", "Did it reach the CRM?",
                  "Show me the warrant.", "What happens if I approve this?"]:
            _, a = http("/api/ask", "POST", {"q": q})
            asks.append({"q": q, "answer": a["answer"], "evidence": a["evidence"],
                         "grounded": a["grounded"]})
        checks.append(dict(check="ask · answers assembled from the record (no model in the path)",
                           asks=asks))

        # 8. chain integrity after the whole run
        _, health = http("/health")
        checks.append(dict(check="chain · integrity after every decision above",
                           chain=health["chain"]))
    finally:
        server.should_exit = True

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "evidence" / f"human_hold-{stamp}.json"
    out.write_text(json.dumps({"generated_at": stamp, "base": BASE, "checks": checks},
                              indent=2, sort_keys=False))
    md = ROOT / "evidence" / f"human_hold-{stamp}.md"
    lines = [f"# Human-hold evidence · {stamp}", "",
             "| check | decision | upstream_contacted | executed | receipt | action_id |",
             "| --- | --- | --- | --- | --- | --- |"]
    for c in checks:
        api = c.get("api") or {}
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            c["check"], c.get("decision") or api.get("decision") or "-",
            c.get("upstream_delta", api.get("upstream_contacted", "-")),
            c.get("executed", "-"), (api.get("receipt") or "-"),
            (api.get("action_id") or c.get("response", {}).get("action_id") or "-")))
    md.write_text("\n".join(lines) + "\n")

    print(f"\nwrote {out.relative_to(ROOT)} and {md.relative_to(ROOT)}\n")
    for c in checks:
        api = c.get("api") or {}
        print(f"- {c['check']}")
        print(f"    action_id={api.get('action_id') or c.get('response', {}).get('action_id') or '-'}"
              f" run_id={api.get('run_id') or '-'} warrant={api.get('warrant') or '-'}"
              f" decision={api.get('decision') or c.get('next_decision') or '-'}"
              f" upstream_contacted={api.get('upstream_contacted')}"
              f" receipt={api.get('receipt') or '-'}"
              f" api==state: {c.get('agree')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
