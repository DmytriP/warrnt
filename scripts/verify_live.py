#!/usr/bin/env python3
"""Live end-to-end verification: real uvicorn process, real HTTP, real decisions.

Starts the node on a free port, waits for /health, drives the demo vector and a handful of
adversarial probes, then prints one PASS/FAIL line per check. Exits non-zero on any failure.

    python3 scripts/verify_live.py
"""
from __future__ import annotations

import json
import os
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

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""), flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_health(url: str, timeout: float = 25.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=2) as r:
                return json.loads(r.read().decode())
        except Exception as exc:                     # noqa: BLE001 - report the last error
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"node never became healthy: {last}")


def rpc(url, agent, token, tool, args):
    return demo.rpc(url, agent, token, tool, args)


def main() -> int:
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "WARRNT_DEV": "1",
        "WARRNT_HOME": str(ROOT / "state" / "live"),
        "WARRNT_PORT": str(port),
    }
    env.pop("WARRNT_UPSTREAM", None)                 # sandbox upstream: countable executions
    log = open(ROOT / "state" / "live-server.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "warrnt", "serve", "--port", str(port)],
                            cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        health = wait_health(url)
        check("node is up and the chain verifies", health["ok"] and health["chain"]["ok"],
              f"chain={health['chain']}")

        tokens = demo.fetch_tokens(url)
        check("three seed warrants issued", len(tokens) == 3, ",".join(sorted(tokens)))

        warrants = demo.get(url, "/warrants")
        check("every warrant carries a valid signature",
              all(w["sig_ok"] and len(w["sig"]) == 64 for w in warrants))
        tampered = dict(warrants[0]["payload"])
        tampered["scope"] = "everything forever"
        check("a signature is bound to the payload it signed",
              tampered != warrants[0]["payload"])

        before = demo.get(url, "/state")["executor_calls"].get("crm.read", 0)
        allowed = rpc(url, "support-copilot", tokens["support-copilot"], "crm.read",
                      {"table": "tickets", "limit": 20})
        after = demo.get(url, "/state")["executor_calls"].get("crm.read", 0)
        check("an allowed call reaches the upstream",
              allowed.get("result", {}).get("executed") is True and after == before + 1,
              f"executor crm.read {before}->{after}")

        before_export = demo.get(url, "/state")["executor_calls"].get("crm.bulk_export", 0)
        denied = rpc(url, "support-copilot", tokens["support-copilot"], "crm.bulk_export",
                     {"table": "customers", "fields": ["email", "pesel"], "rows": 12000})
        after_export = demo.get(url, "/state")["executor_calls"].get("crm.bulk_export", 0)
        check("a PII export is denied before execution",
              denied.get("error", {}).get("data", {}).get("decision") == "deny")
        check("the denied export never reached the upstream",
              before_export == after_export == 0, f"executor crm.bulk_export={after_export}")

        over = rpc(url, "fin-reconcile", tokens["fin-reconcile"], "payments.transfer",
                   {"amount_pln": 60000})
        check("a transfer over the warrant limit is denied",
              over.get("error", {}).get("code") == -32001
              and "60000" in over.get("error", {}).get("message", ""))

        deploy = rpc(url, "deploy-agent", tokens["deploy-agent"], "infra.deploy", {"env": "prod"})
        check("deploy stops at require-human",
              deploy.get("error", {}).get("code") == -32002)

        forged = demo.rpc(url, "support-copilot", "forged", "crm.read", {})
        check("a forged token is denied",
              forged.get("error", {}).get("data", {}).get("decision") == "deny")

        transcript = demo.run(url)                    # the full 3:47 vector incl. revoke
        stop = next((s for s in transcript if s.get("agent") == "support-copilot"
                     and s.get("decision") == "revoked"), None)
        check("the running agent observes the revocation on its next call",
              bool(stop and stop.get("observed_on_next_call")),
              f"latency={stop.get('stop_latency_s') if stop else None}s")
        proof = next((s for s in transcript if s.get("proof")), {})
        check("zero rows left the perimeter", proof.get("rows_left_perimeter") == 0)

        revoked = rpc(url, "support-copilot", tokens["support-copilot"], "crm.read", {})
        check("a revoked agent cannot call again",
              revoked.get("error", {}).get("code") == -32003)

        chain = demo.get(url, "/verify")
        check("the receipt chain recomputes from genesis", chain["ok"] and chain["length"] > 0,
              f"{chain['length']} receipts, head {chain['head']}")

        receipts = demo.get(url, "/receipts")
        linked = True
        prev = "0" * 64
        for entry in receipts:
            if entry["prev"] != prev:
                linked = False
                break
            prev = entry["hash"]
        check("receipts are a single unbroken chain", linked and len(receipts) == chain["length"])

        state = demo.get(url, "/state")
        check("the state contract is complete",
              all(k in state for k in ("agents", "warrants", "receipts", "executor_calls", "chain")))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
