#!/usr/bin/env python3
"""Adversarial security-boundary suite for the WARRNT node (task D2).

The track theme is CONTROL: it carries ~30% of the idea score. This script attacks the
three control pillars the pitch promises, on a real uvicorn process with real HTTP:

  1. JOURNAL   (журнал дзеянняў) - every decision is in the append-only, hash-chained
                 registry, with provenance; edit or delete a byte on disk and the chain
                 refuses to verify.
  2. PERMISSIONS (дазволы)        - identity-bound tokens, warrant scope, fail-closed
                 guards, exact numeric boundaries.
  3. KILL-SWITCH (кіл-світч)      - revoke by warrant id halts exactly one agent, is
                 idempotent, and leaves the rest of the fleet running.

    python3 scripts/security_boundaries.py            # starts its own node on a free port

Exit code 0 iff every check passed. Prints one PASS/FAIL line per check.
"""
from __future__ import annotations

import hashlib
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

os.environ.setdefault("WARRNT_ADMIN_TOKEN", "operator-token")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warrnt.anchor import HeadAnchor  # noqa: E402
from warrnt.canonical import canon  # noqa: E402
from warrnt.registry import AppendOnlyRegistry  # noqa: E402
from warrnt.warrants import WarrantIssuer  # noqa: E402

CHECKS: list[tuple[str, bool, str]] = []


def check(tag: str, name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((f"{tag} {name}", bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  [{tag}] {name}" + (f"  [{detail}]" if detail else ""),
          flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_health(url: str, timeout: float = 25.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return get(url, "/health")
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"node never became healthy: {last}")


def get(url: str, path: str) -> dict:
    with urllib.request.urlopen(url.rstrip("/") + path, timeout=5) as resp:
        return json.loads(resp.read().decode())


def post(url: str, path: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url.rstrip("/") + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                      "X-WARRNT-Admin": os.environ.get("WARRNT_ADMIN_TOKEN", "")})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def rpc(url: str, agent: str, token: str, tool: str, args: dict, timeout: float = 5.0) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/mcp", data=body,
                                 headers={"Content-Type": "application/json",
                                          "X-WARRNT-Agent": agent, "X-WARRNT-Token": token or ""})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read().decode())


def decision_of(reply: dict) -> str | None:
    if "result" in reply:
        return reply["result"].get("decision")
    return (reply.get("error", {}).get("data") or {}).get("decision")


def code_of(reply: dict) -> int | None:
    return (reply.get("error") or {}).get("code")


def tokens(url: str) -> dict[str, str]:
    return {a["id"]: a.get("token", "") for a in get(url, "/agents")}


# --------------------------------------------------------------------------- journal
def journal_checks(url: str, home: Path) -> None:
    post(url, "/reset", {})
    tok = tokens(url)
    base = get(url, "/verify")["length"]

    allow = rpc(url, "support-copilot", tok["support-copilot"], "crm.read",
                {"table": "tickets", "limit": 5})
    deny = rpc(url, "support-copilot", tok["support-copilot"], "crm.bulk_export",
               {"table": "customers", "fields": ["email", "pesel"], "rows": 999})
    human = rpc(url, "deploy-agent", tok["deploy-agent"], "infra.deploy", {"env": "prod"})

    receipts = get(url, "/receipts")
    after = get(url, "/verify")

    check("J1", "an allow, a deny and a human stop are all journaled",
          decision_of(allow) == "allow" and decision_of(deny) == "deny"
          and decision_of(human) == "human" and after["length"] == base + 4,
          f"{base} -> {after['length']} receipts (allow=2, deny=1, human=1)")

    check("J2", "the chain verifies after mixed decisions", after["ok"] is True)

    denied_rows = [r for r in receipts
                   if r.get("decision") == "deny" and r.get("tool") == "crm.bulk_export"]
    check("J3", "a denial is journaled with provenance (who, what, why)",
          bool(denied_rows) and denied_rows[0].get("agent") == "support-copilot"
          and "no PII fields" in (denied_rows[0].get("reason") or ""),
          f"agent={denied_rows[0].get('agent') if denied_rows else None}")

    exec_rows = [r for r in receipts if r.get("exec_hash")]
    linked = bool(exec_rows) and any(
        e["exec_hash"] == r["hash"] for e in exec_rows
        for r in receipts if r.get("decision") == "allow" and not r.get("exec_hash"))
    check("J4", "an approval is journaled twice and the execution links to its decision",
          linked, f"{len(exec_rows)} execution receipt(s) carry exec_hash")

    # --- disk-level immutability: reload the real file after editing / deleting a byte
    live = home / "receipts.jsonl"
    check("J5", "the registry has a durable on-disk journal", live.exists()
          and len(live.read_text(encoding="utf-8").splitlines()) == after["length"],
          f"{live}")

    edited = home / "tamper-edited.jsonl"
    lines = live.read_text(encoding="utf-8").splitlines()
    victim = max(1, len(lines) // 2)
    bad = list(lines)
    row = json.loads(bad[victim])
    row["reason"] = (row.get("reason") or "") + " (widened after the fact)"
    bad[victim] = json.dumps(row, sort_keys=True)
    edited.write_text("\n".join(bad) + "\n", encoding="utf-8")
    v = AppendOnlyRegistry(str(edited)).verify()
    check("J6", "editing a past receipt breaks the chain at that index",
          v["ok"] is False and v.get("broken_at") == victim, f"broken_at={v.get('broken_at')}")

    deleted = home / "tamper-deleted.jsonl"
    deleted.write_text("\n".join(lines[:victim] + lines[victim + 1:]) + "\n", encoding="utf-8")
    v2 = AppendOnlyRegistry(str(deleted)).verify()
    check("J7", "deleting a past receipt is detected", v2["ok"] is False,
          f"broken_at={v2.get('broken_at')}")

    copy = home / "tamper-copy.jsonl"
    shutil.copyfile(live, copy)
    check("J8", "an untouched copy still verifies (the check is not always-red)",
          AppendOnlyRegistry(str(copy)).verify()["ok"] is True)


# ----------------------------------------------------------------------- permissions
def permission_checks(url: str) -> None:
    post(url, "/reset", {})
    tok = tokens(url)

    swap = rpc(url, "fin-reconcile", tok["support-copilot"], "payments.read",
               {"account": "PL61", "limit": 10})
    check("P1", "another agent's token does not authorise this identity",
          decision_of(swap) == "deny" and code_of(swap) == -32001,
          f"reason={((swap.get('error') or {}).get('message'))!r}")

    off_scope = rpc(url, "support-copilot", tok["support-copilot"], "payments.read",
                    {"account": "PL61", "limit": 10})
    check("P2", "a tool outside the warrant scope is denied", decision_of(off_scope) == "deny"
          and "not covered by warrant scope" in ((off_scope.get("error") or {}).get("message") or ""))

    missing = rpc(url, "fin-reconcile", tok["fin-reconcile"], "payments.transfer", {})
    check("P3", "a guarded call with the amount missing fails closed",
          decision_of(missing) == "deny")

    edge_allow = rpc(url, "fin-reconcile", tok["fin-reconcile"], "payments.transfer",
                     {"amount_pln": 50000})
    edge_deny = rpc(url, "fin-reconcile", tok["fin-reconcile"], "payments.transfer",
                    {"amount_pln": 50001})
    # The guard is the boundary; the class is the floor. Exactly at the limit the guard
    # holds - and the act is still irreversible, so the machine will not decide it alone:
    # the answer is require-human (-32002), not allow. One zloty over, the guard denies.
    check("P4", "the limit is exact: in-limit clears the guard and stops at require-human",
          decision_of(edge_allow) == "human" and code_of(edge_allow) == -32002
          and decision_of(edge_deny) == "deny" and code_of(edge_deny) == -32001,
          "50000 require-human / 50001 deny")

    anon = rpc(url, "support-copilot", "", "crm.read", {})
    check("P5", "no token means no identity and no call", decision_of(anon) == "deny"
          and code_of(anon) == -32001)

    forged_agent = rpc(url, "ghost-agent", "deadbeef", "crm.read", {})
    check("P6", "an unknown agent is denied", decision_of(forged_agent) == "deny")

    # a denied call must not move the upstream counter
    before = get(url, "/state")["executor_calls"].get("payments.transfer", 0)
    rpc(url, "fin-reconcile", tok["fin-reconcile"], "payments.transfer", {"amount_pln": 999999})
    after = get(url, "/state")["executor_calls"].get("payments.transfer", 0)
    check("P7", "a denied call never reaches the upstream", before == after,
          f"executor payments.transfer {before}->{after}")


# ------------------------------------------------------------------ anchor (fix M1)
def anchor_checks(url: str, home: Path) -> None:
    """The head anchor seals the chain: a consistent rewrite can no longer pass silently."""
    post(url, "/reset", {})
    tok = tokens(url)
    rpc(url, "support-copilot", tok["support-copilot"], "crm.read", {"table": "tickets", "limit": 5})
    rpc(url, "support-copilot", tok["support-copilot"], "crm.bulk_export",
        {"table": "customers", "fields": ["email"], "rows": 5})

    view = get(url, "/anchor")
    check("A1", "the node seals a signed anchor on every decision",
          view["anchors"] >= 3 and view["verdict"]["ok"] is True,
          f"{view['anchors']} seals, head={view['last']['head'][:16]}")

    check("A2", "the signed anchor matches the live registry head",
          view["last"]["head"][:16] == get(url, "/verify")["head"])

    # Rebuild a *consistent* rewrite of the real receipts (the M1 attack) and show the
    # signed anchor no longer matches it - while the genuine anchor still verifies.
    live = home / "receipts.jsonl"
    reg = AppendOnlyRegistry(str(live))
    prev = AppendOnlyRegistry.GENESIS
    forged = []
    for entry in reg.entries:
        body = {k: v for k, v in entry.items() if k != "hash"}
        if body.get("decision") == "deny":
            body["decision"] = "allow"
            body["reason"] = "within warrant scope"
        body["prev"] = prev
        body["hash"] = hashlib.sha256((prev + canon(body)).encode()).hexdigest()
        prev = body["hash"]
        forged.append(body)

    issuer = WarrantIssuer.from_env_or_file(str(home / "issuer.key"))
    anchor = HeadAnchor(str(home / "anchors.jsonl"), issuer.sign)
    verdict = anchor.verify(forged[-1]["hash"], len(forged))
    check("A3", "a consistent rewrite of the log is caught by the anchor",
          verdict["ok"] is False and verdict["signed"] is True,
          f"{verdict.get('reason')}")
    check("A4", "the honest head still verifies against the same anchor",
          anchor.verify(reg.entries[-1]["hash"], len(reg.entries))["ok"] is True)
    honest = anchor.verify(reg.entries[-1]["hash"], len(reg.entries))
    # An attacker who edits the anchor record to cover the rewrite still cannot sign it.
    doctored = HeadAnchor(str(home / "anchors.jsonl"), issuer.sign)
    doctored.records[-1]["head"] = forged[-1]["hash"]
    forged_verdict = doctored.verify(forged[-1]["hash"], len(forged))
    check("A5", "an anchor edited to hide a rewrite fails its signature check",
          honest["signed"] is True and forged_verdict["ok"] is False
          and forged_verdict["signed"] is False,
          "signature invalid -> forger needs the issuer key")


# ------------------------------------------------------------------------ kill switch
def kill_switch_checks(url: str) -> None:
    post(url, "/reset", {})
    tok = tokens(url)

    st, body = post(url, "/revoke", {"warrant": "W-4419"})           # support-copilot's order
    check("K1", "revoke by warrant id halts exactly that agent",
          st == 200 and body.get("agent") == "support-copilot" and body.get("state") == "halted",
          f"http={st} agent={body.get('agent')}")

    dead = rpc(url, "support-copilot", tok["support-copilot"], "crm.read", {"table": "tickets"})
    check("K2", "the halted agent cannot call again", code_of(dead) == -32003,
          f"code={code_of(dead)}")

    alive = rpc(url, "fin-reconcile", tok["fin-reconcile"], "payments.read", {"account": "PL61"})
    check("K3", "the rest of the fleet keeps working (blast radius = one warrant)",
          decision_of(alive) == "allow")

    st2, body2 = post(url, "/revoke", {"agent": "support-copilot"})
    check("K4", "revoking again is a clean 409, not a crash", st2 == 409,
          f"http={st2} {body2.get('error')}")

    st3, _ = post(url, "/revoke", {"agent": "nobody-here"})
    check("K5", "revoking an unknown agent is rejected without side effects", st3 == 409)

    warr = {w["id"]: w for w in get(url, "/warrants")}
    check("K6", "the pulled order shows state=revoked in the registry",
          warr["W-4419"]["state"] == "revoked"
          and warr["W-4417"]["state"] != "revoked",
          f"W-4419={warr['W-4419']['state']} W-4417={warr['W-4417']['state']}")

    # kill latency on a live loop: measure how fast the running agent notices
    post(url, "/reset", {})
    tok = tokens(url)
    observed: dict[str, float] = {}

    def loop() -> None:
        while time.time() < deadline_at[0]:
            r = rpc(url, "support-copilot", tok["support-copilot"], "crm.read", {"table": "tickets"})
            if decision_of(r) == "revoked":
                observed["t"] = time.time()
                return
            time.sleep(0.05)

    import threading
    deadline_at = [time.time() + 4.0]
    th = threading.Thread(target=loop, daemon=True)
    th.start()
    time.sleep(0.3)
    t0 = time.time()
    post(url, "/revoke", {"agent": "support-copilot"})
    th.join(3.0)
    latency = round(observed["t"] - t0, 3) if observed else None
    check("K7", "a running agent observes the kill on its next call, measured live",
          observed.get("t") is not None and latency is not None and latency < 1.0,
          f"latency={latency}s")

    check("K8", "the journal survives a kill and still verifies",
          get(url, "/verify")["ok"] is True)


def main() -> int:
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    home = ROOT / "state" / "sec-d2"
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "WARRNT_DEV": "1", "WARRNT_HOME": str(home),
           "WARRNT_PORT": str(port)}
    env.pop("WARRNT_UPSTREAM", None)
    log = open(home / "server.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "warrnt", "serve", "--port", str(port)],
                            cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        h = wait_health(url)
        check("S0", "node up, chain verifies from genesis", h["ok"] and h["chain"]["ok"])
        journal_checks(url, home)
        permission_checks(url)
        kill_switch_checks(url)
        anchor_checks(url, home)     # last, so the demo state keeps a 'deny' to forgive
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} security-boundary checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
