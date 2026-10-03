"""P0 findings from the adversary walk (docs/roast-journey-redteam-2026-10-03.md).

Each test pins one promise the node made and could not keep on 2026-10-03:

V1  an anonymous control plane: /reset, /revoke, /api/breakglass answered anyone
V2  a reset erased the chain and /verify stayed green (anchor signed GENESIS)
V3  the decision receipt carried the request's raw values, so the control layer
    became the PII store it was supposed to keep out of the machine

A test here is a promise that has to hold; delete one and the finding comes back.
"""
from __future__ import annotations

import json
import pathlib

import pytest
from fastapi.testclient import TestClient

PII_MAIL = "jan.kowalski@example.com"
PII_PESEL = "44051401359"


def call(client, tokens, agent, tool, args):
    return client.post("/mcp",
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": tool, "arguments": args}},
                       headers={"X-WARRNT-Agent": agent,
                                "X-WARRNT-Token": tokens.get(agent, "")})


@pytest.fixture
def proxy_factory(tmp_path):
    """A node built by hand (no HTTP), for the concurrency and failure paths."""
    import time

    from warrnt.models import AgentState, Rule, WarrantSpec
    from warrnt.proxy import MCPProxy
    from warrnt.registry import AppendOnlyRegistry
    from warrnt.warrants import WarrantIssuer

    made = {"n": 0}

    def build():
        made["n"] += 1
        now = time.time
        p = MCPProxy(WarrantIssuer(key=b"redteam-p0-key", now=now),
                     AppendOnlyRegistry(str(tmp_path / f"chain{made['n']}.jsonl")), now=now)
        p.issue_all()
        spec = WarrantSpec(id="W-9001", agent="report-bot", role="Analytics",
                           scope="crm.bulk_export ⇒ require-human", ttl=900.0,
                           rules=[Rule(tool="crm.bulk_export", effect="human",
                                       reason="a mass export is a person\'s decision")])
        w = p.issuer.issue(spec)
        p.warrants[w.id] = w
        p.agents[w.agent] = AgentState(id=w.agent, role=w.role, warrant=w.id,
                                       token=p.issuer.token_for(w.agent, w.id))
        return p

    return build


@pytest.fixture
def anon(app):
    """A client that holds no operator token - i.e. the attacker's view of the node."""
    with TestClient(app) as c:
        yield c


# ------------------------------------------------------------------ V1: no auth
def test_control_plane_refuses_anonymous_mutations(anon):
    """Every mutating route answers 401 without the operator token (finding V1)."""
    assert anon.post("/reset", json={"reason": "wipe", "actor": "attacker"}).status_code == 401
    assert anon.post("/revoke", json={"agent": "fin-reconcile"}).status_code == 401
    grant = anon.post("/api/breakglass", json={
        "human": "attacker", "agent": "report-bot", "tool": "crm.bulk_export",
        "reason": "x"}).status_code
    assert grant == 401
    assert anon.post("/api/breakglass/revoke", json={"id": "BG-0001"}).status_code == 401
    assert anon.post("/api/breakglass/postmortem",
                     json={"id": "BG-0001", "note": "nothing"}).status_code == 401


def test_anonymous_breakglass_leaves_no_grant(anon):
    """A 401 is not just a code: the pause must not have been opened (finding V1)."""
    anon.post("/api/breakglass", json={"human": "attacker", "agent": "report-bot",
                                       "tool": "crm.bulk_export", "reason": "x"})
    assert anon.get("/api/breakglass").json()["grants"] == []


def test_the_token_is_what_opens_the_door(client, tokens):
    """The same call with the token works - the route is guarded, not broken."""
    r = client.post("/api/breakglass", json={"human": "Anna Kowalska", "agent": "report-bot",
                                             "tool": "crm.bulk_export", "reason": "audit"})
    assert r.status_code == 200 and r.json()["human"] == "Anna Kowalska"


# ------------------------------------------------- V2: reset must not erase history
def test_reset_rotates_the_chain_instead_of_erasing_it(client, tokens, settings):
    """After a reset the closed segment survives, is counted, and is named (finding V2)."""
    call(client, tokens, "fin-reconcile", "payments.read", {"table": "payments", "limit": 1})
    before = client.get("/verify").json()
    assert before["ok"] is True and before["length"] >= 1

    body = client.post("/reset", json={"reason": "demo rerun", "actor": "operator"}).json()
    rotation = body["rotated"]
    assert rotation and rotation["closed_length"] >= 1
    assert pathlib.Path(settings.home, rotation["archive"]).exists()

    after = client.get("/verify").json()
    assert after["length"] == 0                      # a fresh chain...
    assert after["history"]["rotations"] == 1        # ...but not a forgotten one
    assert after["history"]["archived_rows"] >= 1
    assert after["history"]["archives_ok"] is True
    assert after["history"]["last_closed_head"] == rotation["closed_head"][:16]


def test_deleting_the_archive_turns_the_verdict_red(client, tokens, settings):
    """Erasure is detected, not rewarded: no archive -> verify ok=False (finding V2)."""
    call(client, tokens, "fin-reconcile", "payments.read", {"table": "payments", "limit": 1})
    rotation = client.post("/reset", json={"reason": "rerun"}).json()["rotated"]
    pathlib.Path(settings.home, rotation["archive"]).unlink()

    verdict = client.get("/verify").json()
    assert verdict["ok"] is False
    assert verdict["history"]["archives_ok"] is False
    assert verdict["history"]["problems"]


def test_anchor_verdict_is_not_green_when_history_is_gone(client, tokens, settings):
    """The anchor speaks for the live head; it must not vouch for a mangled history."""
    call(client, tokens, "fin-reconcile", "payments.read", {"table": "payments", "limit": 1})
    rotation = client.post("/reset", json={"reason": "rerun"}).json()["rotated"]
    pathlib.Path(settings.home, rotation["archive"]).unlink()
    verdict = client.get("/anchor").json()["verdict"]
    assert verdict["ok"] is False and verdict["history_ok"] is False


# ------------------------------------------------- V3: values never enter the chain
def test_a_receipt_never_carries_the_request_values(client, tokens):
    """A redacted read still runs; the chain keeps keys and a digest, not values (V3)."""
    reply = call(client, tokens, "support-copilot", "crm.read",
                 {"table": "tickets", "fields": ["subject", "email"], "limit": 5,
                  "email_value": PII_MAIL, "pesel_value": PII_PESEL})
    assert reply.json()["result"]["decision"] == "redact"

    dump = json.dumps(client.get("/receipts").json(), ensure_ascii=False)
    assert PII_MAIL not in dump and PII_PESEL not in dump
    rows = client.get("/receipts").json()
    assert any(r.get("params_sha256") for r in rows)
    assert any(r.get("param_keys") for r in rows)


def test_an_unknown_agent_receipt_also_drops_the_values(client):
    """The deny path is the loudest place to leak: it must not either (finding V3)."""
    client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "crm.read",
                                         "arguments": {"email_value": PII_MAIL}}},
                headers={"X-WARRNT-Agent": "ghost", "X-WARRNT-Token": "nope"})
    dump = json.dumps(client.get("/receipts").json(), ensure_ascii=False)
    assert PII_MAIL not in dump


# ------------------------------------------------- V5: one grant, one execution
def test_a_single_grant_cannot_be_spent_twice_under_concurrency(proxy_factory):
    """Ten callers, one grant: exactly one executes (finding V5)."""
    import concurrent.futures as cf

    proxy = proxy_factory()
    grant = proxy.breakglass.grant(human="Anna Kowalska", agent="report-bot",
                                   tool="crm.bulk_export", reason="board deck",
                                   cls="read_personal", ttl_s=900)

    def one(_i):
        d, _reason, _detail, _receipt, executed = proxy.intercept(
            "report-bot", proxy.agents["report-bot"].token, "crm.bulk_export",
            {"table": "customers"})
        return d.value, executed

    with cf.ThreadPoolExecutor(max_workers=10) as pool:
        outcomes = list(pool.map(one, range(10)))

    executed = [o for o in outcomes if o[1]]
    assert len(executed) == 1, outcomes
    assert executed[0][0] == "allow"
    assert proxy.breakglass.grants[grant.id].state == "used"
    refusals = [o for o in outcomes if not o[1]]
    assert len(refusals) == 9
    # the loser is refused, and the refusal is on the chain like any other decision
    executed_rows = [e for e in proxy.registry.entries
                     if e.get("outcome") in {"ok", "error"} and e["tool"] == "crm.bulk_export"]
    assert len(executed_rows) == 1, executed_rows
    assert all(e["reason"] for e in proxy.registry.entries)
    assert proxy.registry.verify()["ok"] is True


# ------------------------------------------------- V6: a failed act is still a record
def test_an_upstream_failure_after_the_decision_still_lands_on_the_chain(proxy_factory):
    """An error is not an excuse to go quiet (finding V6)."""
    proxy = proxy_factory()

    class Boom:
        def call(self, tool, args):
            raise RuntimeError("upstream refused the connection")

    proxy.upstream = Boom()
    decision, _reason, detail, receipt, executed = proxy.intercept(
        "support-copilot", proxy.agents["support-copilot"].token, "crm.read", {"table": "tickets"})

    assert decision.value == "allow" and executed is True
    assert "upstream_error" in detail
    assert receipt["outcome"] == "error"
    assert proxy.registry.verify()["ok"] is True
