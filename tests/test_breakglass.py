"""Break-glass: the one thing that may lower a *policy* pause - and the things it may not.

These tests are the contract. Read them as the answer to "what stops this from being a hole":

* a pause a *rule* asked for can be opened by a named person, for a bounded window, once;
* the *class* floor is not reachable - a grant for an irreversible act is refused with the
  sentence that says why, and a hand-inserted one is ignored by the gate;
* the window is a hard cap, the clock is the expiry, and the grant is signed: widening the
  tool it covers invalidates it;
* a spent grant leaves a debt - no second grant for that agent before a review is written;
* the grant, its use and the review all land in the same hash chain as the refusals.
"""
from __future__ import annotations

import pytest

from warrnt.breakglass import MAX_TTL_S, BreakGlassRefused
from warrnt.models import AgentState, Decision, Rule, WarrantSpec
from warrnt.proxy import MCPProxy
from warrnt.registry import AppendOnlyRegistry
from warrnt.warrants import WarrantIssuer


@pytest.fixture
def clock():
    """A hand-turned clock: the window is a thing to test, not a thing to wait for."""
    # Start from the wall clock: the node's own TTL check reads real time, so a made-up
    # baseline would make every seeded order look expired for reasons unrelated to the test.
    state = {"t": __import__("time").time()}
    return state, (lambda: state["t"])


@pytest.fixture
def proxy(tmp_path, clock):
    _state, now = clock
    p = MCPProxy(WarrantIssuer(key=b"break-glass-test-key", now=now),
                 AppendOnlyRegistry(str(tmp_path / "chain.jsonl")), now=now)
    p.issue_all()
    # A fourth agent, added by the test alone: mass export is a *policy* pause (the class
    # itself, read_personal, would let the node decide). This is the case break-glass is for.
    spec = WarrantSpec(id="W-9001", agent="report-bot", role="Analytics",
                       scope="crm.bulk_export ⇒ require-human", ttl=900.0,
                       rules=[Rule(tool="crm.bulk_export", effect="human",
                                   reason="a mass export is a person's decision")])
    w = p.issuer.issue(spec)
    p.warrants[w.id] = w
    p.agents[w.agent] = AgentState(id=w.agent, role=w.role, warrant=w.id,
                                   token=p.issuer.token_for(w.agent, w.id))
    return p


def ask(proxy, agent, tool, args=None):
    """The node's own entry point, without HTTP."""
    return proxy.intercept(agent, proxy.agents[agent].token, tool, args or {})


def hcall(client, tokens, agent, tool, args=None):
    """The same call over /mcp, the way a juror or an agent would reach it."""
    return client.post("/mcp",
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": tool, "arguments": args or {}}},
                       headers={"X-WARRNT-Agent": agent,
                                "X-WARRNT-Token": tokens.get(agent, "")})


# --------------------------------------------------------------- the pause itself
def test_a_policy_pause_without_a_grant_stays_a_pause(proxy):
    decision, reason, _d, _r, executed = ask(proxy, "report-bot", "crm.bulk_export",
                                              {"table": "customers"})
    assert decision is Decision.human
    assert executed is False
    assert "mass export" in reason


def test_a_named_grant_opens_the_pause_exactly_once(proxy):
    grant = proxy.breakglass.grant(human="Anna Kowalska", agent="report-bot",
                                   tool="crm.bulk_export", reason="board deck, 20 min",
                                   cls="read_personal", ttl_s=900)

    decision, reason, detail, receipt, executed = ask(proxy, "report-bot", "crm.bulk_export",
                                                      {"table": "customers"})
    assert decision is Decision.allow and executed is True
    assert detail["break_glass"] == grant.id and detail["break_glass_by"] == "Anna Kowalska"
    assert grant.id in reason and "single use" in reason
    assert grant.id in receipt["reason"], "the chain carries who opened the door"

    # spent: the same call now waits for a person again
    decision2, _r2, _d2, _rec2, executed2 = ask(proxy, "report-bot", "crm.bulk_export",
                                                {"table": "customers"})
    assert decision2 is Decision.human and executed2 is False
    assert proxy.breakglass.grants[grant.id].state == "used"


# ------------------------------------------------------------- the line that holds
def test_the_irreversible_floor_is_not_liftable(proxy):
    with pytest.raises(BreakGlassRefused, match="taxonomy's own floor"):
        proxy.breakglass.grant(human="Anna Kowalska", agent="deploy-agent",
                               tool="infra.deploy", reason="prod is down", cls="irreversible")

    # and a grant pushed in by hand, as if the validation had been bypassed, is ignored
    from warrnt.models import BreakGlassGrant
    forged = BreakGlassGrant(id="BG-bad", human="Anna", agent="deploy-agent",
                             tool="infra.deploy", reason="bypass", cls="irreversible",
                             issued=__import__("time").time(),
                             expires=__import__("time").time() + 900, sig="")
    forged.sig = proxy.issuer.sign(forged.payload())
    proxy.breakglass.grants["BG-bad"] = forged

    decision, _reason, _d, _r, executed = ask(proxy, "deploy-agent", "infra.deploy", {})
    assert decision is Decision.human and executed is False


def test_the_rules_may_not_be_rewritten_by_a_grant(proxy):
    with pytest.raises(BreakGlassRefused, match="taxonomy's own floor"):
        proxy.breakglass.grant(human="Anna", agent="fin-reconcile", tool="warrant.issue",
                               reason="just this once", cls="authorize")


def test_a_revoked_order_is_not_reopened_by_a_grant(proxy):
    grant = proxy.breakglass.grant(human="Anna Kowalska", agent="report-bot",
                                   tool="crm.bulk_export", reason="board deck",
                                   cls="read_personal", ttl_s=300)
    proxy.revoke("report-bot")
    decision, _reason, _d, _r, executed = ask(proxy, "report-bot", "crm.bulk_export", {})
    assert decision is Decision.revoked and executed is False
    assert proxy.breakglass.grants[grant.id].state == "active", \
        "the grant did not spend itself on a call it never lifted"


# ------------------------------------------------------------------- the rule of form
def test_no_anonymous_switch(proxy):
    with pytest.raises(BreakGlassRefused, match="names the person"):
        proxy.breakglass.grant(human="  ", agent="report-bot", tool="crm.bulk_export",
                               reason="urgency", cls="read_personal")


def test_a_grant_must_carry_its_reason(proxy):
    with pytest.raises(BreakGlassRefused, match="carries its reason"):
        proxy.breakglass.grant(human="Anna", agent="report-bot", tool="crm.bulk_export",
                               reason="", cls="read_personal")


def test_the_window_is_capped(proxy):
    with pytest.raises(BreakGlassRefused, match=str(int(MAX_TTL_S))):
        proxy.breakglass.grant(human="Anna", agent="report-bot", tool="crm.bulk_export",
                               reason="all day", cls="read_personal", ttl_s=86_400)


def test_the_clock_is_the_expiry(proxy, clock):
    state, _now = clock
    grant = proxy.breakglass.grant(human="Anna", agent="report-bot", tool="crm.bulk_export",
                                   reason="board deck", cls="read_personal", ttl_s=900)
    state["t"] += 901
    decision, _reason, _d, _r, executed = ask(proxy, "report-bot", "crm.bulk_export", {})
    assert decision is Decision.human and executed is False
    assert proxy.breakglass.effective_state(grant) == "expired"


def test_a_widened_grant_fails_its_signature(proxy):
    grant = proxy.breakglass.grant(human="Anna", agent="report-bot", tool="crm.bulk_export",
                                   reason="board deck", cls="read_personal", ttl_s=900)
    grant.tool = "payments.transfer"          # edit the artifact after signing
    assert proxy.breakglass.active("report-bot", "payments.transfer",
                                   "irreversible") is None
    decision, _reason, _d, _r, executed = ask(proxy, "report-bot", "crm.bulk_export", {})
    assert decision is Decision.human and executed is False


# ------------------------------------------------------------------------ the debt
def test_a_used_grant_owes_a_review_before_the_next_one(proxy):
    first = proxy.breakglass.grant(human="Anna", agent="report-bot", tool="crm.bulk_export",
                                   reason="board deck", cls="read_personal", ttl_s=900)
    ask(proxy, "report-bot", "crm.bulk_export", {})
    assert [g.id for g in proxy.breakglass.pending_postmortem()] == [first.id]

    with pytest.raises(BreakGlassRefused, match="owes a post-mortem"):
        proxy.breakglass.grant(human="Piotr", agent="report-bot", tool="crm.bulk_export",
                               reason="second export", cls="read_personal", ttl_s=900)

    with pytest.raises(BreakGlassRefused, match="says something"):
        proxy.breakglass.postmortem(first.id, "   ")

    proxy.breakglass.postmortem(first.id, "deck needed 12 rows, no personal fields exported")
    second = proxy.breakglass.grant(human="Piotr", agent="report-bot", tool="crm.bulk_export",
                                    reason="second export", cls="read_personal", ttl_s=900)
    assert second.id != first.id


def test_the_grant_the_use_and_the_review_are_one_chain(proxy):
    grant = proxy.breakglass.grant(human="Anna", agent="report-bot", tool="crm.bulk_export",
                                   reason="board deck", cls="read_personal", ttl_s=900)
    ask(proxy, "report-bot", "crm.bulk_export", {})
    proxy.breakglass.postmortem(grant.id, "reviewed: 12 rows, nothing personal left the node")

    assert proxy.registry.verify()["ok"] is True
    tools = [e["tool"] for e in proxy.registry.entries]
    assert tools.count("/break-glass") == 2, "the grant and the review are receipts"
    used = [e for e in proxy.registry.entries if e.get("grant") == grant.id]
    assert {e["reason"][:8] for e in used} == {"break-gl", "post-mor"}, used
    executed = [e for e in proxy.registry.entries if e["tool"] == "crm.bulk_export"]
    assert executed and grant.id in executed[-1]["reason"]


def test_state_shows_the_grants_and_the_debt(proxy):
    grant = proxy.breakglass.grant(human="Anna", agent="report-bot", tool="crm.bulk_export",
                                   reason="board deck", cls="read_personal", ttl_s=900)
    ask(proxy, "report-bot", "crm.bulk_export", {})
    snap = proxy.state()["breakglass"]
    assert snap["max_ttl_s"] == int(MAX_TTL_S)
    assert snap["unliftable"] == ["irreversible", "authorize"]
    assert snap["postmortem_required"] == [grant.id]
    row = snap["grants"][0]
    assert row["state"] == "used" and row["human"] == "Anna" and row["sig_ok"] is True


# ------------------------------------------------------------ through the HTTP surface
def test_the_operator_cannot_grant_what_the_taxonomy_forbids(client, tokens):
    r = client.post("/api/breakglass", json={"human": "Anna Kowalska", "agent": "deploy-agent",
                                             "tool": "infra.deploy", "reason": "prod is down"})
    assert r.status_code == 409
    assert "taxonomy" in r.json()["error"] and r.json()["class"] == "irreversible"


def test_a_tool_with_no_class_cannot_be_granted_either(client):
    r = client.post("/api/breakglass", json={"human": "Anna", "agent": "report-bot",
                                            "tool": "crm.mystery", "reason": "urgent"})
    assert r.status_code == 409 and "no action class" in r.json()["error"]


def test_break_glass_end_to_end_over_http(client, tokens):
    granted = client.post("/api/breakglass",
                          json={"human": "Anna Kowalska", "agent": "report-bot",
                                "tool": "crm.bulk_export", "reason": "board deck, 20 minutes",
                                "ttl_s": 900})
    assert granted.status_code == 200, granted.text
    gid = granted.json()["id"]
    assert granted.json()["single_use"] is True
    assert 0 < granted.json()["expires_in_s"] <= 900

    # the pause is open: the call runs, and the receipt names the person who opened it
    first = hcall(client, tokens, "report-bot", "crm.bulk_export", {"table": "customers"})
    assert first.status_code == 200, first.text
    body = first.json()["result"]
    assert body["decision"] == "allow" and body["executed"] is True
    reason = first.json()["result"]["reason"]
    assert gid in reason and "Anna Kowalska" in reason

    # spent: the next call waits for a person again, with the RPC code for human
    second = hcall(client, tokens, "report-bot", "crm.bulk_export", {"table": "customers"})
    assert second.status_code == 200 and "error" in second.json()
    assert second.json()["error"]["code"] == -32002

    listing = client.get("/api/breakglass").json()
    assert listing["postmortem_required"] == [gid]
    row = [g for g in listing["grants"] if g["id"] == gid][0]
    assert row["state"] == "used" and row["human"] == "Anna Kowalska" and row["sig_ok"] is True


def test_a_grant_can_be_closed_early_and_then_lifts_nothing(client, tokens):
    gid = client.post("/api/breakglass",
                      json={"human": "Piotr Nowak", "agent": "report-bot",
                            "tool": "crm.bulk_export", "reason": "shift handover"}).json()["id"]
    assert client.post("/api/breakglass/revoke", json={"id": gid}).json()["state"] == "revoked"
    r = hcall(client, tokens, "report-bot", "crm.bulk_export", {"table": "customers"})
    assert r.json()["error"]["code"] == -32002


def test_the_review_has_to_be_written_before_the_next_grant(client, tokens):
    gid = client.post("/api/breakglass",
                      json={"human": "Anna", "agent": "report-bot", "tool": "crm.bulk_export",
                            "reason": "deck"}).json()["id"]
    hcall(client, tokens, "report-bot", "crm.bulk_export", {"table": "customers"})

    again = client.post("/api/breakglass",
                        json={"human": "Piotr", "agent": "report-bot", "tool": "crm.bulk_export",
                              "reason": "another deck"})
    assert again.status_code == 409 and "owes a post-mortem" in again.json()["error"]

    empty = client.post("/api/breakglass/postmortem", json={"id": gid, "note": "  "})
    assert empty.status_code == 409

    reviewed = client.post("/api/breakglass/postmortem",
                           json={"id": gid, "note": "deck needed 12 rows; nothing personal exported"})
    assert reviewed.status_code == 200 and reviewed.json()["note"].startswith("deck needed")

    allowed = client.post("/api/breakglass",
                          json={"human": "Piotr", "agent": "report-bot",
                                "tool": "crm.bulk_export", "reason": "another deck"})
    assert allowed.status_code == 200 and allowed.json()["id"] != gid


def test_the_chain_still_verifies_with_grants_in_it(client, tokens):
    gid = client.post("/api/breakglass",
                      json={"human": "Anna", "agent": "report-bot", "tool": "crm.bulk_export",
                            "reason": "deck"}).json()["id"]
    hcall(client, tokens, "report-bot", "crm.bulk_export", {"table": "customers"})
    client.post("/api/breakglass/postmortem", json={"id": gid, "note": "reviewed, nothing left"})
    chain = client.get("/verify").json()
    assert chain["ok"] is True
    ledger = [e for e in client.get("/receipts").json() if e.get("grant") == gid]
    assert len(ledger) == 2, "the grant and the review are on the same chain"
