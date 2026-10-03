"""PR-14 - the human hold: a real pause, a real decision, a real receipt.

The brief asks for one provable path: action -> control plane -> WARRNT -> decision ->
execution or refusal -> receipt, with the same ``action_id`` visible at every level. These
tests pin the parts a juror can check with a counter, not with a promise:

* an irreversible act is HELD - nothing is sent upstream while it waits;
* approve runs the upstream exactly once, after the human receipt is written;
* deny never contacts the upstream at all, and the receipt says so;
* redact sends the upstream a request the personal fields were already removed from;
* a hold cannot outlive its order - revoke wins over a pending decision.
"""
from __future__ import annotations

import pytest


class Recorder:
    """An upstream that remembers exactly what it was given (the strongest evidence that
    a field did or did not cross the boundary)."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def call(self, tool: str, args: dict) -> dict:
        self.calls.append({"tool": tool, "args": dict(args or {})})
        rows = int((args or {}).get("rows", 1)) if (tool.endswith("read") or tool == "crm.bulk_export") else 1
        return {"rows": rows, "tool": tool}


def token_for(client, agent: str) -> str:
    row = next(a for a in client.get("/agents").json() if a["id"] == agent)
    return row["token"]


def call(client, agent: str, tool: str, args: dict | None = None, run: str = "") -> dict:
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": tool, "arguments": args or {}}},
        headers={"x-warrnt-agent": agent, "x-warrnt-token": token_for(client, agent),
                 "x-warrnt-run": run or f"run-{agent}"},
    ).json()


@pytest.fixture
def rec(client):
    r = Recorder()
    client.app.state.proxy.upstream = r
    return r


# --------------------------------------------------------------- held, not executed
def test_irreversible_act_is_held_and_nothing_runs(client, rec):
    reply = call(client, "deploy-agent", "infra.deploy", {"target": "prod"})
    assert "error" in reply
    data = reply["error"]["data"]
    assert data["decision"] == "human"
    assert data["executed"] is False
    assert rec.calls == [], "nothing may reach the upstream while a person has not decided"

    action_id = data["action_id"]
    one = client.get(f"/api/actions/{action_id}").json()
    assert one["state"] == "pending"
    assert one["upstream_contacted"] is False
    assert one["decision"] == "human"
    assert one["action_class"] == "irreversible"
    assert one["warrant"] == "W-4421" and one["warrant_state"] == "active"
    assert one["receipt"], "a hold is on the record as its own receipt"
    assert one["parameters"]["values_withheld"] is True


# --------------------------------------------------------------- approve
def test_approve_runs_once_after_the_human_receipt(client, rec):
    action_id = call(client, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
    out = client.post(f"/api/actions/{action_id}/approve", json={"by": "Indra"}).json()
    assert out["executed"] is True and out["upstream_contacted"] is True
    assert len(rec.calls) == 1 and rec.calls[0]["tool"] == "infra.deploy"

    one = client.get(f"/api/actions/{action_id}").json()
    assert one["state"] == "approved" and one["decided_by"] == "Indra"
    assert one["upstream_contacted"] is True
    assert one["execution_result"]["rows"] == 1

    # The human decision is written BEFORE the execution it authorises: the execution
    # receipt hangs off the decision receipt.
    entries = {e["hash"]: e for e in client.get("/receipts").json()}
    execution = entries[[h for h, e in entries.items()
                         if e.get("reason", "").startswith("executed after human approval")][0]]
    human = entries[execution["exec_hash"]]
    assert human["decision"] == "allow" and "human approved by Indra" in human["reason"]

    again = client.post(f"/api/actions/{action_id}/approve", json={"by": "Indra"})
    assert again.status_code == 409, "a hold is single-use"
    assert len(rec.calls) == 1


# --------------------------------------------------------------- deny
def test_deny_never_contacts_the_upstream(client, rec):
    action_id = call(client, "report-bot", "crm.bulk_export",
                     {"rows": 12000, "fields": ["email", "pesel"]})["error"]["data"]["action_id"]
    out = client.post(f"/api/actions/{action_id}/deny", json={"by": "Indra"}).json()
    assert out["executed"] is False and out["upstream_contacted"] is False
    assert rec.calls == []

    one = client.get(f"/api/actions/{action_id}").json()
    assert one["state"] == "denied" and one["upstream_contacted"] is False
    entries = {e["hash"][:8]: e for e in client.get("/receipts").json()}
    receipt = entries[one["receipt"]]
    assert receipt["decision"] == "deny"
    assert "human denied by Indra" in receipt["reason"]
    assert receipt.get("rows_after") in (0, None)


def test_anonymous_decision_is_refused(client):
    action_id = call(client, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
    r = client.post(f"/api/actions/{action_id}/approve", json={"by": "   "})
    assert r.status_code == 409 and "name is required" in r.json()["error"]


# --------------------------------------------------------------- redact
def test_redact_strips_personal_fields_before_upstream(client, rec):
    reply = call(client, "support-copilot", "crm.read",
                 {"rows": 3, "fields": ["subject", "email", "pesel"]})
    result = reply["result"]
    assert result["decision"] == "redact" and result["executed"] is True
    assert set(result["redacted"]) == {"email", "pesel"}
    assert len(rec.calls) == 1
    sent = rec.calls[0]["args"]
    assert sent["fields"] == ["subject"], f"upstream received {sent}"
    assert "email" not in sent["fields"] and "pesel" not in sent["fields"]


# --------------------------------------------------------------- scope denial
def test_deny_before_upstream_on_scope_violation(client, rec):
    reply = call(client, "support-copilot", "crm.bulk_export",
                 {"rows": 12000, "fields": ["email", "pesel"]})
    data = reply["error"]["data"]
    assert data["decision"] == "deny" and data["executed"] is False
    assert rec.calls == []
    one = client.get(f"/api/actions/{data['action_id']}").json()
    assert one["upstream_contacted"] is False


# --------------------------------------------------------------- revoke
def test_revoke_stops_further_execution(client, rec):
    client.post("/revoke", json={"agent": "deploy-agent"})
    reply = call(client, "deploy-agent", "infra.deploy")
    data = reply["error"]["data"]
    assert data["decision"] == "revoked" and data["executed"] is False
    assert rec.calls == []


def test_hold_cannot_outlive_its_order(client, rec):
    action_id = call(client, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
    client.post("/revoke", json={"agent": "deploy-agent"})
    out = client.post(f"/api/actions/{action_id}/approve", json={"by": "Indra"}).json()
    assert out["executed"] is False and out["state"] == "expired"
    assert rec.calls == []


# --------------------------------------------------------------- one id everywhere
def test_one_action_id_links_api_state_and_receipt(client):
    reply = call(client, "support-copilot", "crm.bulk_export", {"fields": ["email"]},
                 run="run-support-7")
    action_id = reply["error"]["data"]["action_id"]
    one = client.get(f"/api/actions/{action_id}").json()
    state = client.get("/api/state").json()
    logged = {a["action_id"]: a for a in state["action_log"]}[action_id]
    assert one == logged, "the console and the API read the same object"
    assert one["run_id"] == "run-support-7"
    receipts = {e["hash"][:8] for e in client.get("/receipts").json()}
    assert one["receipt"] in receipts, "the action points at a receipt that exists"
    assert state["control"]["counts"]["total"] >= 1


def test_ask_answers_from_the_record_only(client):
    action_id = call(client, "support-copilot", "crm.bulk_export", {"fields": ["email"]},
                     run="run-support-9")["error"]["data"]["action_id"]
    a = client.post("/api/ask", json={"q": "Why was support-copilot blocked?"}).json()
    assert a["grounded"] is True and a["evidence"]["action_id"] == action_id
    assert "upstream_contacted=false" in a["answer"]
    assert a["evidence"]["receipt"] and a["evidence"]["run_id"] == "run-support-9"

    client.post("/api/ask", json={"q": "Which action is waiting for me?"})  # no pending
    held = call(client, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
    w = client.post("/api/ask", json={"q": "Which action is waiting for me?"}).json()
    assert held in w["answer"] and w["evidence"]["action_id"] == held

    p = client.post("/api/ask", json={"q": "What happens if I approve this?"}).json()
    assert held in p["answer"] and "exactly once" in p["answer"]


# --------------------------------------------------------------- the answer is grounded
def test_ask_skips_actions_the_question_does_not_name(client):
    blocked = call(client, "support-copilot", "crm.bulk_export", {"fields": ["email"]},
                   run="run-support-11")["error"]["data"]["action_id"]
    call(client, "deploy-agent", "infra.deploy", run="run-deploy-11")

    a = client.post("/api/ask", json={"q": "Why was support-copilot blocked?"}).json()
    assert a["evidence"]["action_id"] == blocked, "the answer must be about the agent asked about"
    assert a["evidence"]["run_id"] == "run-support-11"

    r = client.post("/api/ask", json={"q": "Did it reach the CRM?"}).json()
    assert r["evidence"]["action_id"] == blocked
    assert "crm" in r["answer"].lower() and "false" in r["answer"]

    n = client.post("/api/ask", json={"q": "Why was vendor-mcp-bridge blocked?"}).json()
    assert "no action for vendor-mcp-bridge" in n["answer"], n["answer"]
    assert n["evidence"]["action_id"] is None


def test_held_action_names_the_class_decider(client):
    one = client.get(f"/api/actions/{call(client, 'deploy-agent', 'infra.deploy')['error']['data']['action_id']}").json()
    assert one["state"] == "pending"
    assert one["policy_result"], "the class floor that raised this decision is on the record"
    assert "person decides" in one["policy_result"]


# ---------------------------------------------------------------- asked-about action
def test_a_question_naming_an_action_is_answered_about_that_action():
    """The one dishonesty the layer cannot afford: answering about the wrong record."""
    from warrnt.controlplane import answer

    acts = [
        {"action_id": "A-0006", "agent": "deploy-agent", "tool": "infra.deploy", "decision": "human",
         "action_class": "irreversible", "warrant": "W-4421", "warrant_state": "active",
         "upstream_contacted": False, "receipt": "c57beb02", "state": "pending", "run_id": "run-deploy-6"},
        {"action_id": "A-0003", "agent": "support-copilot", "tool": "crm.bulk_export", "decision": "deny",
         "action_class": "read_personal", "warrant": "W-4419", "warrant_state": "active",
         "upstream_contacted": False, "receipt": "66442e31", "state": "denied", "run_id": "run-support-3",
         "reason": "bulk export of personal fields is never allowed"},
    ]
    out = answer("Why was A-0003 denied?", acts, {"receipts": [], "action_log": acts})
    assert out["evidence"]["action_id"] == "A-0003", out
    assert "A-0003" in out["answer"] and "bulk export of personal fields" in out["answer"]
    assert out["grounded"] is True


def test_a_question_naming_an_unknown_action_admits_it():
    from warrnt.controlplane import answer

    out = answer("What happened to A-9999?", [], {"receipts": [], "action_log": []})
    assert out["evidence"]["action_id"] is None
    assert "no action A-9999" in out["answer"]
    assert out["grounded"] is True


# --------------------------------------------- the boundary, counted (one number, two uses)
def test_a_denied_action_never_reached_for_the_boundary(client, rec):
    data = call(client, "support-copilot", "crm.bulk_export", {"rows": 5})["error"]["data"]
    assert data["decision"] == "deny"
    one = client.get(f"/api/actions/{data['action_id']}").json()
    assert one["boundary_attempts"] == 0 and one["upstream_contacted"] is False
    assert rec.calls == []


def test_an_allowed_action_reached_the_boundary_exactly_once(client, rec):
    aid = call(client, "support-copilot", "crm.read", {"table": "tickets"})["result"]["action_id"]
    one = client.get(f"/api/actions/{aid}").json()
    assert one["boundary_attempts"] == 1 and one["upstream_contacted"] is True
    assert len(rec.calls) == 1, "one attempt, one call - the counter is not a wish"


def test_a_held_action_counts_nothing_until_a_person_approves(client, rec):
    aid = call(client, "deploy-agent", "infra.deploy",
               {"target": "prod"})["error"]["data"]["action_id"]
    assert client.get(f"/api/actions/{aid}").json()["boundary_attempts"] == 0
    assert rec.calls == [], "a hold that has not been released has not reached out"
    client.post(f"/api/actions/{aid}/approve", json={"by": "Indra"})
    one = client.get(f"/api/actions/{aid}").json()
    assert one["boundary_attempts"] == 1 and one["upstream_contacted"] is True
    assert len(rec.calls) == 1


def test_the_separation_of_duties_refusal_is_the_kernel_vocabulary():
    """The refusal type has one home, so a catcher catches every refusal of this kind."""
    from warrnt.controlplane import SeparationOfDutiesRefused

    assert issubclass(SeparationOfDutiesRefused, RuntimeError)
