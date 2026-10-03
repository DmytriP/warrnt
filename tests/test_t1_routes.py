"""TASK.1 - the read/mutation surface the Control Plane needs.

Every new route is a *projection* of state the kernel already holds: counters from the
registry and the Action ledger, warrants from the issuer, agents from the register. These
tests pin three things a juror can check: the route answers 200 with the right shape, the
aliases return byte-for-byte the same payload as the originals, and empty state returns
empty lists - never a fixture row (AC1, AC4, TASK.3).
"""
from __future__ import annotations

import pytest


def call(client, agent: str, tool: str, args: dict | None = None, run: str = "") -> dict:
    row = next(a for a in client.get("/agents").json() if a["id"] == agent)
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": tool, "arguments": args or {}}},
        headers={"x-warrnt-agent": agent, "x-warrnt-token": row["token"],
                 "x-warrnt-run": run or f"run-{agent}"},
    ).json()


# ------------------------------------------------------------------- AC1: status + shape
def test_overview_is_one_payload_of_counters_and_authority(client):
    r = client.get("/api/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["node"] == "TENET"
    assert body["mode"] == "dev"
    assert set(body["counts"]) >= {"agents", "warrants", "receipts", "actions", "pending"}
    assert body["counts"]["agents"] == 4          # the four seeded orders
    assert set(body["authority"]) >= {"issuer", "warrant_states", "actors", "action_classes"}
    assert body["chain"]["ok"] is True


def test_activity_is_ordered_newest_first(client):
    held = call(client, "deploy-agent", "infra.deploy", {"target": "prod"})["error"]["data"]
    second = call(client, "support-copilot", "crm.read", {"table": "tickets"})
    assert "result" in second

    body = client.get("/api/activity").json()
    assert body["count"] == len(body["events"]) and body["events"]
    assert all("kind" in e and "ts" in e for e in body["events"])
    ts = [e["ts"] for e in body["events"]]
    assert ts == sorted(ts, reverse=True), "ordered newest first by the record's own ts"
    # Every action the node recorded is on the list, newest action first.
    actions = [e for e in body["events"] if e["kind"] == "action"]
    assert [a["action_id"] for a in actions] == ["A-0002", "A-0001"]
    assert held["action_id"] == "A-0001"




def test_activity_respects_limit_and_never_returns_null_timestamps(client):
    call(client, "support-copilot", "crm.read", {"table": "tickets"})
    body = client.get("/api/activity?limit=1").json()
    assert body["count"] == 1 and len(body["events"]) == 1
    assert body["events"][0]["ts"] is not None, "no placeholder timestamps"


def test_pending_lists_only_pending_actions(client):
    held = call(client, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
    call(client, "support-copilot", "crm.read", {"table": "tickets"})   # allowed, not pending

    body = client.get("/api/actions/pending").json()
    assert body["count"] == 1
    assert [a["action_id"] for a in body["pending"]] == [held]
    assert all(a["state"] == "pending" for a in body["pending"])


def test_pending_route_is_not_swallowed_by_the_id_route(client):
    """Declared order matters: /pending must not be read as an action id."""
    body = client.get("/api/actions/pending").json()
    assert "pending" in body and "action_id" not in body


def test_api_warrants_is_the_same_payload_as_warrants(client):
    plain = client.get("/warrants").json()
    alias = client.get("/api/warrants").json()
    assert alias == plain


def test_api_agents_is_the_same_payload_as_agents(client):
    plain = client.get("/agents").json()
    alias = client.get("/api/agents").json()
    assert alias == plain


def test_existing_routes_still_answer(client, tokens):
    for path in ("/health", "/state", "/api/state", "/api/actions"):
        assert client.get(path).status_code == 200, path
    assert client.post("/api/ask", json={"q": "what is happening"}).status_code == 200


# ------------------------------------------------------------------ AC4: empty state = []
def test_empty_state_returns_empty_lists_not_samples(client):
    assert client.get("/api/actions").json()["actions"] == []
    assert client.get("/api/actions/pending").json()["pending"] == []
    assert client.get("/api/activity").json()["events"] == []
    assert client.get("/api/warrants").json() != []          # warrants are seeded, not invented
