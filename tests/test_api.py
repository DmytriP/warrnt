"""End-to-end over the FastAPI surface: the node really decides and really brakes."""


def call(client, tokens, agent, tool, args):
    return client.post("/mcp",
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": tool, "arguments": args}},
                       headers={"X-WARRNT-Agent": agent, "X-WARRNT-Token": tokens.get(agent, "")})


def _calls(client, tool):
    return client.get("/state").json()["executor_calls"].get(tool, 0)


def test_health_reports_the_chain(client):
    body = client.get("/health").json()
    assert body["ok"] is True and body["chain"]["ok"] is True


def test_allowed_call_reaches_the_upstream(client, tokens):
    before = _calls(client, "crm.read")
    reply = call(client, tokens, "support-copilot", "crm.read", {"table": "tickets", "limit": 5})
    body = reply.json()
    assert "result" in body and body["result"]["decision"] == "allow"
    assert body["result"]["executed"] is True
    assert _calls(client, "crm.read") == before + 1


def test_transfer_over_limit_is_denied_and_not_executed(client, tokens):
    before = _calls(client, "payments.transfer")
    reply = call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 60000})
    body = reply.json()
    assert "error" in body
    assert body["error"]["code"] == -32001
    assert body["error"]["data"]["decision"] == "deny"
    assert "60000" in body["error"]["message"]
    assert body["error"]["data"]["executed"] is False
    assert _calls(client, "payments.transfer") == before      # nothing ran


def test_transfer_within_limit_is_allowed(client, tokens):
    reply = call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 42000})
    assert reply.json()["result"]["decision"] == "allow"


def test_pii_export_is_denied_before_execution(client, tokens):
    before = _calls(client, "crm.bulk_export")
    reply = call(client, tokens, "support-copilot", "crm.bulk_export",
                 {"table": "customers", "fields": ["email", "pesel"], "rows": 12000})
    body = reply.json()
    assert body["error"]["data"]["decision"] == "deny"
    assert "email" in body["error"]["message"]
    after = _calls(client, "crm.bulk_export")
    assert before == after == 0                               # zero rows left the perimeter


def test_deploy_requires_a_human(client, tokens):
    before = _calls(client, "infra.deploy")
    reply = call(client, tokens, "deploy-agent", "infra.deploy", {"env": "prod"})
    body = reply.json()
    assert body["error"]["code"] == -32002
    assert body["error"]["data"]["decision"] == "human"
    assert _calls(client, "infra.deploy") == before


def test_forged_token_is_denied(client, tokens):
    reply = client.post("/mcp",
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "crm.read", "arguments": {}}},
                        headers={"X-WARRNT-Agent": "support-copilot",
                                 "X-WARRNT-Token": "not-the-token"})
    assert reply.json()["error"]["data"]["decision"] == "deny"


def test_unknown_tool_is_denied(client, tokens):
    reply = call(client, tokens, "support-copilot", "crm.delete_all", {})
    assert reply.json()["error"]["data"]["decision"] == "deny"


def test_revoke_halts_the_agent_on_its_next_call(client, tokens):
    assert call(client, tokens, "support-copilot", "crm.read", {}).json()["result"]["decision"] == "allow"
    rv = client.post("/revoke", json={"agent": "support-copilot"})
    assert rv.status_code == 200 and rv.json()["state"] == "halted"

    reply = call(client, tokens, "support-copilot", "crm.read", {})
    body = reply.json()
    assert body["error"]["code"] == -32003
    assert body["error"]["data"]["decision"] == "revoked"

    warrants = {w["id"]: w for w in client.get("/warrants").json()}
    assert warrants["W-4419"]["state"] == "revoked"


def test_revoke_accepts_a_warrant_id(client, tokens):
    rv = client.post("/revoke", json={"warrant": "W-4421"})
    assert rv.status_code == 200 and rv.json()["agent"] == "deploy-agent"


def test_revoke_is_idempotent_conflict(client, tokens):
    client.post("/revoke", json={"agent": "deploy-agent"})
    assert client.post("/revoke", json={"agent": "deploy-agent"}).status_code == 409


def test_receipts_are_append_only_and_chain_verifies(client, tokens):
    call(client, tokens, "support-copilot", "crm.read", {})
    call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 60000})
    receipts = client.get("/receipts").json()
    assert len(receipts) >= 2
    assert client.get("/verify").json()["ok"] is True
    # hash chain: every entry points at the previous hash
    prev = "0" * 64
    for entry in receipts:
        assert entry["prev"] == prev
        prev = entry["hash"]


def test_warrants_expose_a_valid_signature(client):
    for warrant in client.get("/warrants").json():
        assert warrant["sig_ok"] is True
        assert len(warrant["sig"]) == 64


def test_reset_reissues_and_clears(client, tokens):
    client.post("/revoke", json={"agent": "support-copilot"})
    client.post("/reset")
    assert client.get("/verify").json()['length'] == 0
    assert call(client, tokens, "support-copilot", "crm.read", {}).json()["result"]["decision"] == "allow"


def test_state_contract_shape(client):
    state = client.get("/state").json()
    for key in ("revoked", "last_stop", "agents", "warrants", "receipts", "executor_calls", "chain"):
        assert key in state
    assert len(state["agents"]) == 3 and len(state["warrants"]) == 3


# --- P2.1: pre-execution enforcement of the order itself ----------------------

def test_a_tampered_order_is_refused_before_execution(client, tokens):
    """Widen a signed limit in memory; the gate must honour the signature, not the object."""
    proxy = client.app.state.proxy
    proxy.warrants["W-4417"].rules[1].guards[0].value = 10_000_000

    before = _calls(client, "payments.transfer")
    reply = call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 5_000_000})
    body = reply.json()
    assert body["error"]["code"] == -32001
    assert body["error"]["data"]["decision"] == "deny"
    assert "signature invalid" in body["error"]["message"]
    assert body["error"]["data"]["sig_ok"] is False
    assert body["error"]["data"]["executed"] is False
    assert _calls(client, "payments.transfer") == before          # nothing ran

    seen = {w["id"]: w for w in client.get("/warrants").json()}
    assert seen["W-4417"]["sig_ok"] is False                      # visible on the order view


def test_identity_is_scoped_to_its_own_order(client, tokens):
    """A support identity pointed at the finance order is refused by binding, not by tool."""
    proxy = client.app.state.proxy
    proxy.agents["support-copilot"].warrant = "W-4417"            # rebind to another agent's order
    reply = call(client, tokens, "support-copilot", "payments.read", {})
    body = reply.json()
    assert body["error"]["data"]["decision"] == "deny"
    assert "binding mismatch" in body["error"]["message"]


def test_dev_tamper_probe_is_off_without_dev_mode(settings, tokens):
    from fastapi.testclient import TestClient
    import dataclasses
    from warrnt.api import create_app

    prod = dataclasses.replace(settings, dev=False)
    with TestClient(create_app(settings=prod)) as c:
        assert c.post("/_dev/tamper", json={"warrant": "W-4419"}).status_code == 403


def test_dev_tamper_probe_marks_the_order_invalid(client):
    reply = client.post("/_dev/tamper", json={"warrant": "W-4417"})
    assert reply.status_code == 200
    body = reply.json()
    assert body["ok"] is True and body["sig_ok"] is False
    seen = {w["id"]: w for w in client.get("/warrants").json()}
    assert seen["W-4417"]["sig_ok"] is False
