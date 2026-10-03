"""Brick 2 - policy on the parameters of the call, decided before execution."""
from warrnt.models import Decision, Guard, Rule, WarrantSpec
from warrnt.policy import PolicyEngine
from warrnt.warrants import WarrantIssuer


def warrant(rules, ttl=900.0):
    issuer = WarrantIssuer(key=b"k")
    return issuer.issue(WarrantSpec(id="W-9", agent="a", role="R", scope="scope",
                                    ttl=ttl, rules=rules))


ENGINE = PolicyEngine()


def test_tool_outside_scope_is_denied():
    w = warrant([Rule(tool="payments.read", effect=Decision.allow)])
    decision, reason, _ = ENGINE.evaluate(w, "payments.transfer", {})
    assert decision is Decision.deny
    assert "not covered by warrant scope" in reason


def test_guard_denies_over_limit():
    w = warrant([Rule(tool="payments.transfer", effect=Decision.allow, reason="limit",
                      guards=[Guard(param="amount_pln", op="le", value=50000,
                                    fail=Decision.deny,
                                    reason="amount_pln={v} exceeds warrant limit 50,000 PLN")])])
    decision, reason, detail = ENGINE.evaluate(w, "payments.transfer", {"amount_pln": 60000})
    assert decision is Decision.deny
    assert "60000" in reason and "50,000" in reason
    assert detail["amount_pln"] == 60000


def test_guard_allows_within_limit():
    w = warrant([Rule(tool="payments.transfer", effect=Decision.allow,
                      guards=[Guard(param="amount_pln", op="le", value=50000)])])
    decision, _, _ = ENGINE.evaluate(w, "payments.transfer", {"amount_pln": 42000})
    assert decision is Decision.allow


def test_missing_guarded_param_fails_closed():
    w = warrant([Rule(tool="payments.transfer", effect=Decision.allow,
                      guards=[Guard(param="amount_pln", op="le", value=50000)])])
    decision, _, _ = ENGINE.evaluate(w, "payments.transfer", {})
    assert decision is Decision.deny


def test_pii_fields_are_reported():
    w = warrant([Rule(tool="crm.bulk_export", effect=Decision.deny,
                      reason="export=false", inspect_pii=["fields"])])
    decision, reason, detail = ENGINE.evaluate(
        w, "crm.bulk_export", {"fields": ["email", "pesel", "city"]})
    assert decision is Decision.deny
    assert "email" in reason and "pesel" in reason
    assert detail["fields"] == ["email", "pesel", "city"]


def test_human_effect_stops_short_of_execution():
    w = warrant([Rule(tool="infra.deploy", effect=Decision.human, reason="needs a human")])
    decision, reason, _ = ENGINE.evaluate(w, "infra.deploy", {})
    assert decision is Decision.human


def test_revoked_warrant_wins_over_scope():
    w = warrant([Rule(tool="crm.read", effect=Decision.allow)])
    w.state = "revoked"
    decision, _, _ = ENGINE.evaluate(w, "crm.read", {})
    assert decision is Decision.revoked


def test_an_expired_order_is_refused_as_a_deny_carrying_the_state():
    """``expired`` is a warrant state, not a decision: the contract freezes five decisions."""
    clock = {"t": 0.0}
    issuer = WarrantIssuer(key=b"k", now=lambda: clock["t"])
    w = issuer.issue(WarrantSpec(id="W-x", agent="a", role="R", scope="s", ttl=10.0,
                                 rules=[Rule(tool="crm.read", effect=Decision.allow)]))
    clock["t"] = 11.0
    decision, reason, detail = ENGINE.evaluate(w, "crm.read", {})
    assert decision is Decision.deny and "TTL" in reason
    assert detail["warrant_state"] == "expired"
    assert "expired" not in {d.value for d in Decision}


def test_a_read_that_names_a_personal_field_is_stripped_not_refused():
    w = warrant([Rule(tool="crm.read", effect=Decision.allow, redact=["fields"])])
    decision, reason, detail = ENGINE.evaluate(
        w, "crm.read", {"table": "tickets", "fields": ["subject", "email", "PESEL"]})
    assert decision is Decision.redact
    assert sorted(detail["redacted"]) == ["PESEL", "email"]   # the record keeps the asking
    assert "stripped" in reason


def test_a_clean_read_stays_a_plain_allow():
    w = warrant([Rule(tool="crm.read", effect=Decision.allow, redact=["fields"])])
    decision, _, _ = ENGINE.evaluate(w, "crm.read", {"table": "tickets", "fields": ["subject"]})
    assert decision is Decision.allow


def test_strip_pii_removes_the_field_from_the_payload():
    from warrnt.policy import strip_pii
    clean, removed = strip_pii({"table": "tickets", "fields": ["subject", "email"], "limit": 5},
                               ["email"])
    assert clean == {"table": "tickets", "fields": ["subject"], "limit": 5}
    assert removed == ["email"]


def test_unknown_agent_has_no_warrant():
    decision, reason, _ = ENGINE.evaluate(None, "crm.read", {})
    assert decision is Decision.deny and "no warrant" in reason


# --- P2.1: the order is verified at the gate, not merely displayed ------------

def test_unverifiable_order_is_denied_before_rules_are_read():
    engine = PolicyEngine(verify=lambda w: False)
    w = warrant([Rule(tool="payments.read", effect=Decision.allow)])
    decision, reason, detail = engine.evaluate(w, "payments.read", {})
    assert decision is Decision.deny
    assert "signature invalid" in reason
    assert detail["sig_ok"] is False


def test_verifying_engine_allows_a_genuine_order():
    issuer = WarrantIssuer(key=b"k")
    w = issuer.issue(WarrantSpec(id="W-ok", agent="a", role="R", scope="s", ttl=900.0,
                                 rules=[Rule(tool="crm.read", effect=Decision.allow,
                                             reason="read-only · in scope")]))
    engine = PolicyEngine(verify=issuer.signature_ok)
    decision, _, _ = engine.evaluate(w, "crm.read", {})
    assert decision is Decision.allow


def test_tampered_order_is_denied_by_a_verifying_engine():
    issuer = WarrantIssuer(key=b"k")
    w = issuer.issue(WarrantSpec(id="W-t", agent="a", role="R", scope="s", ttl=900.0,
                                 rules=[Rule(tool="payments.transfer", effect=Decision.allow,
                                             guards=[Guard(param="amount_pln", op="le", value=50000)])]))
    w.rules[0].guards[0].value = 10_000_000          # widen after signing
    engine = PolicyEngine(verify=issuer.signature_ok)
    decision, reason, _ = engine.evaluate(w, "payments.transfer", {"amount_pln": 5_000_000})
    assert decision is Decision.deny and "signature invalid" in reason


def test_verify_error_fails_closed():
    def boom(_):
        raise RuntimeError("verifier exploded")

    engine = PolicyEngine(verify=boom)
    w = warrant([Rule(tool="crm.read", effect=Decision.allow)])
    decision, _, _ = engine.evaluate(w, "crm.read", {})
    assert decision is Decision.deny


def test_engine_without_a_verifier_still_works():
    # back-compat: unit policy tests run without wiring the issuer.
    assert ENGINE.order_ok(warrant([Rule(tool="crm.read")])) is True
