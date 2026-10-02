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


def test_expired_warrant_is_reported_as_expired():
    clock = {"t": 0.0}
    issuer = WarrantIssuer(key=b"k", now=lambda: clock["t"])
    w = issuer.issue(WarrantSpec(id="W-x", agent="a", role="R", scope="s", ttl=10.0,
                                 rules=[Rule(tool="crm.read", effect=Decision.allow)]))
    clock["t"] = 11.0
    decision, reason, _ = ENGINE.evaluate(w, "crm.read", {})
    assert decision is Decision.expired and "TTL" in reason


def test_unknown_agent_has_no_warrant():
    decision, reason, _ = ENGINE.evaluate(None, "crm.read", {})
    assert decision is Decision.deny and "no warrant" in reason
