"""The taxonomy of action classes: what kind of act is this, and who decides it.

These tests hold the two rules that make the taxonomy enforcement rather than a diagram:
an unclassified act is refused, and a class can only raise a decision - never lower it.
"""
import pytest

from warrnt.actions import (CLASS_MEANING, CLASS_OF_TOOL, DECIDER, DECIDER_TEXT, ActionClass,
                            Decider, apply_class, assert_seed_covered, classify, decided_by,
                            listing, personal_fields)
from warrnt.models import Decision
from warrnt.seed import SEED_SPECS


def _call(client, tokens, agent, tool, args=None):
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                     "params": {"name": tool, "arguments": args or {}}},
                       headers={"X-WARRNT-Agent": agent, "X-WARRNT-Token": tokens[agent]})


def test_there_are_six_classes_and_every_one_has_a_decider():
    assert [c.value for c in ActionClass] == [
        "observe", "read_personal", "draft", "write_reversible", "irreversible", "authorize"]
    assert set(DECIDER) == set(ActionClass)
    for cls in ActionClass:
        assert DECIDER_TEXT[DECIDER[cls]] and CLASS_MEANING[cls]


def test_the_ladder_of_who_decides():
    """Five rungs, in order of authority: machine at the bottom, the operator at the top."""
    assert [decided_by(c) for c in ActionClass] == [
        Decider.machine, Decider.machine_receipt, Decider.machine,
        Decider.machine_warrant, Decider.human, Decider.operator]


def test_every_tool_the_seed_warrants_speak_about_is_classified():
    """A tool covered by a warrant but missing from the taxonomy is a wiring bug."""
    assert assert_seed_covered(SEED_SPECS) == []


def test_a_read_that_names_a_personal_field_is_not_an_observation():
    """The classification follows the act, not the tool's label."""
    assert classify("infra.plan", {"note": "dry run"}) is ActionClass.observe
    assert classify("infra.plan", {"fields": ["pesel", "env"]}) is ActionClass.read_personal
    assert personal_fields({"fields": ["email", "PESEL", "table"]}) == ["email", "pesel"]


def test_an_unclassified_act_is_refused_rather_than_guessed():
    decision, reason, detail = apply_class(Decision.allow, None, {})
    assert decision is Decision.deny
    assert detail["class"] is None
    assert "cannot classify" in reason


def test_a_class_raises_an_allow_to_a_person_for_irreversible_acts():
    decision, reason, detail = apply_class(Decision.allow, ActionClass.irreversible, {})
    assert decision is Decision.human
    assert detail["decider"] == "human"
    assert "the machine prepares" in reason


def test_only_the_operator_may_act_on_the_rules_themselves():
    decision, reason, detail = apply_class(Decision.allow, ActionClass.authorize, {})
    assert decision is Decision.deny
    assert detail["decider"] == "operator-human only"
    assert "no machine may" in reason


def test_a_redact_is_raised_by_a_class_like_any_executed_call():
    """A redact is an executed call, so the ladder treats it as one: machine classes keep
    it, an irreversible act still lifts it to a person, the operator class still refuses."""
    expected = {
        ActionClass.observe: Decision.redact,
        ActionClass.read_personal: Decision.redact,
        ActionClass.draft: Decision.redact,
        ActionClass.write_reversible: Decision.redact,
        ActionClass.irreversible: Decision.human,
        ActionClass.authorize: Decision.deny,
    }
    got = {cls: apply_class(Decision.redact, cls, {})[0] for cls in ActionClass}
    assert got == expected


@pytest.mark.parametrize("given", [Decision.deny, Decision.revoked])
def test_a_class_never_lowers_a_decision(given):
    """Whatever the order, the guards or the register already decided stands."""
    for cls in ActionClass:
        decision, _, _ = apply_class(given, cls, {})
        assert decision is given


def test_the_whole_ladder_on_one_page():
    """allow in, one pinned decision out - the table a juror can read in ten seconds."""
    got = {c.value: apply_class(Decision.allow, c, {})[0].value for c in ActionClass}
    assert got == {
        "observe": "allow",
        "read_personal": "allow",
        "draft": "allow",
        "write_reversible": "allow",
        "irreversible": "human",
        "authorize": "deny",
    }


def test_a_transfer_within_limit_now_needs_a_person_not_a_stamp(client, tokens):
    """Money is the canonical irreversible act: a valid warrant is not enough."""
    before = client.get("/state").json()["executor_calls"].get("payments.transfer", 0)
    body = _call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 42000}).json()
    assert body["error"]["data"]["decision"] == "human"
    assert body["error"]["data"]["class"] == "irreversible"
    assert body["error"]["data"]["executed"] is False
    assert client.get("/state").json()["executor_calls"].get("payments.transfer", 0) == before


def test_the_receipt_names_the_class_of_the_act(client, tokens):
    """The class belongs in the hash-chained record, not only in the reply."""
    _call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 42000})
    row = client.get("/receipts").json()[-1]
    assert row["decision"] == "human" and "class irreversible" in row["reason"]
    assert client.get("/verify").json()["ok"] is True


def test_the_taxonomy_is_readable_by_the_console(client):
    actions = client.get("/state").json()["actions"]
    assert [a["class"] for a in actions] == [c.value for c in ActionClass]
    by_class = {a["class"]: a for a in actions}
    assert by_class["irreversible"]["tools"] == ["infra.deploy", "payments.transfer"]
    assert by_class["authorize"]["decider"] == "operator-human only"
    assert by_class["observe"]["decider"] == "machine"


def test_listing_names_the_tools_of_each_class():
    rows = {r["class"]: r for r in listing()}
    assert "payments.transfer" in rows["irreversible"]["tools"]
    assert "crm.update" in rows["write_reversible"]["tools"]
    assert CLASS_OF_TOOL["infra.plan"] is ActionClass.observe
