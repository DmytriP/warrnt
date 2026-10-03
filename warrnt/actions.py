"""The taxonomy of action classes — *what kind of act is this, and who decides it*.

The warrant answers "was this call authorised". The register answers "may this kind of
actor stand at the gate". This module answers the third question, the one a control layer
owes an auditor before either of the others: **what kind of action is this, and who is
allowed to decide it**.

Two rules make the taxonomy enforcement rather than documentation:

1. **An unclassified tool is refused.** A layer that cannot say what kind of act it is
   looking at does not get to let it through. The refusal names the missing classification.
2. **A class can only raise the decision, never lower it.** The order, the guards and the
   register may all say ``allow``; if the act is ``irreversible``, the answer the machine
   gives is still ``human`` — the machine prepares, a person decides. Nothing in the
   warrant can talk the class down, which is exactly why the taxonomy is not a permission.

Declared in code on purpose, next to the seed warrants: this node has no admin UI, so
editing this table is how the classification changes. ``assert_seed_covered()`` keeps the
two tables honest — a tool covered by a warrant but missing here is a wiring bug, not a
policy choice.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from .models import Decision


class ActionClass(str, Enum):
    """Six kinds of act. The order is the ladder, from "the machine may decide" up to
    "only a person may decide"."""

    observe = "observe"                    # read-only, no personal data leaves
    read_personal = "read_personal"         # reads personal data; the fields are recorded
    draft = "draft"                         # writes something that has no effect outside
    write_reversible = "write_reversible"   # changes external state, undoable
    irreversible = "irreversible"           # money, deletion, filing, sending: no undo
    authorize = "authorize"                 # changes the rules themselves


class Decider(str, Enum):
    """Who holds the decision for a class."""

    machine = "machine"                                      # the node decides alone
    machine_receipt = "machine + receipt"                     # decides, and the fields are on the record
    machine_warrant = "machine + valid warrant"               # decides, but only under a signed order
    human = "human"                                           # a person decides; the machine prepares
    operator = "operator-human only"                          # only the operator may act; never a machine


# The ladder. Higher index = more authority required; a class can only move a decision up.
DECIDER: dict[ActionClass, Decider] = {
    ActionClass.observe: Decider.machine,
    ActionClass.read_personal: Decider.machine_receipt,
    ActionClass.draft: Decider.machine,
    ActionClass.write_reversible: Decider.machine_warrant,
    ActionClass.irreversible: Decider.human,
    ActionClass.authorize: Decider.operator,
}

DECIDER_TEXT: dict[Decider, str] = {
    Decider.machine: "the node decides",
    Decider.machine_receipt: "the node decides · the fields are on the record",
    Decider.machine_warrant: "the node decides under a signed order",
    Decider.human: "a person decides · the machine prepares only",
    Decider.operator: "the operator-human only · no machine may",
}

# What each class *is*, in one line, for the console and for a juror reading the state.
CLASS_MEANING: dict[ActionClass, str] = {
    ActionClass.observe: "read-only, nothing personal and nothing changed",
    ActionClass.read_personal: "reads personal data; the fields read are recorded",
    ActionClass.draft: "produces an artifact that changes nothing outside the boundary",
    ActionClass.write_reversible: "changes external state in a way that can be undone",
    ActionClass.irreversible: "cannot be undone: money moves, data is deleted, a document is filed",
    ActionClass.authorize: "changes the rules themselves — a warrant, a limit, a registration",
}

# class -> the tools of this node. A tool that is not here is refused (fail closed).
CLASS_OF_TOOL: dict[str, ActionClass] = {
    "infra.plan": ActionClass.observe,
    "payments.read": ActionClass.read_personal,
    "crm.read": ActionClass.read_personal,
    "crm.bulk_export": ActionClass.read_personal,
    "crm.update": ActionClass.write_reversible,
    "infra.deploy": ActionClass.irreversible,
    "payments.transfer": ActionClass.irreversible,
    "warrant.issue": ActionClass.authorize,
    "warrant.revoke": ActionClass.authorize,
    "policy.edit": ActionClass.authorize,
}

# Params whose values name data fields. A read that asks for a personal field is not a
# plain read, whatever the tool is called.
FIELD_PARAMS = ("fields",)
PERSONAL_FIELDS = {
    "email", "pesel", "dob", "ssn", "iban", "phone", "address", "card", "passport",
    "national_id", "tax_id", "account", "credit_card", "msisdn", "pesel_number",
}

# redact ranks with allow: the call still runs, so a class may raise it but never needs to.
_RAISE = {Decision.allow: 0, Decision.redact: 0, Decision.human: 1, Decision.deny: 2,
          Decision.revoked: 3}


def personal_fields(params: dict[str, Any] | None) -> list[str]:
    """The personal fields a call actually names, from the parameters themselves."""
    hits: list[str] = []
    for name in FIELD_PARAMS:
        value = (params or {}).get(name)
        for field in (value if isinstance(value, (list, tuple, set)) else [value]):
            if isinstance(field, str) and field.lower() in PERSONAL_FIELDS:
                hits.append(field.lower())
    return sorted(set(hits))


def classify(tool: str, params: dict[str, Any] | None = None) -> Optional[ActionClass]:
    """The class of this act, or ``None`` when the layer cannot say — which is a refusal.

    A read that names a personal field is escalated to ``read_personal`` even if the tool
    is registered as an observation: the classification follows the act, not the label.
    """
    cls = CLASS_OF_TOOL.get(tool)
    if cls is None:
        return None
    if cls is ActionClass.observe and personal_fields(params):
        return ActionClass.read_personal
    return cls


def decided_by(cls: ActionClass) -> Decider:
    return DECIDER[cls]


def apply_class(decision: Decision, cls: Optional[ActionClass],
                params: dict[str, Any] | None = None) -> tuple[Decision, str, dict[str, Any]]:
    """Raise a decision to the floor its class demands. Returns (decision, note, detail).

    The class never lowers a decision: a denial stays a denial, a revocation stays a
    revocation. It only raises an ``allow`` to ``human`` (or a train of them) where the
    class says a person holds the call.
    """
    if cls is None:
        return Decision.deny, ("no action class for this tool · the layer refuses what it "
                               "cannot classify"), {"class": None, "decider": None}

    who = DECIDER[cls]
    detail: dict[str, Any] = {"class": cls.value, "decider": who.value,
                              "decider_text": DECIDER_TEXT[who]}
    hits = personal_fields(params)
    if hits:
        detail["personal_fields"] = hits

    # The floor the class imposes. Raising means moving *up* the ladder, never down: a
    # revoked or denied order stays revoked or denied even for an irreversible act -
    # fail-closed means the reason is kept, not overwritten.
    floor = Decision.allow
    note = ""
    if who is Decider.human:
        floor = Decision.human
        note = (f"class {cls.value} · {CLASS_MEANING[cls]} · the machine prepares, "
                f"a person decides")
    elif who is Decider.operator:
        floor = Decision.deny
        note = (f"class {cls.value} · only the operator may act, no machine may "
                f"({CLASS_MEANING[cls]})")

    if _RAISE[decision] < _RAISE[floor]:
        return floor, note, detail
    return decision, "", detail


def listing() -> list[dict[str, Any]]:
    """The taxonomy as the console shows it: class, who decides, what it means, tools."""
    out = []
    for cls in ActionClass:
        who = DECIDER[cls]
        out.append({
            "class": cls.value,
            "decider": who.value,
            "decider_text": DECIDER_TEXT[who],
            "meaning": CLASS_MEANING[cls],
            "tools": sorted(t for t, c in CLASS_OF_TOOL.items() if c is cls),
        })
    return out


def assert_seed_covered(specs) -> list[str]:
    """Every tool a seed warrant speaks about must be classified. Returns the missing ones."""
    missing = []
    for spec in specs:
        for rule in spec.rules:
            if rule.tool not in CLASS_OF_TOOL:
                missing.append(rule.tool)
    return sorted(set(missing))
