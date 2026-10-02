"""Pre-execution policy engine.

The engine reads the *parameters of the call itself* - not the agent's stated intent -
and returns a decision in ``allow | deny | human | revoked | expired``. It never executes
anything: that is the proxy's job, and only on ``allow``.
"""
from __future__ import annotations

from typing import Any

from .models import AgentState, Decision, Rule, Warrant
from .warrants import refresh_state

# Fields that make a payload PII. A warrant that fences ``crm.bulk_export`` will trip on
# any of these appearing in an inspected parameter.
PII_FIELDS = {
    "email", "pesel", "dob", "ssn", "iban", "phone", "address", "card", "passport",
    "national_id", "tax_id", "account", "credit_card", "msisdn", "pesel_number",
}

_OPS = {
    "le": lambda a, b: a is not None and a <= b,
    "ge": lambda a, b: a is not None and a >= b,
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
}


def _pii(names: Any) -> list[str]:
    return [str(n) for n in (names or []) if str(n).lower() in PII_FIELDS]


class PolicyEngine:
    def __init__(self, pii_fields: set[str] | None = None, verify=None):
        self.pii_fields = pii_fields or PII_FIELDS
        # ``verify`` is the issuer's signature check, wired in by the node. When set, an
        # order that does not verify is refused *before* its rules are ever read: the
        # signed artifact is the authority, not a mutable object in memory.
        self.verify = verify

    def order_ok(self, warrant: Warrant) -> bool:
        """Fail closed: any error while verifying means the order is not honoured."""
        if self.verify is None:
            return True
        try:
            return bool(self.verify(warrant))
        except Exception:
            return False

    def evaluate(self, warrant: Warrant | None, tool: str,
                 params: dict[str, Any] | None) -> tuple[Decision, str, dict[str, Any]]:
        params = params or {}

        if warrant is None:
            return Decision.deny, "no warrant covers this agent", {"scope": "none"}
        if not self.order_ok(warrant):
            return (Decision.deny,
                    f"warrant {warrant.id} signature invalid · unverified order, no action",
                    {"warrant": warrant.id, "sig_ok": False})
        if warrant.state == "revoked":
            return Decision.revoked, f"warrant {warrant.id} revoked · chain stopped", {"warrant": warrant.id}
        if refresh_state(warrant) == "expired":
            return Decision.expired, f"warrant {warrant.id} TTL elapsed", {"warrant": warrant.id}

        rule = next((r for r in warrant.rules if r.tool == tool), None)
        if rule is None:
            return (Decision.deny,
                    f"tool '{tool}' is not covered by warrant scope",
                    {"scope": warrant.scope})

        detail: dict[str, Any] = {"scope": warrant.scope, "warrant": warrant.id}
        reason = rule.reason

        for guard in rule.guards:
            value = params.get(guard.param)
            holds = _OPS.get(guard.op, lambda a, b: True)(value, guard.value)
            if not holds:
                text = guard.reason.replace("{param}", guard.param).replace("{v}", str(value))
                return guard.fail, text, {**detail, guard.param: value}

        if rule.inspect_pii:
            fields = params.get(rule.inspect_pii[0])
            detail["fields"] = fields
            hits = _pii(fields)
            if hits:
                reason = f"{reason} · PII fields requested: {', '.join(hits)}"

        return rule.effect, reason, detail
