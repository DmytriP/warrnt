"""Pre-execution policy engine.

The engine reads the *parameters of the call itself* - not the agent's stated intent -
and returns a decision in ``allow | deny | redact | human | revoked`` — the frozen contract
space. It never executes anything: that is the proxy's job, and only on ``allow`` and
``redact`` (a redacted call runs, but with the personal fields removed first).
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


def strip_pii(params: dict[str, Any] | None, redacted: list[str]) -> tuple[dict[str, Any], list[str]]:
    """Return (executable params, names removed) with the named fields taken out.

    Works on the parameters as they arrive: any list-valued param loses the named entries,
    and a bare string param that *is* one of the names is dropped. Nothing here decides
    anything - the decision was already taken; this only builds the payload the upstream
    is allowed to see.
    """
    gone = {n.lower() for n in redacted}
    if not gone:
        return dict(params or {}), []
    clean: dict[str, Any] = {}
    removed: list[str] = []
    for key, value in (params or {}).items():
        if isinstance(value, (list, tuple, set)):
            kept = [v for v in value
                    if not (isinstance(v, str) and v.lower() in gone)]
            dropped = [v for v in value if isinstance(v, str) and v.lower() in gone]
            if dropped:
                removed.extend(str(d) for d in dropped)
                clean[key] = kept
            else:
                clean[key] = value
        elif isinstance(value, str) and value.lower() in gone:
            removed.append(value)
        else:
            clean[key] = value
    return clean, sorted(set(removed))


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
            # An elapsed TTL is not a decision of its own: the decision space is frozen at
            # allow|deny|redact|human|revoked, so the refusal is a deny and the *reason*
            # carries the state. A consumer reading the contract sees a deny with
            # ``warrant_state: expired``, which is exactly what happened.
            return (Decision.deny,
                    f"warrant {warrant.id} TTL elapsed · order expired, no action",
                    {"warrant": warrant.id, "warrant_state": "expired"})

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

        if rule.redact:
            fields = params.get(rule.redact[0])
            detail["fields"] = fields
            hits = _pii(fields)
            if hits:
                # The act is authorised, the data is not: strip the fields and let the
                # read run. Recorded as its own decision so the chain shows what was
                # removed, not merely that something was.
                return (Decision.redact,
                        f"{reason} · personal fields stripped before execution: {', '.join(hits)}",
                        {**detail, "redacted": hits})

        return rule.effect, reason, detail
