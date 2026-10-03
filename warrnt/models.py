"""Wire and domain models.

The vocabulary is the product: a *warrant* is a signed order (scope + TTL + signature),
a *guard* is a condition on a parameter of the call itself, and a *receipt* is the
append-only record of a decision.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Decision(str, Enum):
    """The frozen decision space: allow | deny | redact | human | revoked.

    ``expired`` is **not** a decision - it is a warrant state (``state`` below). An order
    whose TTL elapsed is refused as ``deny`` with ``warrant_state: expired``, because the
    decision answers "did this call run", and an expired order is simply refused.
    """

    allow = "allow"
    deny = "deny"            # refused before execution
    redact = "redact"        # executed, with the personal fields stripped out first
    human = "human"          # require-human: pause, do not execute
    revoked = "revoked"      # warrant pulled / agent halted


DECISION_TEXT = {
    Decision.allow: "ALLOW",
    Decision.deny: "DENY before execution",
    Decision.redact: "REDACT — executed, personal fields stripped",
    Decision.human: "REQUIRE-HUMAN",
    Decision.revoked: "REVOKED",
}


class Guard(BaseModel):
    """A condition evaluated against the parameters of the call, pre-execution."""

    param: str
    op: str = "le"                     # le | ge | eq | ne
    value: Any = None
    fail: Decision = Decision.deny     # decision when the guard does not hold
    reason: str = "{param}={v} violates policy"


class Rule(BaseModel):
    """One tool covered (or fenced) by a warrant."""

    tool: str
    effect: Decision = Decision.allow
    reason: str = ""
    guards: list[Guard] = Field(default_factory=list)
    # names of params that carry a list of fields; if any is PII the rule fires
    inspect_pii: list[str] = Field(default_factory=list)
    # names of params that carry a list of fields; PII found there is *stripped* and the
    # call still runs (decision ``redact``). The distinction from ``inspect_pii`` is the
    # whole point: one refuses the act, the other lets the act happen without the data.
    redact: list[str] = Field(default_factory=list)


class WarrantSpec(BaseModel):
    """What an issuer asks for; the signed artifact is :class:`Warrant`."""

    id: str
    agent: str
    role: str
    scope: str
    ttl: float
    rules: list[Rule]
    issuer: str = "risk-office"
    # ACT-2 §1: the human this order is issued to serve, and the party that human acts for.
    # A warrant is a delegation, so it names both ends: the agent that will act and the
    # person whose act it is. Empty means "not recorded" - never a guessed identity.
    principal: str = ""
    on_behalf_of: str = ""


class Warrant(BaseModel):
    """A signed order. ``sig`` is HMAC-SHA256 over ``canon(payload())``.

    Not a metaphor: mutate any field of ``payload()`` and ``signature_ok`` turns False.
    """

    id: str
    agent: str
    role: str
    scope: str
    ttl: float
    rules: list[Rule]
    issuer: str
    issued: float
    principal: str = ""
    on_behalf_of: str = ""
    sig: str = ""
    state: str = "active"                    # active | revoked | expired
    revoked_at: Optional[float] = None

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent": self.agent,
            "role": self.role,
            "scope": self.scope,
            "ttl": self.ttl,
            "rules": [r.model_dump(mode="json") for r in self.rules],
            "issuer": self.issuer,
            "issued": self.issued,
            # The delegation is part of the grant: change who the order is for and the
            # signature stops matching, exactly as for the scope it carries.
            "principal": self.principal,
            "on_behalf_of": self.on_behalf_of,
        }

    def arity(self) -> str:
        """Short one-line scope, for logs and the console."""
        return f"{self.id} {self.scope}"


class AgentState(BaseModel):
    id: str
    role: str
    warrant: str
    token: str
    state: str = "active"                    # active | halted
    last: str = "warrant issued · idle"
    # ACT-2 §1/§2: who this agent acts for, on whose behalf, and what its order actually
    # grants it. ``entitlements`` are the tools the warrant covers - a warrant is not a
    # grant of data, so this is the authority the entitlement gate checks against.
    principal: str = ""
    on_behalf_of: str = ""
    entitlements: list[str] = Field(default_factory=list)
    scope: list[str] = Field(default_factory=list)


class BreakGlassGrant(BaseModel):
    """A named person's time-boxed permission to lift a *policy* ``human`` pause.

    Signed like a warrant, because it is one in miniature: it names one person, one agent,
    one tool and one reason, and it stops existing on the clock. It cannot touch the class
    taxonomy - an ``irreversible`` act is a person's act, and no grant makes it a machine's.
    """

    id: str
    human: str                              # the person who gave it, by name
    agent: str
    tool: str
    reason: str
    cls: str
    issued: float
    expires: float
    sig: str = ""
    state: str = "active"                   # active | used | revoked
    used_at: Optional[float] = None
    used_by: Optional[str] = None
    postmortem: Optional[str] = None
    postmortem_at: Optional[float] = None

    def payload(self) -> dict[str, Any]:
        """What the signature covers: the grant itself, not its lifecycle."""
        return {"id": self.id, "human": self.human, "agent": self.agent, "tool": self.tool,
                "reason": self.reason, "cls": self.cls, "issued": self.issued,
                "expires": self.expires}

    def remaining(self, now: float) -> float:
        return max(0.0, self.expires - now)


class Receipt(BaseModel):
    """One line of the append-only registry. ``hash = sha256(prev + canon(body))``."""

    model_config = {"extra": "allow"}
    prev: str
    hash: str
