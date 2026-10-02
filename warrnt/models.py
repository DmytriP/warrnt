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
    allow = "allow"
    deny = "deny"
    human = "human"          # require-human: pause, do not execute
    revoked = "revoked"      # warrant pulled / agent halted
    expired = "expired"      # TTL elapsed


DECISION_TEXT = {
    Decision.allow: "ALLOW",
    Decision.deny: "DENY before execution",
    Decision.human: "REQUIRE-HUMAN",
    Decision.revoked: "REVOKED",
    Decision.expired: "EXPIRED",
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


class WarrantSpec(BaseModel):
    """What an issuer asks for; the signed artifact is :class:`Warrant`."""

    id: str
    agent: str
    role: str
    scope: str
    ttl: float
    rules: list[Rule]
    issuer: str = "risk-office"


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


class Receipt(BaseModel):
    """One line of the append-only registry. ``hash = sha256(prev + canon(body))``."""

    model_config = {"extra": "allow"}
    prev: str
    hash: str
