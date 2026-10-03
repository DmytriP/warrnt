"""Break-glass: one named person's short permission to lift a *policy* human pause.

Where the line runs, and why it does not move
---------------------------------------------
The taxonomy (``actions.py``) says who holds a decision. That ladder is the product: an
``irreversible`` act is a person's act, and a machine never gets to make it. Break-glass does
**not** touch the ladder. What it can open is the other kind of ``human``: the one a *rule*
asks for ("deploy requires human authority"), where the class itself would let the machine
decide. A policy pause is exactly the thing an operator may decline to wait for.

So the node answers three questions before a grant exists at all:

  * is the act's class below ``human`` on the ladder? (else: not liftable, ever)
  * is the person named, and is the reason written down? (no anonymous switch)
  * is the window short? (hard cap ``MAX_TTL_S``; the clock is the expiry)

And after it is used, the grant leaves a debt: the next grant for the same agent is refused
until a post-mortem is recorded. A bypass that must be reviewed is an operating procedure; a
bypass that never is, is a hole.

Everything here is a state change on an append-only chain: the grant, its use (in the
executed call's receipt, which carries the grant id) and the post-mortem all land in the same
hash chain as the refusals. The grant is signed by the issuer key, so editing its fields -
widening the tool it covers, extending the window - invalidates it, exactly like a warrant.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from .models import BreakGlassGrant, Decision
from .canonical import canon

#: Hard cap on any grant. Fifteen minutes: long enough for an operator to come to the
#: keyboard, short enough that nobody forgets it is open.
MAX_TTL_S = 900.0

#: Classes whose own floor is already "a person decides". A grant must never reach them:
#: the taxonomy is the line the product is sold on, and a bypass around it would be a
#: different product. ``authorize`` is here too - a grant may not rewrite the rules.
UNLIFTABLE = ("irreversible", "authorize")


class BreakGlassRefused(Exception):
    """Raised with the sentence the operator gets. The reason is the whole point."""


class BreakGlassRegistry:
    def __init__(self, sign: Callable[[dict], str], now: Callable[[], float],
                 registry: Any = None) -> None:
        self._sign = sign
        self._now = now
        self.registry = registry
        self.grants: dict[str, BreakGlassGrant] = {}
        self._seq = 0

    # ------------------------------------------------------------------ grant
    def grant(self, *, human: str, agent: str, tool: str, reason: str, cls: str,
              ttl_s: float = MAX_TTL_S, enforce_postmortem: bool = True) -> BreakGlassGrant:
        """Issue a signed grant. Refuses anything wider than the line allows."""
        human, reason, agent, tool = (human or "").strip(), (reason or "").strip(), \
            (agent or "").strip(), (tool or "").strip()
        if not human:
            raise BreakGlassRefused("a grant names the person who gives it · no anonymous switch")
        if not reason:
            raise BreakGlassRefused("a grant carries its reason · an unexplained bypass is a hole")
        if not agent or not tool:
            raise BreakGlassRefused("a grant covers one agent and one tool · no wildcard scope")
        if cls in UNLIFTABLE:
            raise BreakGlassRefused(
                f"class {cls} is the taxonomy's own floor · a person decides it, no grant lifts it")
        if ttl_s <= 0 or ttl_s > MAX_TTL_S:
            raise BreakGlassRefused(
                f"the window must be 0 < ttl ≤ {int(MAX_TTL_S)}s · a standing bypass is not a grant")
        if enforce_postmortem:
            owed = self.pending_postmortem(agent)
            if owed:
                raise BreakGlassRefused(
                    f"agent {agent} still owes a post-mortem for {owed[0].id} "
                    f"(used by {owed[0].used_by} at {owed[0].used_at}) · review before you re-open")

        self._seq += 1
        now = self._now()
        grant = BreakGlassGrant(
            id=f"BG-{self._seq:04d}", human=human, agent=agent, tool=tool, reason=reason,
            cls=cls, issued=now, expires=now + float(ttl_s), sig="",
        )
        grant.sig = self._sign(grant.payload())
        self.grants[grant.id] = grant
        self._receipt(grant,
                      f"break-glass {grant.id} · {int(ttl_s)}s · {agent} → {tool} · "
                      f"by {human}: {reason}")
        return grant

    # ------------------------------------------------------------------- use
    def active(self, agent: str, tool: str, cls: str) -> Optional[BreakGlassGrant]:
        """The grant, if one genuinely covers this call right now.

        Fail closed on every axis: the signature must verify, the class must be liftable, the
        window must be open, and the grant must not already have been spent.
        """
        if cls in UNLIFTABLE:
            return None
        now = self._now()
        for grant in self.grants.values():
            if grant.state != "active" or grant.agent != agent or grant.tool != tool:
                continue
            if grant.cls in UNLIFTABLE or grant.cls != cls:
                continue
            if grant.remaining(now) <= 0:
                continue
            try:
                if grant.sig != self._sign(grant.payload()):
                    continue
            except Exception:
                continue
            return grant
        return None

    def remaining_s(self, grant: BreakGlassGrant) -> float:
        return grant.remaining(self._now())

    def consume(self, grant_id: str, by_tool: str) -> Optional[BreakGlassGrant]:
        """A grant is single-use: the first call it lifts spends it."""
        grant = self.grants.get(grant_id)
        if grant is None or grant.state != "active":
            return None
        grant.state = "used"
        grant.used_at = self._now()
        grant.used_by = by_tool
        return grant

    def revoke(self, grant_id: str) -> Optional[BreakGlassGrant]:
        grant = self.grants.get(grant_id)
        if grant is None or grant.state != "active":
            return None
        grant.state = "revoked"
        self._receipt(grant, f"break-glass {grant.id} closed early by the operator")
        return grant

    # -------------------------------------------------------------- review
    def pending_postmortem(self, agent: str | None = None) -> list[BreakGlassGrant]:
        return [g for g in self.grants.values()
                if g.state == "used" and g.postmortem is None
                and (agent is None or g.agent == agent)]

    def postmortem(self, grant_id: str, note: str) -> BreakGlassGrant:
        grant = self.grants.get(grant_id)
        if grant is None:
            raise BreakGlassRefused(f"unknown grant {grant_id}")
        if grant.state != "used":
            raise BreakGlassRefused(
                f"grant {grant_id} is {grant.state} · a post-mortem is owed only after a use")
        note = (note or "").strip()
        if not note:
            raise BreakGlassRefused("a post-mortem says something · an empty note closes nothing")
        grant.postmortem = note
        grant.postmortem_at = self._now()
        self._receipt(grant, f"post-mortem {grant.id} owed by review: {note}")
        return grant

    # -------------------------------------------------------------- views
    def effective_state(self, grant: BreakGlassGrant) -> str:
        if grant.state == "active" and grant.remaining(self._now()) <= 0:
            return "expired"
        return grant.state

    def listing(self) -> list[dict[str, Any]]:
        now = self._now()
        rows = []
        for grant in sorted(self.grants.values(), key=lambda g: g.id):
            rows.append({
                "id": grant.id, "human": grant.human, "agent": grant.agent, "tool": grant.tool,
                "class": grant.cls, "reason": grant.reason,
                "state": self.effective_state(grant),
                "remaining_s": int(round(grant.remaining(now))) if grant.state == "active" else 0,
                "ttl_s": int(round(grant.expires - grant.issued)),
                "sig": grant.sig[:16], "sig_ok": grant.sig == self._sign(grant.payload()),
                "used_by": grant.used_by, "postmortem": grant.postmortem,
            })
        return rows

    def snapshot(self) -> dict[str, Any]:
        return {"grants": self.listing(),
                "max_ttl_s": int(MAX_TTL_S),
                "unliftable": list(UNLIFTABLE),
                "postmortem_required": [g.id for g in self.pending_postmortem()]}

    # -------------------------------------------------------------- chain
    def _receipt(self, grant: BreakGlassGrant, reason: str) -> None:
        if self.registry is None:
            return
        self.registry.append(
            t=__import__("time").strftime("%H:%M:%S"), decision=Decision.allow.value,
            agent=grant.agent, tool="/break-glass", warrant="—", reason=reason,
            params="", rows_after=0, ts=self._now(), grant=grant.id,
        )
