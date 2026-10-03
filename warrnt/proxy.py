"""The node: identity -> actor class -> order -> policy on parameters -> brake -> receipt.

:class:`MCPProxy` is the single object that decides. Everything the HTTP layer does is
translate a request into a call here and serialise the answer.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from . import gates as gate_registry
from .breakglass import BreakGlassRegistry
from .gates import GateContext
from .actions import listing as class_listing
from .actors import ACTOR_SEED, ActorProfile, ActorRegistry
from .models import AgentState, Decision, DECISION_TEXT, Warrant
from .policy import PolicyEngine, strip_pii
from .registry import AppendOnlyRegistry
from .seed import SEED_SPECS
from .upstream import ExecutionCounter, build_upstream
from .warrants import WarrantIssuer, refresh_state, remaining


def _clock() -> str:
    return time.strftime("%H:%M:%S")


def _receipt_row(entry: dict) -> dict[str, Any]:
    """Console-shaped view of a receipt: a screen can render it without knowing the schema."""
    decision = entry.get("decision")
    text = DECISION_TEXT[Decision(decision)] if decision in Decision._value2member_map_ else decision
    return {
        "t": entry.get("t"), "decision": decision, "agent": entry.get("agent"),
        "tool": entry.get("tool"), "warrant": entry.get("warrant"),
        "reason": entry.get("reason"), "hash": entry["hash"][:8],
        "what": f"<code>{entry.get('tool')}</code> {entry.get('agent')} → {text}",
        "meta": f"order {entry.get('warrant')} · {entry.get('reason')}",
    }


class MCPProxy:
    def __init__(self, issuer: WarrantIssuer, registry: AppendOnlyRegistry,
                 engine: Optional[PolicyEngine] = None, upstream=None,
                 now=None, actors: Optional[list[ActorProfile]] = None):
        self.issuer = issuer
        self.registry = registry
        self.engine = engine or PolicyEngine()
        # The register of actor classes. It answers the question the warrant cannot: may
        # this kind of actor call this tool at all, whatever the user's rights are.
        self.actors = ActorRegistry(actors if actors is not None else list(ACTOR_SEED))
        self.counter = ExecutionCounter()
        self.upstream = upstream or build_upstream(self.counter)
        # The kernel loads its gates from the plugin package and never names one itself:
        # adding a gate is adding a file under warrnt/plugins/, not editing this module.
        gate_registry.load()
        self._now = now or time.time
        # Break-glass: the one thing that can lower a *policy* pause, and only that. It is
        # signed with the same key as an order, it is single-use, and it owes a review.
        self.breakglass = BreakGlassRegistry(sign=self.issuer.sign, now=self._now,
                                             registry=self.registry)
        self.agents: dict[str, AgentState] = {}
        self.warrants: dict[str, Warrant] = {}
        self.anchor: Any = None
        # stats["revoked"]  - orders pulled by the operator (known the moment /revoke lands)
        # stats["last_stop"] - seconds from that pull to the node refusing the agent's next
        #                      outbound call; None until a stopped agent actually tries again
        self.stats: dict[str, Any] = {"revoked": 0, "last_stop": None, "stopped_agent": None}
        self._revoke_t0: dict[str, float] = {}

    # ------------------------------------------------------------------- seed
    def issue_all(self, reset_registry: bool = True) -> None:
        self.agents.clear()
        self.warrants.clear()
        if reset_registry:
            self.registry.reset()
        for spec in SEED_SPECS:
            warrant = self.issuer.issue(spec)
            self.warrants[warrant.id] = warrant
            self.agents[warrant.agent] = AgentState(
                id=warrant.agent, role=warrant.role, warrant=warrant.id,
                token=self.issuer.token_for(warrant.agent, warrant.id),
            )
        self.stats = {"revoked": 0, "last_stop": None, "stopped_agent": None}
        self._revoke_t0 = {}
        self.counter.clear()
        # A reset re-issues the orders; an open bypass must not survive it.
        self.breakglass.grants.clear()
        self.breakglass._seq = 0

    # -------------------------------------------------------------- interception
    def intercept(self, agent_id: str, token: str, tool: str,
                  params: dict[str, Any] | None) -> tuple[Decision, str, dict[str, Any], dict, bool]:
        """Return ``(decision, reason, detail, receipt, executed)``.

        ``executed`` is True only when the upstream was actually invoked - the proof that a
        deny leaves the perimeter untouched.
        """
        agent = self.agents.get(agent_id)
        if agent is None or agent.token != token:
            self._receipt(Decision.deny, agent_id or "<anonymous>", tool, "-",
                          f"unknown agent identity or bad token", params)
            return Decision.deny, "unknown agent identity or bad token", {}, {}, False

        warrant = self.warrants.get(agent.warrant)
        if warrant is not None and warrant.agent != agent_id:
            # Identity is scoped: a token minted for one agent never authorises another's
            # warrant, even if both are held by the same node.
            decision, reason = Decision.deny, "identity/warrant binding mismatch · token not scoped to this order"
            detail = {"warrant": agent.warrant, "agent": agent_id}
        elif agent.state == "halted":
            decision, reason = Decision.revoked, f"agent halted · warrant {agent.warrant} pulled"
            detail = {"warrant": agent.warrant}
        else:
            # The chains live in the registry, not here: the kernel only asks. The gates
            # read in the order a person would ask them - what kind of act is this
            # (act_class), who is standing at the gate (actor_scope), what does the order
            # allow (order_policy) - and a class can only raise what follows it.
            ctx = GateContext(agent_id=agent_id, agent=agent, warrant=warrant, tool=tool,
                              params=params or {}, actors=self.actors, engine=self.engine,
                              breakglass=self.breakglass)
            decision, reason, detail = gate_registry.run(ctx)
            if detail.get("break_glass"):
                # A grant is single-use: the call it lifted has just spent it. The receipt
                # below carries the grant id, so the chain shows who opened the door and when.
                self.breakglass.consume(detail["break_glass"], tool)

        agent.last = f"{tool} · {DECISION_TEXT.get(decision, decision.value)}"
        receipt = self._receipt(decision, agent_id, tool, agent.warrant, reason, params,
                                detail=detail)

        if decision is Decision.revoked:
            # The halted agent just tried to act again: this receipt *is* the observation.
            # Measure it here so the console can show a real time-to-stop without the client
            # having to report anything back.
            self._note_stop(agent_id)

        if decision is not Decision.allow and decision is not Decision.redact:
            return decision, reason, {**detail, "receipt": receipt["hash"][:8],
                                      "rows_after": 0}, receipt, False

        # Exactly two decisions execute: allow, and redact - where the personal fields the
        # rule names are taken out of the payload *before* the upstream is called, so the
        # upstream never sees them. The removal is part of the record, not a silent edit.
        exec_params = params or {}
        if decision is Decision.redact:
            exec_params, removed = strip_pii(params, detail.get("redacted") or [])
            detail = {**detail, "redacted": removed, "upstream_params": exec_params}

        result = self.upstream.call(tool, exec_params)   # executed ONLY here
        receipt2 = self.registry.append(
            t=_clock(), decision=decision.value, agent=agent_id, tool=tool,
            warrant=agent.warrant,
            reason=reason, params="", rows_after=result["rows"], ts=self._now(),
            exec_hash=receipt["hash"],
        )
        return (decision, reason,
                {**detail, "receipt": receipt2["hash"][:8], "rows_after": result["rows"],
                 "result": result}, receipt2, True)

    # ------------------------------------------------------------------- brake
    def revoke(self, agent_id: str) -> Optional[float]:
        """Pull the warrant and halt the agent chain. Returns the revoke timestamp."""
        agent = self.agents.get(agent_id)
        if agent is None or agent.state == "halted":
            return None
        t0 = self._now()
        agent.state = "halted"
        warrant = self.warrants.get(agent.warrant)
        if warrant:
            warrant.state = "revoked"
            warrant.revoked_at = t0
        self.registry.append(
            t=_clock(), decision=Decision.revoked.value, agent=agent_id, tool="/revoke",
            warrant=agent.warrant, reason="warrant pulled by operator",
            params="", rows_after=0, ts=t0,
        )
        agent.last = "chain stopped · warrant revoked"
        self.stats["revoked"] += 1
        self._revoke_t0[agent_id] = t0
        return t0

    def _note_stop(self, agent_id: str) -> Optional[float]:
        """Record time-to-stop the first time a halted agent is refused after the pull.

        Silent by design: the refusal receipt is already in the chain, so the latency needs
        no line of its own. Idempotent per agent - a stopped agent that keeps retrying must
        not keep moving the number.
        """
        t0 = self._revoke_t0.get(agent_id)
        if t0 is None or self.stats.get("stopped_agent") == agent_id:
            return self.stats.get("last_stop")
        latency = max(0.0, self._now() - t0)
        self.stats["last_stop"] = latency
        self.stats["stopped_agent"] = agent_id
        return latency

    def observe_stop(self, agent_id: str, observed: float | None = None) -> Optional[float]:
        """Called when the running agent itself notices the revocation. Measures latency."""
        agent = self.agents.get(agent_id)
        t0 = self._revoke_t0.get(agent_id)
        if agent is None or t0 is None or self.stats.get("stopped_agent") == agent_id:
            return None
        latency = max(0.0, (observed or self._now()) - t0)
        self.stats["last_stop"] = latency
        self.stats["stopped_agent"] = agent_id
        self.registry.append(
            t=_clock(), decision=Decision.revoked.value, agent=agent_id, tool="agent-loop",
            warrant=agent.warrant, reason="stop observed on next outbound call",
            params="", rows_after=0, ts=observed or self._now(),
        )
        return latency

    # ------------------------------------------------------------------ helpers
    def _receipt(self, decision: Decision, agent: str, tool: str, warrant: str,
                 reason: str, params: dict[str, Any] | None,
                 detail: dict[str, Any] | None = None) -> dict:
        import json

        return self.registry.append(
            t=_clock(), decision=decision.value, agent=agent, tool=tool, warrant=warrant,
            reason=reason,
            params=json.dumps(params or {}, sort_keys=True, ensure_ascii=False)[:400],
            rows_after=0, ts=self._now(),
        )

    # ------------------------------------------------------------------- state
    def state(self, limit: int = 60) -> dict[str, Any]:
        agents, warrants = [], []
        for agent in self.agents.values():
            warrant = self.warrants.get(agent.warrant)
            agents.append({
                "id": agent.id, "role": agent.role, "state": agent.state,
                "warrant": agent.warrant, "last": agent.last,
                "ttl": int(round(remaining(warrant, self._now()))) if warrant else 0,
                "ttl0": warrant.ttl if warrant else 0,
            })
        for warrant in self.warrants.values():
            warrants.append({
                "id": warrant.id, "agent": warrant.agent, "scope": warrant.scope,
                "ttl": int(round(remaining(warrant, self._now()))), "ttl0": warrant.ttl,
                "state": refresh_state(warrant, self._now()),
                "sig": warrant.sig[:16], "sig_ok": self.issuer.signature_ok(warrant),
            })
        receipts = [_receipt_row(e) for e in self.registry.recent(limit)]
        return {
            "revoked": self.stats["revoked"], "last_stop": self.stats["last_stop"],
            "agents": agents, "warrants": warrants, "receipts": receipts,
            "actors": self.actors.listing(),
            "actions": class_listing(),
            "executor_calls": self.counter.snapshot(), "chain": self.registry.verify(),
            "breakglass": self.breakglass.snapshot(),
        }
