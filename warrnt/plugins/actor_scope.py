"""Gate 20: who is standing at the gate.

The actor profile can refuse a tool outright (``this agent cannot``) before the order is
consulted - a person reads their own scope before their permit.
"""
from ..gates import Gate, GateContext, Outcome, register


def _check(ctx: GateContext) -> Outcome:
    block = ctx.actors.check(ctx.agent_id, ctx.tool, ctx.params)
    if block is None:
        return None
    decision, reason, detail = block
    return decision, f"{reason} · class {ctx.cls.value}", {**detail, "class": ctx.cls.value}


register(Gate("actor_scope", _check, order=20))
