"""Gate 25: is there a break-glass grant open for *this* call?

The gate never decides. It looks up whether a genuinely live grant covers this
(agent, tool, class) - signature verified, window open, not yet spent - and puts it in
``ctx.extra`` for the gate that does decide. Keeping the lookup here has two effects: the
decision stays in one place (order_policy), and a grant can be listed on the console without
being able to make anything happen by itself.
"""
from __future__ import annotations

from ..gates import Gate, GateContext, Outcome, register


def _check(ctx: GateContext) -> Outcome:
    if ctx.breakglass is None or ctx.cls is None:
        return None
    grant = ctx.breakglass.active(ctx.agent_id, ctx.tool, ctx.cls.value)
    if grant is not None:
        ctx.extra["breakglass"] = grant
        ctx.extra["breakglass_left_s"] = int(round(ctx.breakglass.remaining_s(grant)))
    return None


register(Gate("break_glass", _check, order=25))
