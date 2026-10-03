"""Gate 30: what does the order allow.

The policy engine decides on the order, and the class floor is applied on top: a class can
only raise what the order allows, never talk it back down.

One thing can lower a *policy* pause, and only one: a break-glass grant that gate 25 found
alive. It is deliberately narrow - the grant never reaches the class floor (gate 25 refuses
to return one for ``irreversible``/``authorize``), so what it opens is the ``human`` a *rule*
asked for, never the ``human`` the taxonomy demands. The lift names the person and the grant
in the reason, so the receipt carries who opened it.
"""
from ..actions import apply_class
from ..gates import Gate, GateContext, Outcome, register
from ..models import Decision


def _check(ctx: GateContext) -> Outcome:
    decision, reason, detail = ctx.engine.evaluate(ctx.warrant, ctx.tool, ctx.params)
    decision, class_note, class_detail = apply_class(decision, ctx.cls, ctx.params)
    detail = {**detail, **class_detail}
    if class_note:
        reason = class_note if not reason else f"{reason} · {class_note}"
    else:
        reason = f"{reason} · class {ctx.cls.value}"

    grant = ctx.extra.get("breakglass")
    if grant is not None and decision is Decision.human:
        left = ctx.extra.get("breakglass_left_s", 0)
        decision = Decision.allow
        reason = (f"break-glass {grant.id} by {grant.human} · {left}s left · single use · "
                  f"the policy pause is opened, the class floor is not")
        detail = {**detail, "break_glass": grant.id, "break_glass_by": grant.human,
                  "break_glass_reason": grant.reason, "break_glass_left_s": left}

    return decision, reason, detail


register(Gate("order_policy", _check, order=30))
