"""Gate 30: what does the order allow.

The policy engine decides on the order, and the class floor is applied on top: a class can
only raise what the order allows, never talk it back down.
"""
from ..actions import apply_class
from ..gates import Gate, GateContext, Outcome, register


def _check(ctx: GateContext) -> Outcome:
    decision, reason, detail = ctx.engine.evaluate(ctx.warrant, ctx.tool, ctx.params)
    decision, class_note, class_detail = apply_class(decision, ctx.cls, ctx.params)
    detail = {**detail, **class_detail}
    if class_note:
        reason = class_note if not reason else f"{reason} · {class_note}"
    else:
        reason = f"{reason} · class {ctx.cls.value}"
    return decision, reason, detail


register(Gate("order_policy", _check, order=30))
