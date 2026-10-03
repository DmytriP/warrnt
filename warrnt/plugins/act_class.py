"""Gate 10: what kind of act is this?

Fills ``ctx.cls`` for the gates after it. When the tool is not in the catalogue the act has
no class, and the node answers with the classless allow it always did.
"""
from ..actions import apply_class, classify
from ..gates import Gate, GateContext, Outcome, register
from ..models import Decision


def _check(ctx: GateContext) -> Outcome:
    cls = classify(ctx.tool, ctx.params)
    ctx.cls = cls
    if cls is None:
        return apply_class(Decision.allow, None, ctx.params)
    return None


register(Gate("act_class", _check, order=10))
