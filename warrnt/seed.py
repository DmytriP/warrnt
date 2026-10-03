"""Seed warrants - the three agents of the demo vector.

Declared in code on purpose: this scaffold has no admin UI and no multi-tenant issuer
(that is a platform, and this is one node). Editing this list is how you change policy.
"""
from __future__ import annotations

from .models import Guard, Rule, WarrantSpec

SEED_SPECS: list[WarrantSpec] = [
    WarrantSpec(
        id="W-4417", agent="fin-reconcile", role="Finance",
        scope="payments.read · ≤ 50,000 PLN · read-only", ttl=900.0,
        rules=[
            Rule(tool="payments.read", effect="allow", reason="read-only · in scope"),
            Rule(
                tool="payments.transfer", effect="allow", reason="within 50,000 PLN limit",
                guards=[Guard(param="amount_pln", op="le", value=50000, fail="deny",
                              reason="amount_pln={v} exceeds warrant limit 50,000 PLN")],
            ),
        ],
    ),
    WarrantSpec(
        id="W-4419", agent="support-copilot", role="Support",
        scope="crm.read · export=false · personal fields stripped", ttl=420.0,
        rules=[
            # A read that names a personal field is authorised but stripped: the copilot
            # still answers the ticket, the PII never reaches it (decision ``redact``).
            Rule(tool="crm.read", effect="allow", reason="read-only · in scope · PII stripped",
                 redact=["fields"]),
            Rule(tool="crm.bulk_export", effect="deny", reason="export=false · no PII fields in warrant scope",
                 inspect_pii=["fields"]),
        ],
    ),
    # The fourth agent exists for one reason: to show what break-glass is *for*. A mass
    # export is a policy pause - the class itself (read_personal) would let the node decide,
    # and the order says a person decides instead. That is the pause a named operator may
    # open for fifteen minutes. ``infra.deploy`` above stays a person's act with no way round.
    WarrantSpec(
        id="W-4423", agent="report-bot", role="Analytics",
        scope="crm.bulk_export ⇒ require-human · break-glass ≤ 15 min", ttl=1800.0,
        rules=[
            Rule(tool="crm.bulk_export", effect="human",
                 reason="a mass export is a person's decision, not a schedule's"),
        ],
    ),
    WarrantSpec(
        id="W-4421", agent="deploy-agent", role="Platform",
        scope="infra.plan · deploy ⇒ require-human", ttl=150.0,
        rules=[
            Rule(tool="infra.plan", effect="allow", reason="read-only · in scope"),
            Rule(tool="infra.deploy", effect="human", reason="deploy requires human authority"),
        ],
    ),
]
