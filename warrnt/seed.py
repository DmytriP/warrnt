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
        scope="crm.read · export=false · no PII fields", ttl=420.0,
        rules=[
            Rule(tool="crm.read", effect="allow", reason="read-only · in scope"),
            Rule(tool="crm.bulk_export", effect="deny", reason="export=false · no PII fields in warrant scope",
                 inspect_pii=["fields"]),
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
