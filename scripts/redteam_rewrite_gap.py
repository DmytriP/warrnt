#!/usr/bin/env python3
"""Red-team the receipt layer: the M1 attack against a bare chain, and the anchor that stops it.

The old gap: anyone with write access to ``receipts.jsonl`` can recompute every hash from
genesis, turn a 'deny' into an 'allow', and ``verify()`` goes green again - the log is
tamper-EVIDENT, not tamper-PROOF. The head anchor (warrnt/anchor.py) seals the head with the
issuer key on every append, so the forged head no longer matches what was signed.

Run after scripts/security_boundaries.py has produced a state dir:

    python3 scripts/redteam_rewrite_gap.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warrnt.anchor import HeadAnchor  # noqa: E402
from warrnt.canonical import canon  # noqa: E402
from warrnt.registry import AppendOnlyRegistry  # noqa: E402
from warrnt.warrants import WarrantIssuer  # noqa: E402

HOME = ROOT / "state" / "sec-d2"


def forge(entries):
    """Rebuild the whole chain with every 'deny' turned into an 'allow'."""
    prev = AppendOnlyRegistry.GENESIS
    out = []
    for entry in entries:
        body = {k: v for k, v in entry.items() if k != "hash"}
        if body.get("decision") == "deny":
            body["decision"] = "allow"
            body["reason"] = "within warrant scope"
        body["prev"] = prev
        body["hash"] = hashlib.sha256((prev + canon(body)).encode()).hexdigest()
        prev = body["hash"]
        out.append(body)
    return out


def main() -> int:
    live = HOME / "receipts.jsonl"
    anchors = HOME / "anchors.jsonl"
    if not live.exists() or not anchors.exists():
        print(f"SKIP  run scripts/security_boundaries.py first (need {HOME})")
        return 0

    reg = AppendOnlyRegistry(str(live))
    honest = AppendOnlyRegistry(str(live)).verify()
    print(f"live registry : {len(reg.entries)} entries, honest verify={honest['ok']}")

    forged = forge(reg.entries)
    forged_path = HOME / "forged-rewrite.jsonl"
    forged_path.write_text("\n".join(canon(e) for e in forged) + "\n", encoding="utf-8")
    bare = AppendOnlyRegistry(str(forged_path)).verify()
    print(f"ATTACK (bare chain) : verify={bare['ok']}  <- the log alone is fooled")

    issuer = WarrantIssuer.from_env_or_file(str(HOME / "issuer.key"))
    anchor = HeadAnchor(str(anchors), issuer.sign)
    v = anchor.verify(forged[-1]["hash"], len(forged))
    print(f"DEFENCE (anchor)    : {v}")
    honest_v = anchor.verify(reg.entries[-1]["hash"], len(reg.entries))
    print(f"honest head         : {honest_v}")

    if bare["ok"] and v["ok"] is False and v["signed"] is True and honest_v["ok"] is True:
        print("\nRESULT  the bare chain is fooled; the anchored node is not.")
        print("        To hide the rewrite an attacker must also forge the anchor signature,")
        print("        which needs the issuer key they do not hold.")
        return 0
    print("\nUNEXPECTED  re-check the anchor wiring.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
