#!/usr/bin/env python3
"""Honest red-team probe: what the journal does NOT protect against.

The hash chain detects an *edit* or a *deletion* inside the log. It does not, by itself,
detect a wholesale rewrite: an attacker with filesystem write access can recompute every
hash from genesis and the chain will verify again. This script proves that boundary on the
real registry file so we state it as a known limitation (and a fix) instead of hiding it.

    python3 scripts/redteam_rewrite_gap.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warrnt.canonical import canon  # noqa: E402
from warrnt.registry import AppendOnlyRegistry  # noqa: E402


def main() -> int:
    live = ROOT / "state" / "sec-d2" / "receipts.jsonl"
    if not live.exists():
        print(f"SKIP  no live registry at {live} - run scripts/security_boundaries.py first")
        return 0

    original = AppendOnlyRegistry(str(live))
    print(f"live registry: {len(original.entries)} entries, verify={original.verify()['ok']}")

    # Rewrite every entry from genesis, inflating one decision to 'allow'.
    prev = AppendOnlyRegistry.GENESIS
    rewritten = []
    for entry in original.entries:
        body = {k: v for k, v in entry.items() if k != "hash"}
        if body.get("decision") == "deny":
            body["decision"] = "allow"          # the forgery
            body["reason"] = "within warrant scope"
        body["prev"] = prev
        body["hash"] = hashlib.sha256((prev + canon(body)).encode()).hexdigest()
        prev = body["hash"]
        rewritten.append(body)

    forged = ROOT / "state" / "sec-d2" / "forged-rewrite.jsonl"
    forged.write_text("\n".join(canon(e) for e in rewritten) + "\n", encoding="utf-8")
    verdict = AppendOnlyRegistry(str(forged)).verify()

    print(f"forged copy: verify={verdict}")
    if verdict["ok"]:
        print("FINDING  a consistent rewrite from genesis passes verify() -> the log is")
        print("         tamper-EVIDENT, not tamper-PROOF without an external anchor.")
        print("FIX      anchor the head hash outside the node (append to a WORM store, publish")
        print("         the head on every N receipts, or sign the head with an offline key).")
        return 0
    print("UNEXPECTED  the rewrite was caught - re-check the chain construction.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
