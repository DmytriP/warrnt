"""Head anchor - closes the "consistent rewrite from genesis" gap (finding M1, task D2).

A hash chain detects an edit or a deletion inside the log, but not a wholesale rewrite:
anyone with write access to ``receipts.jsonl`` can recompute every hash from genesis and
``verify()`` goes green again (see scripts/redteam_rewrite_gap.py).

The anchor removes that ability. After every append the node signs the current head with
the issuer key (HMAC-SHA256, the same key the orders are signed with - never written into a
receipt) and appends ``{head, length, ts, sig}`` to a separate anchor log. An attacker who
rewrites the receipts does not hold the key, so they cannot forge a matching anchor; and the
stale anchor's head no longer equals the recomputed head. Either way ``verify`` fails.

Point ``WARRNT_ANCHOR`` at storage outside the node (a WORM bucket, another host, an
append-only sink) to make the separation physical, not just cryptographic.
"""
from __future__ import annotations

import hmac
import json
import os
import threading
import time
from typing import Any, Callable, Optional

from .canonical import canon


class HeadAnchor:
    def __init__(self, path: str, signer: Callable[[dict], str], now=None):
        self.path = path
        self._sign = signer
        self._now = now or time.time
        self._lock = threading.RLock()
        self.records: list[dict[str, Any]] = []
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self.records.append(json.loads(line))

    def _payload(self, head: str, length: int, ts: float) -> dict:
        return {"head": head, "length": length, "ts": ts}

    def seal(self, head: str, length: int) -> dict[str, Any]:
        """Sign the current head and persist the anchor. Called on every append."""
        with self._lock:
            ts = self._now()
            payload = self._payload(head, length, ts)
            rec = {**payload, "sig": self._sign(payload)}
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(canon(rec) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.records.append(rec)
            return rec

    @property
    def last(self) -> Optional[dict[str, Any]]:
        return self.records[-1] if self.records else None

    def verify(self, head: str, length: int) -> dict[str, Any]:
        """Is the registry head the one the issuer last signed?"""
        last = self.last
        if last is None:
            return {"anchored": False, "ok": True, "reason": "no anchor recorded yet"}
        payload = self._payload(last["head"], last["length"], last["ts"])
        signed = hmac.compare_digest(last["sig"], self._sign(payload))
        if not signed:
            return {"anchored": True, "ok": False, "signed": False,
                    "reason": "anchor signature does not verify - the anchor was edited",
                    "anchor_head": last["head"][:16]}
        if last["head"] != head or last["length"] != length:
            return {"anchored": True, "ok": False, "signed": True,
                    "reason": "registry head does not match the signed anchor - rewrite detected",
                    "anchor_head": last["head"][:16], "registry_head": head[:16],
                    "anchor_length": last["length"], "registry_length": length}
        return {"anchored": True, "ok": True, "signed": True,
                "head": head[:16], "length": length, "anchors": len(self.records)}
