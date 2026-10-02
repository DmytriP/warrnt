"""Append-only, hash-chained receipt registry.

Each entry carries ``prev`` (the previous entry's hash, or the genesis zeros) and
``hash = sha256(prev + canon(entry_without_hash))``. The file is fsync'd on every append,
so a crash cannot leave a decision unrecorded-but-executed. ``verify()`` recomputes the
chain from genesis: edit any byte in the middle and it fails at that index.

This is one node's honest log - not a distributed ledger, and not claimed to be one.
"""
from __future__ import annotations

import hashlib
import os
import threading
from typing import Any, Callable, Optional

from .canonical import canon


class AppendOnlyRegistry:
    GENESIS = "0" * 64

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.entries: list[dict[str, Any]] = []
        self.on_append: Optional[Callable[[dict[str, Any]], None]] = None
        self.on_reset: Optional[Callable[[], None]] = None
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self.entries.append(__import__("json").loads(line))

    # ------------------------------------------------------------------ write
    def append(self, **fields: Any) -> dict[str, Any]:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else self.GENESIS
            rec: dict[str, Any] = dict(fields)
            rec["prev"] = prev
            rec["hash"] = hashlib.sha256((prev + canon(rec)).encode()).hexdigest()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(canon(rec) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.entries.append(rec)
            if self.on_append is not None:
                self.on_append(rec)
            return rec

    # ------------------------------------------------------------------ read
    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else self.GENESIS

    def recent(self, limit: int = 60) -> list[dict[str, Any]]:
        return list(reversed(self.entries))[:limit]

    # ------------------------------------------------------------------ verify
    def verify(self) -> dict[str, Any]:
        prev = self.GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            want = hashlib.sha256((prev + canon(body)).encode()).hexdigest()
            if body.get("prev") != prev or want != entry["hash"]:
                return {"ok": False, "broken_at": i, "expected": want, "found": entry["hash"]}
            prev = entry["hash"]
        return {"ok": True, "length": len(self.entries), "head": prev[:16]}

    def reset(self) -> None:
        with self._lock:
            self.entries = []
            open(self.path, "w").close()
            if self.on_reset is not None:
                self.on_reset()
