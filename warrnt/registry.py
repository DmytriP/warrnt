"""Append-only, hash-chained receipt registry.

Each entry carries ``prev`` (the previous entry's hash, or the genesis zeros) and
``hash = sha256(prev + canon(entry_without_hash))``. The file is fsync'd on every append,
so a crash cannot leave a decision unrecorded-but-executed. ``verify()`` recomputes the
chain from genesis: edit any byte in the middle and it fails at that index.

A reset is a *rotation*, not an erasure. The closed chain is copied to
``receipts.<ts>.jsonl`` and a rotation record - closed head, row count, archive name and
the archive's sha256 - is appended to a sidecar that is itself never truncated. So
``verify()`` can still answer "what happened before the reset", and deleting the archive
turns the verdict red instead of silently green (finding V2). A reset that leaves the
chain empty *and* the verdict green is exactly the lie this file refuses to tell.

This is one node's honest log - not a distributed ledger, and not claimed to be one.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Callable, Optional

from .canonical import canon


class AppendOnlyRegistry:
    GENESIS = "0" * 64

    def __init__(self, path: str):
        self.path = path
        self.rotations_path = str(path) + ".rotations.jsonl"
        self._lock = threading.RLock()
        self.entries: list[dict[str, Any]] = []
        self.rotations: list[dict[str, Any]] = []
        self.on_append: Optional[Callable[[dict[str, Any]], None]] = None
        self.on_reset: Optional[Callable[[Optional[dict[str, Any]]], None]] = None
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self.entries.append(json.loads(line))
        if os.path.exists(self.rotations_path):
            with open(self.rotations_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self.rotations.append(json.loads(line))

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

    def _archive_path(self, name: str) -> str:
        return os.path.join(os.path.dirname(self.path), name)

    def history(self) -> dict[str, Any]:
        """What happened before the live chain - proved, not asserted.

        Every rotation names its archive and the archive's sha256. If the archive is gone
        or edited, ``archives_ok`` is False and the chain verdict goes red: the layer
        cannot be made to forget by deleting a file.
        """
        missing: list[str] = []
        for rot in self.rotations:
            path = self._archive_path(rot["archive"])
            if not os.path.exists(path):
                missing.append(rot["archive"])
                continue
            with open(path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            if digest != rot["archive_sha256"]:
                missing.append(rot["archive"] + " (altered)")
        return {
            "rotations": len(self.rotations),
            "archived_rows": sum(int(r.get("closed_length") or 0) for r in self.rotations),
            "last_closed_head": (self.rotations[-1]["closed_head"][:16] if self.rotations else None),
            "archives_ok": not missing,
            "problems": missing,
        }

    # ------------------------------------------------------------------ verify
    def verify(self) -> dict[str, Any]:
        prev = self.GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            want = hashlib.sha256((prev + canon(body)).encode()).hexdigest()
            if body.get("prev") != prev or want != entry["hash"]:
                return {"ok": False, "length": len(self.entries), "head": prev[:16],
                        "broken_at": i, "expected": want, "found": entry["hash"],
                        "history": self.history()}
            prev = entry["hash"]
        hist = self.history()
        if not hist["archives_ok"]:
            return {"ok": False, "length": len(self.entries), "head": prev[:16],
                    "broken_at": None,
                    "reason": "archived history removed or altered after a rotation",
                    "history": hist}
        return {"ok": True, "length": len(self.entries), "head": prev[:16], "history": hist}

    def reset(self, reason: str = "", actor: str = "") -> Optional[dict[str, Any]]:
        """Rotate the chain: archive it, record the rotation, start fresh.

        Returns the rotation record, or None when there was nothing to rotate.
        """
        with self._lock:
            rotation: Optional[dict[str, Any]] = None
            if self.entries:
                ts = time.time()
                # The name must be unique even when two rotations happen inside one second: an
                # overwritten archive would read as "altered history" and hide the real one.
                stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(ts))
                archive = f"{os.path.basename(self.path)}.{stamp}.{len(self.rotations) + 1:03d}.jsonl"
                while os.path.exists(self._archive_path(archive)):
                    archive = archive.replace(".jsonl", "-b.jsonl")
                with open(self.path, "rb") as fh:
                    raw = fh.read()
                with open(self._archive_path(archive), "wb") as fh:
                    fh.write(raw)
                    fh.flush()
                    os.fsync(fh.fileno())
                rotation = {
                    "t": time.strftime("%H:%M:%S"), "ts": ts,
                    "closed_head": self.entries[-1]["hash"],
                    "closed_length": len(self.entries),
                    "archive": archive,
                    "archive_sha256": hashlib.sha256(raw).hexdigest(),
                    "reason": reason, "actor": actor,
                }
                with open(self.rotations_path, "a", encoding="utf-8") as fh:
                    fh.write(canon(rotation) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                self.rotations.append(rotation)
            self.entries = []
            open(self.path, "w").close()
            if self.on_reset is not None:
                self.on_reset(rotation)
            return rotation
