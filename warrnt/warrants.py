"""Issuer: turns a :class:`WarrantSpec` into a signed, TTL-bounded order.

The signing key comes from ``WARRNT_ISSUER_KEY`` or, failing that, is generated once at
``state/issuer.key`` (mode 0600). The key never appears in a payload, a receipt or a log.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time

from .canonical import canon
from .models import Warrant, WarrantSpec


class WarrantIssuer:
    def __init__(self, key: bytes, now=None):
        self.key = key
        self._now = now or time.time

    # ------------------------------------------------------------- construction
    @classmethod
    def from_env_or_file(cls, key_path: str, now=None) -> "WarrantIssuer":
        env = os.environ.get("WARRNT_ISSUER_KEY")
        if env:
            return cls(env.encode(), now=now)
        if not os.path.exists(key_path):
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            with open(key_path, "w", encoding="utf-8") as fh:
                fh.write(hashlib.sha256(os.urandom(32)).hexdigest())
            os.chmod(key_path, 0o600)
        with open(key_path, "rb") as fh:
            return cls(fh.read().strip(), now=now)

    # ------------------------------------------------------------- signing
    def sign(self, payload: dict) -> str:
        return hmac.new(self.key, canon(payload).encode(), hashlib.sha256).hexdigest()

    def signature_ok(self, warrant: Warrant) -> bool:
        return hmac.compare_digest(warrant.sig, self.sign(warrant.payload()))

    def issue(self, spec: WarrantSpec) -> Warrant:
        warrant = Warrant(**spec.model_dump(), issued=self._now(), sig="")
        warrant.sig = self.sign(warrant.payload())
        return warrant

    def token_for(self, agent: str, warrant_id: str) -> str:
        """Ephemeral per-agent identity bound to one warrant."""
        return hmac.new(self.key, f"tok:{agent}:{warrant_id}".encode(),
                        hashlib.sha256).hexdigest()[:24]


def remaining(warrant: Warrant, now: float | None = None) -> float:
    now = now if now is not None else time.time()
    return max(0.0, warrant.ttl - (now - warrant.issued))


def refresh_state(warrant: Warrant, now: float | None = None) -> str:
    if warrant.state == "active" and remaining(warrant, now) <= 0:
        warrant.state = "expired"
    return warrant.state
