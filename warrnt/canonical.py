"""Deterministic JSON canonicalisation.

Every signature and every receipt hash is computed over ``canon(obj)`` so the same
logical record always produces the same bytes. Without this the hash chain would be
decorative - two runs of the same event would hash differently.
"""
from __future__ import annotations

import json
from typing import Any


def canon(obj: Any) -> str:
    """Stable JSON: sorted keys, no whitespace, UTF-8 preserved."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
