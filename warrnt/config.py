"""Configuration. Env only - one node has no config server.

WARRNT_HOME         state directory (default: ``./state`` under the repo root)
WARRNT_ISSUER_KEY   signing key (default: generated at <home>/issuer.key)
WARRNT_UPSTREAM     real MCP endpoint to front; unset -> in-process sandbox
WARRNT_HOST/PORT    bind address for ``warrnt serve``
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    home: Path
    registry_path: Path
    key_path: Path
    upstream_url: str
    host: str
    port: int
    dev: bool

    @classmethod
    def load(cls, home: str | os.PathLike | None = None) -> "Settings":
        base = Path(home) if home else Path(os.environ.get("WARRNT_HOME", REPO_ROOT / "state"))
        return cls(
            home=base,
            registry_path=base / "receipts.jsonl",
            key_path=base / "issuer.key",
            upstream_url=os.environ.get("WARRNT_UPSTREAM", "").strip(),
            host=os.environ.get("WARRNT_HOST", "0.0.0.0"),
            port=int(os.environ.get("WARRNT_PORT", "8099")),
            dev=os.environ.get("WARRNT_DEV", "").strip() in ("1", "true", "yes"),
        )
