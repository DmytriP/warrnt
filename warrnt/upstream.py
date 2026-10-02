"""The downstream MCP server the proxy fronts.

There are exactly two upstreams:

* :class:`SandboxUpstream` - in-process, counts every execution. Used in tests and in the
  offline demo, precisely so that "the export never ran" is a measurable number and not a
  claim.
* :class:`HttpUpstream` - forwards the call to a real MCP endpoint over HTTP, selected by
  ``WARRNT_UPSTREAM``. A denied call never reaches this class; the proxy only calls
  ``upstream.call`` after an ``allow``.
"""
from __future__ import annotations

import json
import urllib.request


class ExecutionCounter:
    """Counts tool executions. The single source of truth for 'did it run?'."""

    def __init__(self):
        self.calls: dict[str, int] = {}
        self.rows: dict[str, int] = {}

    def record(self, tool: str, rows: int) -> None:
        self.calls[tool] = self.calls.get(tool, 0) + 1
        self.rows[tool] = self.rows.get(tool, 0) + rows

    def snapshot(self) -> dict[str, int]:
        return dict(self.calls)

    def clear(self) -> None:
        self.calls.clear()
        self.rows.clear()


class SandboxUpstream:
    """In-process stand-in for an MCP server."""

    def __init__(self, counter: ExecutionCounter):
        self.counter = counter

    def call(self, tool: str, args: dict) -> dict:
        rows = int(args.get("rows", 1)) if (tool.endswith("read") or tool == "crm.bulk_export") else 1
        self.counter.record(tool, rows)
        return {"tool": tool, "rows": rows, "ok": True, "upstream": False}


class HttpUpstream:
    """Forwards to a real MCP server (JSON-RPC tools/call over HTTP)."""

    def __init__(self, url: str, counter: ExecutionCounter):
        self.url = url
        self.counter = counter

    def call(self, tool: str, args: dict) -> dict:
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode())
        if "error" in payload:
            raise RuntimeError(f"upstream error: {payload['error']}")
        result = payload.get("result") or {}
        rows = int(result.get("rows", 1))
        self.counter.record(tool, rows)
        return {"tool": tool, "rows": rows, "ok": True, "upstream": True, **result}


def build_upstream(counter: ExecutionCounter):
    import os

    url = os.environ.get("WARRNT_UPSTREAM", "").strip()
    return HttpUpstream(url, counter) if url else SandboxUpstream(counter)
