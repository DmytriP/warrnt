"""The downstream MCP server the proxy fronts.

There are exactly two upstreams:

* :class:`SandboxUpstream` - in-process, counts every execution. Used in tests and in the
  offline demo, precisely so that "the export never ran" is a measurable number and not a
  claim.
* :class:`MCPUpstream` - a real MCP server behind ``WARRNT_UPSTREAM``, spoken to over the
  MCP *streamable HTTP* transport with the official ``mcp`` client. A denied call never
  reaches this class; the proxy only calls ``upstream.call`` after an ``allow``. The
  server keeps its own access log (see ``scripts/mcp_fixture_server.py``), so "the denied
  export never reached upstream" is read from the upstream, not from us.
"""
from __future__ import annotations

import asyncio
import json
import threading


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


def _result_payload(result) -> dict:
    """Pull the tool's JSON payload out of an MCP ``CallToolResult``.

    Prefers ``structured_content``; falls back to the first text block, which the MCP
    server fills with the JSON-encoded return value when the tool returns a dict.
    """
    if getattr(result, "is_error", None):
        text = " ".join(getattr(block, "text", "") or "" for block in (result.content or []))
        raise RuntimeError(f"upstream tool error: {text.strip() or 'unknown'}")
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and structured:
        return structured
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


class MCPUpstream:
    """Forwards to a real MCP server over streamable HTTP (official ``mcp`` client).

    The node is synchronous, so the MCP client lives on its own event loop in a daemon
    thread; :meth:`call` submits one ``initialize`` + ``tools/call`` round trip per
    execution and blocks for the answer.
    """

    def __init__(self, url: str, counter: ExecutionCounter, timeout: float = 15.0):
        self.url = url
        self.counter = counter
        self.timeout = timeout
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever,
                                        name="warrnt-mcp-upstream", daemon=True)
        self._thread.start()

    async def _round_trip(self, tool: str, args: dict) -> dict:
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        async with streamable_http_client(self.url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, args)
                return _result_payload(result)

    def call(self, tool: str, args: dict) -> dict:
        future = asyncio.run_coroutine_threadsafe(self._round_trip(tool, args), self._loop)
        try:
            payload = future.result(timeout=self.timeout)
        except TimeoutError as exc:
            future.cancel()
            raise RuntimeError(f"upstream {self.url} timed out after {self.timeout}s") from exc
        rows = int(payload.get("rows", 1))
        self.counter.record(tool, rows)
        return {"tool": tool, "rows": rows, "ok": True, "upstream": True, **payload}


def build_upstream(counter: ExecutionCounter, url: str | None = None):
    import os

    endpoint = (url if url is not None else os.environ.get("WARRNT_UPSTREAM", "")).strip()
    return MCPUpstream(endpoint, counter) if endpoint else SandboxUpstream(counter)
