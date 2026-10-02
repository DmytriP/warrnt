#!/usr/bin/env python
"""A real MCP server (official ``mcp`` SDK, streamable HTTP) for the D1 live proof.

This process is deliberately *not* part of the node:

* it is started separately, on its own port, by ``scripts/upstream_check.py``;
* it appends every call it actually receives to its own JSONL access log (``--log``);
* the node under test only knows its URL.

That is what makes the negative claim checkable from the other side: "the denied
``crm.bulk_export`` never reached upstream" is asserted against *this* log, not against
the proxy's own counter.

Usage::

    python scripts/mcp_fixture_server.py --port 8210 --log state/upstream/calls.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import time

from mcp.server.mcpserver import MCPServer

# The tools mirror warrnt/seed.py one-for-one, so a warrant that names ``crm.bulk_export``
# finds a tool with exactly that name on the far side of the gate.
TOOLS: dict[str, str] = {
    "crm.read": "read CRM rows (read-only)",
    "crm.bulk_export": "export the whole CRM table including PII",
    "payments.read": "read payment records (read-only)",
    "payments.transfer": "move money",
    "infra.plan": "produce a change plan (read-only)",
    "infra.deploy": "apply a change plan",
}

_LOG_PATH = os.environ.get("MCP_FIXTURE_LOG", "")


def _record(tool: str, args: dict) -> None:
    """Append one line to this server's own access log."""
    if not _LOG_PATH:
        return
    entry = {"ts": round(time.time(), 6), "tool": tool, "args": args, "pid": os.getpid()}
    with open(_LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
        fh.flush()


def _rows(args: dict, default: int = 1) -> int:
    raw = args.get("rows", args.get("limit", default))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def build_server() -> MCPServer:
    server = MCPServer(name="warrnt-upstream-fixture", version="1.0.0")

    @server.tool(name="crm.read", description=TOOLS["crm.read"])
    def crm_read(table: str = "contacts", rows: int = 10) -> dict:
        args = {"table": table, "rows": rows}
        _record("crm.read", args)
        return {"tool": "crm.read", "table": table, "rows": _rows(args), "ok": True}

    @server.tool(name="crm.bulk_export", description=TOOLS["crm.bulk_export"])
    def crm_bulk_export(fields: str = "*", rows: int = 1000) -> dict:
        args = {"fields": fields, "rows": rows}
        _record("crm.bulk_export", args)
        return {"tool": "crm.bulk_export", "fields": fields, "rows": _rows(args, 1000), "ok": True}

    @server.tool(name="payments.read", description=TOOLS["payments.read"])
    def payments_read(rows: int = 10) -> dict:
        args = {"rows": rows}
        _record("payments.read", args)
        return {"tool": "payments.read", "rows": _rows(args), "ok": True}

    @server.tool(name="payments.transfer", description=TOOLS["payments.transfer"])
    def payments_transfer(amount_pln: float = 0, rows: int = 1) -> dict:
        args = {"amount_pln": amount_pln, "rows": rows}
        _record("payments.transfer", args)
        return {"tool": "payments.transfer", "amount_pln": amount_pln, "rows": _rows(args), "ok": True}

    @server.tool(name="infra.plan", description=TOOLS["infra.plan"])
    def infra_plan(rows: int = 1) -> dict:
        args = {"rows": rows}
        _record("infra.plan", args)
        return {"tool": "infra.plan", "rows": _rows(args), "ok": True}

    @server.tool(name="infra.deploy", description=TOOLS["infra.deploy"])
    def infra_deploy(rows: int = 1) -> dict:
        args = {"rows": rows}
        _record("infra.deploy", args)
        return {"tool": "infra.deploy", "rows": _rows(args), "ok": True}

    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Real MCP server used as the D1 upstream.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8210)
    parser.add_argument("--log", default="", help="JSONL access log, one line per call")
    args = parser.parse_args()

    global _LOG_PATH
    _LOG_PATH = args.log
    if _LOG_PATH:
        os.makedirs(os.path.dirname(os.path.abspath(_LOG_PATH)), exist_ok=True)

    server = build_server()
    server.run(transport="streamable-http", host=args.host, port=args.port,
               json_response=True, stateless_http=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
