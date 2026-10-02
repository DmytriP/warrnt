"""FastAPI surface of the node.

    POST /mcp       JSON-RPC 2.0 ``tools/call`` - the interception point
    POST /revoke    pull a warrant and halt the agent
    GET  /state     live contract (agents, warrants, receipts, chain)
    GET  /warrants  signed artifacts + signature validity
    GET  /receipts  the full append-only registry
    GET  /verify    recompute the hash chain from genesis
    GET  /health    liveness + chain head
    POST /reset     re-issue the seed warrants and clear counters

The proxy is built once in ``create_app`` and stored on ``app.state.proxy``; routes are
thin translators. A denied call returns a JSON-RPC ``error`` and the upstream is not
touched.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .config import Settings
from .models import Decision
from .policy import PolicyEngine
from .proxy import MCPProxy
from .registry import AppendOnlyRegistry
from .upstream import build_upstream, ExecutionCounter
from .warrants import WarrantIssuer

RPC_CODES = {
    Decision.deny: -32001,
    Decision.human: -32002,
    Decision.revoked: -32003,
    Decision.expired: -32004,
}


class RevokeRequest(BaseModel):
    agent: Optional[str] = None
    warrant: Optional[str] = None


def build_proxy(settings: Settings) -> MCPProxy:
    issuer = WarrantIssuer.from_env_or_file(str(settings.key_path))
    registry = AppendOnlyRegistry(str(settings.registry_path))
    counter = ExecutionCounter()
    upstream = build_upstream(counter)
    proxy = MCPProxy(issuer=issuer, registry=registry, engine=PolicyEngine(), upstream=upstream)
    proxy.counter = counter
    return proxy


def create_app(settings: Optional[Settings] = None, seed: bool = True) -> FastAPI:
    settings = settings or Settings.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if seed:
            app.state.proxy.issue_all(reset_registry=False)
        yield

    app = FastAPI(title="WARRNT node", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.proxy = build_proxy(settings)

    def proxy() -> MCPProxy:
        return app.state.proxy

    # ------------------------------------------------------------------- reads
    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "node": "warrnt", "chain": proxy().registry.verify()}

    @app.get("/state")
    def state(limit: int = 60) -> dict[str, Any]:
        return proxy().state(limit=limit)

    @app.get("/api/state", include_in_schema=False)
    def api_state_alias(limit: int = 60) -> dict[str, Any]:
        """Alias kept for the console screen (P3), which polls /api/state."""
        return proxy().state(limit=limit)

    @app.get("/verify")
    def verify() -> dict[str, Any]:
        return proxy().registry.verify()

    @app.get("/receipts")
    def receipts() -> list[dict[str, Any]]:
        return proxy().registry.entries

    @app.get("/warrants")
    def warrants() -> list[dict[str, Any]]:
        p = proxy()
        return [{
            "id": w.id, "agent": w.agent, "role": w.role, "scope": w.scope,
            "ttl": w.ttl, "issued": w.issued, "issuer": w.issuer,
            "state": w.state, "sig": w.sig, "sig_ok": p.issuer.signature_ok(w),
            "payload": w.payload(),
        } for w in p.warrants.values()]

    @app.get("/agents")
    def agents() -> list[dict[str, Any]]:
        """Agent identities. Tokens are exposed only when WARRNT_DEV=1 - a demo
        convenience, not an API: this node has no separate control plane yet."""
        p = proxy()
        out = []
        for a in p.agents.values():
            row = {"id": a.id, "role": a.role, "warrant": a.warrant, "state": a.state, "last": a.last}
            if settings.dev:
                row["token"] = a.token
            out.append(row)
        return out

    # -------------------------------------------------------------- interception
    @app.post("/mcp")
    async def mcp(request: Request,
                  x_warrnt_agent: str = Header(default=""),
                  x_warrnt_token: str = Header(default="")) -> JSONResponse:
        body = await request.json()
        rpc_id = body.get("id")
        if body.get("method") != "tools/call":
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id,
                                 "error": {"code": -32601,
                                           "message": "only tools/call is intercepted"}})
        params = body.get("params", {})
        tool = params.get("name")
        args = params.get("arguments") or {}
        if not tool:
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id,
                                 "error": {"code": -32602, "message": "params.name required"}})

        decision, reason, detail, receipt, executed = proxy().intercept(
            x_warrnt_agent, x_warrnt_token, tool, args)

        if decision is Decision.allow:
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "decision": decision.value, "reason": reason, "executed": executed,
                "receipt": detail.get("receipt"), **detail.get("result", {}),
            }})
        return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": {
            "code": RPC_CODES.get(decision, -32000), "message": reason,
            "data": {"decision": decision.value, "executed": executed, **detail},
        }})

    # --------------------------------------------------------------------- brake
    @app.post("/revoke")
    def revoke(body: RevokeRequest) -> JSONResponse:
        p = proxy()
        agent_id = body.agent
        if agent_id is None and body.warrant:
            warrant = p.warrants.get(body.warrant)
            agent_id = warrant.agent if warrant else None
        if agent_id is None or agent_id not in p.agents:
            return JSONResponse({"error": "unknown agent or already halted",
                                 "agent": agent_id}, status_code=409)
        t0 = p.revoke(agent_id)
        if t0 is None:
            return JSONResponse({"error": "unknown agent or already halted",
                                 "agent": agent_id}, status_code=409)
        return JSONResponse({"agent": agent_id, "state": "halted",
                             "warrant": p.agents[agent_id].warrant, "revoked_at": t0})

    # ------------------------------------------------------------------- reset
    @app.post("/reset")
    def reset() -> dict[str, Any]:
        proxy().issue_all(reset_registry=True)
        return {"ok": True, "state": proxy().state()}

    return app


app = None
if os.environ.get("WARRNT_EAGER_APP", "").strip():
    app = create_app()
