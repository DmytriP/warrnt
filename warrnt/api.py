"""FastAPI surface of the node.

    POST /mcp       JSON-RPC 2.0 ``tools/call`` - the interception point
    POST /revoke    pull a warrant and halt the agent
    GET  /state     live contract (agents, warrants, receipts, chain)
    GET  /warrants  signed artifacts + signature validity
    GET  /receipts  the full append-only registry
    GET  /verify    recompute the hash chain from genesis
    GET  /health    liveness + chain head
    POST /reset     rotate the receipt chain and re-issue the seed warrants (operator token)
    POST /api/breakglass            a named person opens a policy pause for ≤15 min
    GET  /api/breakglass            every grant, its state, its window and its debt
    POST /api/breakglass/revoke     close a grant early
    POST /api/breakglass/postmortem record the review a used grant owes
    GET  /api/actions            the canonical Action log (one object per intercepted call)
    GET  /api/actions/{id}       one Action: decision, upstream_contacted, receipt
    POST /api/actions/{id}/approve  a named person releases a held action (runs upstream)
    POST /api/actions/{id}/deny     a named person refuses it (upstream NOT contacted)
    POST /api/ask                an answer assembled from the record - never guessed

The proxy is built once in ``create_app`` and stored on ``app.state.proxy``; routes are
thin translators. A denied call returns a JSON-RPC ``error`` and the upstream is not
touched.

Mutating routes (``/reset``, ``/revoke``, ``/api/breakglass*``, ``/_dev/*``) require the
operator token in ``x-warrnt-admin``: an anonymous control plane is a control plane anyone
can drive (finding V1). Set ``WARRNT_ADMIN_TOKEN``; when it is unset the node generates one
and prints it once at startup.
"""
from __future__ import annotations

import hmac
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .actions import classify
from .actors import ActorRegistry
from .anchor import HeadAnchor
from .breakglass import MAX_TTL_S, BreakGlassRefused
from .controlplane import HoldRefused, answer
from .config import Settings
from .models import Decision
from .policy import PolicyEngine
from .proxy import MCPProxy
from .registry import AppendOnlyRegistry
from .upstream import build_upstream, ExecutionCounter
from .warrants import WarrantIssuer

# Only refusals are errors. ``redact`` runs, so it is a result with a note - a receipt
# that says *executed, minus these fields* - never a JSON-RPC error.
RPC_CODES = {
    Decision.deny: -32001,
    Decision.human: -32002,
    Decision.revoked: -32003,
}


class RevokeRequest(BaseModel):
    agent: Optional[str] = None
    warrant: Optional[str] = None


class TamperRequest(BaseModel):
    warrant: str


class BreakGlassRequest(BaseModel):
    human: str
    agent: str
    tool: str
    reason: str
    ttl_s: float = MAX_TTL_S


class BreakGlassId(BaseModel):
    id: str


class BreakGlassPostmortem(BaseModel):
    id: str
    note: str


class DecideRequest(BaseModel):
    by: str
    note: str = ""


class AskRequest(BaseModel):
    q: str


class ResetRequest(BaseModel):
    reason: str = ""
    actor: str = ""


def build_proxy(settings: Settings) -> MCPProxy:
    issuer = WarrantIssuer.from_env_or_file(str(settings.key_path))
    registry = AppendOnlyRegistry(str(settings.registry_path))
    counter = ExecutionCounter()
    upstream = build_upstream(counter)
    engine = PolicyEngine(verify=issuer.signature_ok)
    proxy = MCPProxy(issuer=issuer, registry=registry, engine=engine, upstream=upstream)
    proxy.counter = counter
    # Every append, and every reset, re-signs the registry head with the issuer key and
    # records it in a separate anchor log. A rewritten registry no longer matches the last
    # signed anchor, and the anchor cannot be forged without the key (finding M1).
    anchor = HeadAnchor(str(settings.anchor_path), issuer.sign)
    proxy.anchor = anchor

    def _seal_append(rec: dict) -> None:
        anchor.seal(rec["hash"], len(registry.entries))

    def _seal_reset(rotation: Optional[dict[str, Any]] = None) -> None:
        # Seal the closed segment first, so the anchor log itself carries the rotation point
        # (head + row count), then seal the fresh empty chain.
        if rotation:
            anchor.seal(rotation["closed_head"], rotation["closed_length"])
        anchor.seal(registry.GENESIS, 0)

    registry.on_append = _seal_append
    registry.on_reset = _seal_reset
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

    admin_token = settings.admin_token or secrets.token_urlsafe(24)
    app.state.admin_token = admin_token
    if not settings.admin_token:
        print("[warrnt] WARRNT_ADMIN_TOKEN is unset - generated for this process only:\n"
              f"[warrnt]   {admin_token}\n"
              "[warrnt] mutating routes need the header x-warrnt-admin: <token>", flush=True)

    def require_admin(supplied: str) -> Optional[JSONResponse]:
        """401 unless the caller holds the operator token."""
        if not admin_token or not supplied or not hmac.compare_digest(supplied, admin_token):
            return JSONResponse({"error": "operator token required",
                                 "hint": "send the x-warrnt-admin header"}, status_code=401)
        return None

    def proxy() -> MCPProxy:
        return app.state.proxy

    def chain_view() -> dict[str, Any]:
        p = proxy()
        return {**p.registry.verify(),
                "anchor": p.anchor.verify(p.registry.head, len(p.registry.entries))}

    # ------------------------------------------------------------------- reads
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def console() -> HTMLResponse:
        """The console screen (IN-6): a live view of THIS node's /api/state.

        Served from inside the package so the demo is one artifact - clone, run, open
        the node - and the screen can never drift from the API it renders. Read per
        request: editing the file does not need a restart during the demo.
        """
        path = Path(__file__).with_name("console.html")
        if not path.exists():
            return HTMLResponse("<h1>WARRNT</h1><p>console.html missing from the package</p>",
                                status_code=500)
        return HTMLResponse(path.read_text(encoding="utf-8"))

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "node": "warrnt", "chain": chain_view()}

    @app.get("/state")
    def state(limit: int = 60) -> dict[str, Any]:
        return proxy().state(limit=limit)

    @app.get("/api/state", include_in_schema=False)
    def api_state_alias(limit: int = 60) -> dict[str, Any]:
        """Alias kept for the console screen (P3), which polls /api/state."""
        return proxy().state(limit=limit)

    @app.get("/verify")
    def verify() -> dict[str, Any]:
        return chain_view()

    @app.get("/anchor")
    def anchor() -> dict[str, Any]:
        """The last head the issuer signed, and whether the live registry still matches it."""
        p = proxy()
        last = p.anchor.last
        hist = p.registry.history()
        verdict = p.anchor.verify(p.registry.head, len(p.registry.entries))
        # The anchor speaks for the live head. If a rotated segment is gone or edited, the
        # anchor must not be the one place that still says "fine" (finding V2).
        verdict = {**verdict, "history_ok": hist["archives_ok"],
                   "ok": bool(verdict.get("ok")) and hist["archives_ok"]}
        return {
            "anchors": len(p.anchor.records),
            "last": ({"head": last["head"], "length": last["length"], "ts": last["ts"],
                      "sig": last["sig"][:16] + "…"} if last else None),
            "verdict": verdict,
            "history": hist,
        }

    @app.get("/receipts")
    def receipts() -> list[dict[str, Any]]:
        return proxy().registry.entries

    @app.get("/actors")
    def actors() -> dict[str, Any]:
        """Who stands at the gate, by class, and what each may never call.

        The register is the answer to "this agent cannot": it is not a permission view of the
        user, it is a limit on the actor, and it is checked before the warrant is read.
        """
        p = proxy()
        return {"kinds": ActorRegistry.kinds(), "actors": p.actors.listing()}

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
                  x_warrnt_token: str = Header(default=""),
                  x_warrnt_run: str = Header(default="")) -> JSONResponse:
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
            x_warrnt_agent, x_warrnt_token, tool, args, run_id=x_warrnt_run)

        if decision in (Decision.allow, Decision.redact):
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "decision": decision.value, "reason": reason, "executed": executed,
                "action_id": detail.get("action_id"),
                "receipt": detail.get("receipt"),
                "redacted": detail.get("redacted"),
                "upstream_params": detail.get("upstream_params"),
                **detail.get("result", {}),
            }})
        return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": {
            "code": RPC_CODES.get(decision, -32000), "message": reason,
            "data": {"decision": decision.value, "executed": executed, **detail},
        }})

    # ---------------------------------------------------------- control plane (PR-14)
    @app.get("/api/actions")
    def actions(state: str = "", limit: int = 60) -> dict[str, Any]:
        """The canonical Action log: the same object the console renders and an answer quotes."""
        p = proxy()
        return {"counts": p.actions.counts(),
                "pending": p.actions.pending(),
                "actions": p.actions.listing(state=state or None, limit=limit)}

    @app.get("/api/actions/{action_id}")
    def action_one(action_id: str) -> JSONResponse:
        action = proxy().actions.get(action_id)
        if action is None:
            return JSONResponse({"error": f"unknown action {action_id}",
                                 "hint": "GET /api/actions lists the ledger"},
                                status_code=404)
        return JSONResponse(action.public())

    @app.post("/api/actions/{action_id}/approve")
    def action_approve(action_id: str, body: DecideRequest,
                       x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """A named person releases the hold: the upstream runs here, once, and the chain
        records the human decision *before* the execution it authorises."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        try:
            out = proxy().resolve_hold(action_id, approve=True, by=body.by)
        except HoldRefused as exc:
            return JSONResponse({"error": str(exc), "action_id": action_id}, status_code=409)
        return JSONResponse({"action_id": action_id, "state": out["action"]["state"],
                             "executed": out["executed"], "upstream_contacted": True,
                             "rows": out.get("rows", 0), "receipt": out["receipt"]})

    @app.post("/api/actions/{action_id}/deny")
    def action_deny(action_id: str, body: DecideRequest,
                    x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """A named person refuses the hold. The upstream is NOT contacted, and the receipt
        is the proof: ``upstream_contacted`` stays false for this action_id."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        try:
            out = proxy().resolve_hold(action_id, approve=False, by=body.by)
        except HoldRefused as exc:
            return JSONResponse({"error": str(exc), "action_id": action_id}, status_code=409)
        return JSONResponse({"action_id": action_id, "state": out["action"]["state"],
                             "executed": False, "upstream_contacted": False,
                             "receipt": out["receipt"]})

    @app.post("/api/ask")
    def ask(body: AskRequest) -> dict[str, Any]:
        """An answer built from the record. There is no model in this path on purpose: what
        the console says about a call must be a field of that call, or an admission that the
        field is missing."""
        p = proxy()
        st = p.state(limit=20)
        return answer(body.q, p.actions.listing(limit=60), st)

    # --------------------------------------------------------------------- brake
    @app.post("/revoke")
    def revoke(body: RevokeRequest, x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
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

    # ------------------------------------------------------------ break-glass
    @app.post("/api/breakglass")
    def breakglass_grant(body: BreakGlassRequest,
                         x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """A named person opens one policy pause, for one agent and one tool, briefly.

        The node checks the class first: what the taxonomy calls a person's act
        (``irreversible``, ``authorize``) is refused here with that sentence, and never
        reaches the grant. What is left is the ``human`` a *rule* asked for.
        """
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        p = proxy()
        if body.agent not in p.agents:
            return JSONResponse({"error": f"unknown agent {body.agent!r}"}, status_code=404)
        cls = classify(body.tool, None)
        if cls is None:
            return JSONResponse({"error": f"tool {body.tool!r} has no action class · "
                                          f"the layer refuses what it cannot classify"},
                                status_code=409)
        try:
            grant = p.breakglass.grant(human=body.human, agent=body.agent, tool=body.tool,
                                       reason=body.reason, cls=cls.value, ttl_s=body.ttl_s)
        except BreakGlassRefused as exc:
            return JSONResponse({"error": str(exc), "agent": body.agent, "tool": body.tool,
                                 "class": cls.value}, status_code=409)
        return JSONResponse({"id": grant.id, "human": grant.human, "agent": grant.agent,
                             "tool": grant.tool, "class": grant.cls, "reason": grant.reason,
                             "expires_in_s": int(round(p.breakglass.remaining_s(grant))),
                             "single_use": True, "postmortem_owed_after_use": True,
                             "sig": grant.sig[:16]})

    @app.get("/api/breakglass")
    def breakglass_list() -> dict[str, Any]:
        return proxy().breakglass.snapshot()

    @app.post("/api/breakglass/revoke")
    def breakglass_revoke(body: BreakGlassId,
                          x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        grant = proxy().breakglass.revoke(body.id)
        if grant is None:
            return JSONResponse({"error": f"grant {body.id} is not open"}, status_code=409)
        return JSONResponse({"id": grant.id, "state": grant.state})

    @app.post("/api/breakglass/postmortem")
    def breakglass_postmortem(body: BreakGlassPostmortem,
                              x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        try:
            grant = proxy().breakglass.postmortem(body.id, body.note)
        except BreakGlassRefused as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse({"id": grant.id, "state": grant.state, "note": grant.postmortem,
                             "postmortem_at": grant.postmortem_at})

    # ------------------------------------------------------------------- reset
    @app.post("/reset")
    def reset(body: Optional[ResetRequest] = None,
              x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """Rotate the chain (archive it, record the rotation) and re-issue the orders.

        A reset is a maintainer action with a name on it, not an anonymous eraser: it needs
        the operator token, and the closed chain survives in the archive (finding V2).
        """
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        body = body or ResetRequest()
        rotation = proxy().issue_all(reset_registry=True,
                                     reason=body.reason or "manual reset",
                                     actor=body.actor or "operator")
        return JSONResponse({"ok": True, "rotated": rotation, "state": proxy().state()})

    # --------------------------------------------------------- dev probe (signature)
    @app.post("/_dev/tamper")
    def dev_tamper(body: TamperRequest,
                   x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """Dev-only: widen a signed order *after* issuance, to prove the gate trusts the
        signature and not the object in memory. Disabled unless WARRNT_DEV=1."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        if not settings.dev:
            return JSONResponse({"error": "tamper probe is dev-only (set WARRNT_DEV=1)"},
                                status_code=403)
        p = proxy()
        warrant = p.warrants.get(body.warrant)
        if warrant is None:
            return JSONResponse({"error": "unknown warrant", "warrant": body.warrant},
                                status_code=404)
        widened = None
        for rule in warrant.rules:
            for guard in rule.guards:
                if isinstance(guard.value, (int, float)):
                    guard.value = guard.value * 1000          # e.g. 50,000 -> 50,000,000 PLN
                    widened = {"param": guard.param, "value": guard.value}
                    break
            if widened:
                break
        if widened is None:
            warrant.scope = warrant.scope + " · everything forever"
            widened = {"scope": warrant.scope}
        return JSONResponse({"ok": True, "warrant": warrant.id, "mutated": widened,
                             "sig_ok": p.issuer.signature_ok(warrant)})

    return app


app = None
if os.environ.get("WARRNT_EAGER_APP", "").strip():
    app = create_app()
