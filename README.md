# WARRNT — no warrant, no action

A proxy that sits in front of an MCP server and decides **before execution** whether an
agent's tool-call is allowed. Not a dashboard about agents — the thing that stops them.

```
order  ->  policy on parameters  ->  brake  ->  receipt
```

Every call carries an ephemeral identity bound to a signed *warrant* (scope + TTL +
HMAC-SHA256 signature). The proxy reads the **parameters of the call itself** and returns
`allow` / `deny` / `require-human`. A deny means the downstream tool is never invoked.
Every decision is appended to a hash-chained receipt registry **before** anything runs.
`POST /revoke` pulls the warrant, and the running agent observes it on its next outbound
call.

This repository is **one node, not a platform**: no admin UI, no multi-tenant issuer, no
stdio transport. Keep it that way until the node is undeniable.

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python3 -m warrnt serve --port 8099      # the node (FastAPI + uvicorn)
curl -s localhost:8099/health | jq
curl -s localhost:8099/state  | jq '.agents,.chain'
```

Run the checks — they exercise a real server, not mocks:

```bash
python3 -m pytest -q          # 44 unit + API tests
python3 scripts/verify_live.py  # 20 checks against a live uvicorn process
```

P2.3 control checkpoint — assert the whole vector happened on a live node:

```bash
python3 scripts/demo_client.py http://127.0.0.1:8111 > /tmp/transcript.json
python3 scripts/checkpoint_p23.py /tmp/transcript.json   # 7/7, exits non-zero on failure
```

Raw evidence of the last green run: `docs/checkpoint-p2.3.out`.

Drive the demo vector (the 3:47 moment) against a running node:

```bash
WARRNT_DEV=1 python3 -m warrnt serve --port 8099   # terminal A
python3 scripts/demo_client.py http://127.0.0.1:8099   # terminal B
```

`WARRNT_DEV=1` exposes agent tokens on `GET /agents` so the demo client can authenticate.
It is a demo convenience, not an API.

## The four bricks, and where each lives

| Brick | What it means | Where |
|---|---|---|
| **1. Order** | signed identity: scope + TTL + signature | `warrnt/warrants.py`, `GET /warrants` returns `sig_ok` |
| **2. Pre-exec policy** | guards on the call's parameters, verified order first | `warrnt/policy.py`, seeded rules in `warrnt/seed.py` |
| **3. Brake** | pull the warrant, halt the agent chain | `POST /revoke`, `MCPProxy.revoke` |
| **4. Receipt** | append-only hash-chained registry | `warrnt/registry.py`, `GET /verify`, `GET /receipts` |

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/mcp` | JSON-RPC 2.0 `tools/call` — the interception point. Headers: `X-WARRNT-Agent`, `X-WARRNT-Token` |
| `POST` | `/revoke` | `{"agent": "..."}` or `{"warrant": "..."}` → halt + warrant pulled |
| `GET` | `/state` | live contract (agents, warrants, receipts, executor calls, chain) |
| `GET` | `/warrants` | signed artifacts + per-warrant signature validity |
| `GET` | `/receipts` | the full append-only registry |
| `GET` | `/verify` | recompute the chain from genesis |
| `GET` | `/agents` | identities (tokens only when `WARRNT_DEV=1`) |
| `GET` | `/health` | liveness + chain head |
| `GET` | `/api/state` | alias of `/state` kept for the console screen (P3) |
| `POST` | `/reset` | re-issue the seed warrants, clear counters |
| `POST` | `/_dev/tamper` | dev-only: widen a signed order in memory to prove the gate refuses it (`WARRNT_DEV=1`) |

Denials come back as JSON-RPC errors, and nothing runs:

| decision | code | meaning |
|---|---|---|
| `deny` | `-32001` | outside warrant scope, a guard failed, or the order's signature is invalid |
| `human` | `-32002` | require-human: pause, do not execute |
| `revoked` | `-32003` | warrant pulled / agent halted |
| `expired` | `-32004` | TTL elapsed |

## Why it is believable (not a claim)

* A denied call never reaches the upstream — `executor_calls` in `/state` counts real
  executions; `scripts/verify_live.py` asserts the counter is unchanged after a denial.
* The order is verified at the gate, not merely displayed: `PolicyEngine` refuses a warrant
  whose signature does not check out *before* reading its rules, so widening a limit in
  memory does not widen it in practice. `/_dev/tamper` + the live script demonstrate this.
* Identity is scoped: a token is bound to one agent and one warrant; a token minted for one
  order never authorises another.
* The signature is bound to the payload: edit `scope` after signing and `sig_ok` is false.
* The registry is hash-chained and `fsync`ed per entry: edit or delete any line and
  `/verify` fails at that index.
* Revocation latency is measured on a live agent loop, not declared.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WARRNT_HOME` | `./state` | state directory |
| `WARRNT_ISSUER_KEY` | generated at `<home>/issuer.key` (0600) | signing key |
| `WARRNT_UPSTREAM` | unset | real MCP endpoint to front; unset → in-process sandbox |
| `WARRNT_DEV` | `0` | expose agent tokens on `/agents` |
| `WARRNT_HOST` / `WARRNT_PORT` | `0.0.0.0` / `8099` | bind address |

## Layout

```
warrnt/
  canonical.py   deterministic JSON (same record -> same bytes -> same hash)
  models.py      Decision, Guard, Rule, Warrant, WarrantSpec, AgentState
  registry.py    AppendOnlyRegistry: hash chain, fsync, verify from genesis
  warrants.py    WarrantIssuer: sign, verify, issue, per-agent tokens
  policy.py      PolicyEngine: guards on parameters, PII inspection
  upstream.py    SandboxUpstream (counts executions) / HttpUpstream (real MCP)
  proxy.py       MCPProxy: the node - intercept, revoke, state
  seed.py        the three seed warrants (edit here to change policy)
  api.py         FastAPI app factory + routes
  cli.py         `python -m warrnt serve|demo|state`
tests/           35 tests: signing, TTL, guards, chain tamper, end-to-end API
scripts/         verify_live.py (live process), demo_client.py
docs/            architecture.md
```

## What is next

* P3 — the single dense console screen (agents / warrants / kill / proof) against `/state`.
* Wire `/revoke` from the screen, not just the API.
* A real upstream MCP server behind `WARRNT_UPSTREAM` for the stage demo.
* stdio transport — not claimed until it exists.
