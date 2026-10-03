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
python3 -m pytest -q                 # 50 unit + API tests
python3 scripts/verify_live.py       # 20 checks against a live uvicorn process
python3 scripts/security_boundaries.py   # 29 adversarial checks (journal/permissions/kill-switch)
python3 scripts/redteam_rewrite_gap.py   # the rewrite attack, before and after the anchor
python3 scripts/upstream_check.py    # 17 checks against a real MCP server (two processes, its own log)
python3 scripts/console_check.py     # 35 checks: the console is served and its kill button is real
```

P2.3 control checkpoint — assert the whole vector happened on a live node:

```bash
python3 scripts/demo_client.py http://127.0.0.1:8111 > /tmp/transcript.json
python3 scripts/checkpoint_p23.py /tmp/transcript.json   # 7/7, exits non-zero on failure
```

Raw evidence of the last green run: `docs/checkpoint-p2.3.out`.

One command for the whole chain (boots its own node, clean state, prints the run):
`make first-demo` (or `python3 scripts/first_demo_path.py`). It is the first demo path:
order → policy → deny → brake → receipt → verify → anchor, asserted inline.

Drive the demo vector (the 3:47 moment) against a running node:

```bash
WARRNT_DEV=1 python3 -m warrnt serve --port 8099   # terminal A
python3 scripts/demo_client.py http://127.0.0.1:8099   # terminal B
```

`WARRNT_DEV=1` exposes agent tokens on `GET /agents` so the demo client can authenticate.
It is a demo convenience, not an API.

## The console screen — the face of the demo

The node serves its own console at `GET /`. It is not a mockup and not a separate app:

```bash
WARRNT_DEV=1 python3 -m warrnt serve --port 8099
# open http://127.0.0.1:8099/   — the screen the jury looks at
python3 scripts/demo_client.py http://127.0.0.1:8099   # drive the 3:47 vector in it
```

* **Live by construction.** The page polls `GET /api/state` every 1.5 s and renders exactly
  that; there is no second source of truth to drift from. Its four tiles are the four
  bricks: agents (order), warrants (scope on parameters), kill switch (brake), receipts
  (proof) — plus footer KPIs for chain integrity, outside-perimeter executions, and
  time-to-stop.
* **The kill switch is real.** The button POSTs `/revoke` to the node and re-polls; the
  halt, the pulled warrant and the new `revoked` receipt you then see are the node's, not
  the page's. Stop latency is measured by the node itself: it times the pull against the
  stopped agent's next outbound call, so the number on screen is an observation.
* **It falls back.** Open the same file from disk (or `?source=demo`) with no node
  reachable and it plays a looping offline scenario, so the screen still tells the story
  from a laptop with no server. The badge shows which of the two you are watching.
* **Two checks keep it honest.** `scripts/console_check.py` boots the node and asserts over
  HTTP that the screen is served, that every field it reads exists, and that the button's
  exact request (`POST /revoke`) produces a halt the state confirms.
  `scripts/console_shot.py` renders the live screen with headless Chromium — evidence for
  the Design brick, produced from a running node rather than a design file.

```bash
python3 scripts/console_check.py                       # 35 checks, exits non-zero on failure
python3 scripts/console_shot.py --outdir state/shots   # console-live.png from a live node
```

## The four bricks, and where each lives

| Brick | What it means | Where |
|---|---|---|
| **1. Order** | signed identity: scope + TTL + signature | `warrnt/warrants.py`, `GET /warrants` returns `sig_ok` |
| **2. Pre-exec policy** | guards on the call's parameters, verified order first | `warrnt/policy.py`, seeded rules in `warrnt/seed.py` |
| **3. Brake** | pull the warrant, halt the agent chain | `POST /revoke`, `MCPProxy.revoke` |
| **4. Receipt** | append-only hash-chained registry | `warrnt/registry.py`, `GET /verify`, `GET /receipts` |
| **4b. Anchor** | the head is signed with the issuer key on every append, so a rewrite cannot be hidden | `warrnt/anchor.py`, `GET /anchor` |

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | the console screen — a live view of this node, served from the package |
| `POST` | `/mcp` | JSON-RPC 2.0 `tools/call` — the interception point. Headers: `X-WARRNT-Agent`, `X-WARRNT-Token` |
| `POST` | `/revoke` | `{"agent": "..."}` or `{"warrant": "..."}` → halt + warrant pulled |
| `GET` | `/state` | live contract (agents, warrants, receipts, executor calls, chain) |
| `GET` | `/warrants` | signed artifacts + per-warrant signature validity |
| `GET` | `/receipts` | the full append-only registry |
| `GET` | `/verify` | recompute the chain from genesis (plus the anchor verdict) |
| `GET` | `/anchor` | the last signed head and whether the live registry still matches it |
| `GET` | `/agents` | identities (tokens only when `WARRNT_DEV=1`) |
| `GET` | `/health` | liveness + chain head |
| `GET` | `/api/state` | the console's contract (alias of `/state`, plus `revoked` / `last_stop`) |
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
* A hash chain alone does not stop a *consistent rewrite* (recompute every hash from
  genesis). That is why the node seals the head with the issuer key on every append: edit
  `receipts.jsonl` and the head no longer matches the signed anchor, and you cannot sign a
  new anchor without the key. `scripts/redteam_rewrite_gap.py` runs both halves of that.
* Revocation latency is measured on a live agent loop, not declared: the node times the
  pull against the stopped agent's next outbound call and reports it as `last_stop`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WARRNT_HOME` | `./state` | state directory |
| `WARRNT_ISSUER_KEY` | generated at `<home>/issuer.key` (0600) | signing key |
| `WARRNT_ANCHOR` | `<home>/anchors.jsonl` | anchor log; point it at storage outside the node (WORM, another host) |
| `WARRNT_UPSTREAM` | unset | URL of a real MCP server (streamable HTTP) to front, e.g. `http://127.0.0.1:8210/mcp`; unset → in-process sandbox |
| `WARRNT_DEV` | `0` | expose agent tokens on `/agents` |
| `WARRNT_HOST` / `WARRNT_PORT` | `0.0.0.0` / `8099` | bind address |

## Layout

```
warrnt/
  canonical.py   deterministic JSON (same record -> same bytes -> same hash)
  models.py      Decision, Guard, Rule, Warrant, WarrantSpec, AgentState
  registry.py    AppendOnlyRegistry: hash chain, fsync, verify from genesis
  anchor.py      HeadAnchor: signs the head on every append (closes the rewrite gap)
  warrants.py    WarrantIssuer: sign, verify, issue, per-agent tokens
  policy.py      PolicyEngine: guards on parameters, PII inspection
  upstream.py    SandboxUpstream (counts executions) / MCPUpstream (real MCP server)
  proxy.py       MCPProxy: the node - intercept, revoke, state
  seed.py        the three seed warrants (edit here to change policy)
  api.py         FastAPI app factory + routes
  cli.py         `python -m warrnt serve|demo|state`
tests/           50 tests: signing, TTL, guards, chain tamper, anchor, end-to-end API
scripts/         first_demo_path.py, verify_live.py, upstream_check.py,
                 mcp_fixture_server.py, security_boundaries.py,
                 redteam_rewrite_gap.py, console_check.py, console_shot.py,
                 checkpoint_p23.py, demo_client.py
docs/            architecture.md + the *.out transcripts of the last green run
```

## What is next

* **stdio transport** — the node fronts its upstream over streamable HTTP only; a stdio
  transport is not claimed until it exists.
* **Ephemeral identity** — agent tokens are static per order (enough for a 24-hour demo);
  rotation and short-lived credentials are the next step.
* **Anchor on external storage** — `WARRNT_ANCHOR` already points anywhere; production
  would place it on a separate host or WORM storage rather than beside the registry.

The console screen (below) and the `/revoke` button on it are **already built** — the node
serves `/` from the package and the button POSTs to the node, not to the page.

## Live proof against a real upstream

`make upstream-check` starts a real MCP server (`scripts/mcp_fixture_server.py`, official
`mcp` SDK, streamable HTTP) as a *separate process with its own access log*, points
`WARRNT_UPSTREAM` at it, drives the vector, and asserts each outcome twice — once from the
node's receipts and once from the upstream's log. The negative claim ("the denied export
never reached upstream") is read from the upstream process, not from the node.

Evidence: `docs/d1-upstream-2026-10-03.out`.
