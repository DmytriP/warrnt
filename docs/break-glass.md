# Break-glass — one named person, one pause, fifteen minutes

A control layer that can never be asked to move is a control layer people route around. The
honest design is not "no way out"; it is a way out that leaves the same trail as a refusal.

## What may be opened, and what may never be

The taxonomy (`warrnt/actions.py`) is the floor and it does not move:

| class | decider | can break-glass lower it? |
|---|---|---|
| `observe`, `draft` | the node | nothing to open |
| `read_personal` | the node · fields on the record | — |
| `write_reversible` | the node under a signed order | — |
| `irreversible` | **a person** (money moves, data is deleted, a document is filed) | **never** |
| `authorize` | **operator-human only** (a warrant, a limit, a registration) | **never** |

Break-glass therefore does not lift a *class*; it lifts a *policy pause* — the case where a
warrant rule says `human` for an act the class itself would have let the node decide. The
seed carries exactly one such order: `W-4423` (agent `report-bot`), where a mass
`crm.bulk_export` is declared a person's decision rather than a schedule's.

A grant for `infra.deploy` is refused with the reason, and a grant pushed into the store by
hand (bypassing validation) is *ignored by the gate* — the check runs again at the moment of
use, on the signature and on the class.

## The rules a grant obeys

* **A name.** `human` must be a person's name. There is no anonymous switch.
* **A reason.** The grant carries why it was opened; it is on the chain.
* **A scope of one.** One agent, one tool. No wildcards.
* **A window.** `ttl_s` ≤ 900 (15 min) — a hard cap, not a suggestion. `expires_in_s` counts
  down; the clock is the expiry.
* **One call.** The first call it lifts spends it. The next call waits for a person again.
* **A signature.** The grant is signed with the same issuer key as an order. Widening the
  tool it covers after signing invalidates it.
* **A debt.** A spent grant owes a review: no second grant for that agent until the
  post-mortem is written. (The review note cannot be blank.)
* **Fail-closed stays closed.** A revoked order is not reopened by a grant, and the
  kill switch clears every open grant.

## The three receipts

Every break-glass event is a row on the same append-only, hash-chained ledger as the
refusals — `verify` covers it like anything else:

1. `grant` — `tool=/break-glass`, reason names the grant id, the person, the tool and the
   window;
2. `use` — the executed call itself records `break_glass: BG-000N` in its reason, so the
   chain shows which call was let through and who opened the door;
3. `review` — `tool=/break-glass`, the post-mortem note.

## Endpoints

```
POST /api/breakglass            {human, agent, tool, reason, ttl_s≤900} -> grant | 409
GET  /api/breakglass            every grant: state, window left, signature, debt
POST /api/breakglass/revoke     {id} -> close early (state=revoked; it then lifts nothing)
POST /api/breakglass/postmortem {id, note} -> the review a used grant owes
```

`409` carries the sentence that explains the refusal, e.g.
`class irreversible is the taxonomy's own floor · a person decides, and no grant may lift it`.

`GET /api/state` includes `breakglass` — the console's panel 06 renders it live.

## Demo path (thirty seconds, on the live node)

```bash
# the pause: a machine cannot do this on a schedule
curl -s localhost:8080/mcp -H 'X-WARRNT-Agent: report-bot' -H "X-WARRNT-Token: $T" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"crm.bulk_export","arguments":{"table":"customers"}}}'
# -> error -32002 · "a mass export is a person's decision, not a schedule's"

# the door: one name, one tool, fifteen minutes
curl -s localhost:8080/api/breakglass -H 'Content-Type: application/json' \
  -d '{"human":"Anna Kowalska","agent":"report-bot","tool":"crm.bulk_export",
       "reason":"board deck: 12 rows","ttl_s":900}'
# -> {"id":"BG-0001", ... "single_use":true}

# the same call now runs, once; the receipt names Anna and BG-0001
# the second call waits for a person again; a new grant is refused until the review exists

# and the floor: this one is refused, always
curl -s localhost:8080/api/breakglass -H 'Content-Type: application/json' \
  -d '{"human":"Anna Kowalska","agent":"deploy-agent","tool":"infra.deploy","reason":"prod down"}'
# -> 409 · "class irreversible is the taxonomy's own floor"
```

## Tests

`tests/test_breakglass.py` (unit + HTTP): the pause holds without a grant; a grant opens it
exactly once; the irreversible floor refuses the grant *and* ignores a hand-inserted one;
`authorize` is refused; a revoked order is not reopened and the grant is not spent by it; no
anonymous switch (blank human, blank reason); the window cap; expiry by clock; a widened
grant fails its signature; the owed review blocks the next grant and is recorded; the grant,
the use and the review are on one verifying chain; `state` exposes grants and the debt.
