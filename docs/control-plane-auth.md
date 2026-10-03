# The operator door: who may touch the control plane, and what a reset leaves behind

Two findings from the adversary walk of 2026-10-03 (`docs/roast-journey-redteam-2026-10-03.md`)
are fixed here, and the tests that pin them live in `tests/test_redteam_p0.py`.

## 1. Mutations need the operator token (finding V1)

Every route that changes the node - `POST /reset`, `POST /revoke`,
`POST /api/breakglass`, `POST /api/breakglass/revoke`,
`POST /api/breakglass/postmortem`, `POST /_dev/tamper` - now requires the header

```
X-WARRNT-Admin: <token>
```

The token is `WARRNT_ADMIN_TOKEN`. If it is not set, the node generates one at
startup and prints it once to its own log, so "no token configured" is never the
same thing as "anyone may reset this node". Reads (`/api/state`, `/verify`,
`/receipts`, `/anchor`) stay open: the operator's own screen has to be able to look
at the node, and after the fix below the chain no longer carries personal values.

The console keeps the token in the browser (`localStorage['warrnt_admin']`) and asks
for it once, on the first 401 - the refusal is visible on the screen, not silent.

## 2. A reset rotates the chain instead of erasing it (finding V2)

`/reset` used to empty the log and let the anchor sign `GENESIS / length 0`, so a
wiped node looked exactly like a fresh one: `verify ok=True`, `anchor signed`.
A demo rerun could destroy the evidence and still show green.

Now a reset with history:

1. copies the live chain to `<chain>.<stamp>.<n>.jsonl` and fsyncs it;
2. appends a rotation record - closed head, closed length, archive name, sha256 of
   the archive, reason, actor - to `<chain>.rotations.jsonl`, which is itself
   append-only and never rewritten;
3. seals the closed head in the anchor log *before* sealing the fresh empty chain;
4. starts the new chain.

`GET /verify` and `GET /anchor` now carry a `history` block: `rotations`,
`archived_rows`, `last_closed_head`, `archives_ok`, `problems`. If a rotated segment
was deleted or edited after the fact, `archives_ok` is false and both verdicts turn
red - erasure is detected, not rewarded. A green `ok` on a rotated node means
"the chain since the last rotation", and the history block says so.

## 3. Two more from the same walk (V5, V6)

* **One grant, one execution (V5).** `active()` only read the grant, so two calls
  arriving together could both see it and both execute. The spend is now an atomic
  `claim()` under a lock: the winner executes, the loser is refused and the refusal
  lands on the chain like any other decision.
* **A failed act is still a record (V6).** If the upstream raised after being
  invoked, the chain kept no exec receipt - it went quiet exactly when the story
  got interesting. The exec receipt is now written with `outcome="ok"` or
  `"outcome=error"` and the error text, and the agent's answer carries
  `upstream_error`.

## 4. Values never enter the chain (finding V3)

The decision receipt used to carry the request's *raw* arguments, so a call the node
had just decided to `redact` left the personal values in the append-only chain -
and `GET /receipts` handed them back to anyone. Receipts now record `param_keys`
(the field names) and `params_sha256` (a digest of what was asked for), never the
values.

## The tests

`tests/test_redteam_p0.py`, seven tests, one per promise:

| test | pins |
| --- | --- |
| `test_control_plane_refuses_anonymous_mutations` | V1 |
| `test_anonymous_breakglass_leaves_no_grant` | V1 |
| `test_the_token_is_what_opens_the_door` | V1 (guarded, not broken) |
| `test_reset_rotates_the_chain_instead_of_erasing_it` | V2 |
| `test_deleting_the_archive_turns_the_verdict_red` | V2 |
| `test_anchor_verdict_is_not_green_when_history_is_gone` | V2 |
| `test_a_receipt_never_carries_the_request_values` | V3 |
| `test_an_unknown_agent_receipt_also_drops_the_values` | V3 |
| `test_a_single_grant_cannot_be_spent_twice_under_concurrency` | V5 |
| `test_an_upstream_failure_after_the_decision_still_lands_on_the_chain` | V6 |

Proof runs after the fix: `pytest` 115 passed · `scripts/security_boundaries.py`
29/29 · `scripts/verify_live.py` 20/20 · `scripts/console_check.py` 35/35.
