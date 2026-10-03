"""The control plane: one canonical Action per intercepted call, the human hold that
pauses an action, and answers built from the record itself.

The kernel still decides. This module is not an authority: it holds the *record* of what
the kernel decided (the canonical ``Action``), the one state the kernel cannot hold on its
own (a call paused for a person), and the answers a person asks for - assembled from the
records, never guessed. Where there is no record, the answer says so.

Two rules make this layer honest:

* values never enter the ledger - a request is kept as its keys and a digest (finding V3:
  the control layer must not become the largest PII store in the building). The single
  exception is an explicit hold, which keeps the request in memory so an approved action
  can still run; ``kept_for_hold`` says so on the object.
* a hold cannot outlive its order: if the agent is halted before a person decides, the
  hold expires and the refusal is recorded.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

MAX_ACTIONS = 200
PENDING = "pending"


class HoldRefused(RuntimeError):
    """A hold that cannot be resolved: unknown, already decided, or its agent was halted."""


def digest(params: dict[str, Any] | None) -> str:
    raw = json.dumps(params or {}, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def params_view(params: dict[str, Any] | None) -> dict[str, Any]:
    """Keys and a digest - never the values."""
    p = params or {}
    return {"keys": sorted(p.keys()), "sha256": digest(p), "values_withheld": True}


@dataclass
class Action:
    """The canonical object: the same one the API returns, the console renders and an
    answer quotes. Anything shown anywhere must come from here."""

    action_id: str
    run_id: str
    agent: str
    tool: str
    action_class: str = ""
    actor: str = ""
    warrant: str = "-"
    warrant_state: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    policy_result: str = ""
    decision: str = ""
    reason: str = ""
    upstream_contacted: bool = False
    execution_result: dict[str, Any] = field(default_factory=dict)
    receipt: str = ""
    ts: float = 0.0
    state: str = "decided"          # decided | pending | approved | denied | expired
    decided_by: str = ""
    decided_ts: float = 0.0
    kept_for_hold: bool = False
    values: dict[str, Any] = field(default_factory=dict, repr=False)

    def public(self) -> dict[str, Any]:
        out = {k: v for k, v in self.__dict__.items() if k != "values"}
        out["parameters"] = dict(self.parameters)
        return out


class ActionStore:
    """Bounded ledger of canonical Actions. One writer per call; reads are snapshots."""

    def __init__(self, limit: int = MAX_ACTIONS) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, Action] = {}
        self._order: list[str] = []
        self._limit = limit
        self._seq = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"A-{self._seq:04d}"

    def record(self, **kw: Any) -> Action:
        with self._lock:
            action_id = kw.pop("action_id", "") or self._next_id()
            action = Action(action_id=action_id, **kw)
            self._items[action_id] = action
            self._order.append(action_id)
            while len(self._order) > self._limit:
                self._items.pop(self._order.pop(0), None)
            return action

    def get(self, action_id: str) -> Optional[Action]:
        return self._items.get(action_id)

    def listing(self, state: str | None = None, limit: int = 60) -> list[dict[str, Any]]:
        with self._lock:
            ids = list(reversed(self._order))
            rows = [self._items[i] for i in ids if i in self._items]
        if state:
            rows = [r for r in rows if r.state == state]
        return [r.public() for r in rows[:limit]]

    def pending(self) -> list[dict[str, Any]]:
        return self.listing(state=PENDING, limit=60)

    def counts(self) -> dict[str, int]:
        with self._lock:
            rows = list(self._items.values())
        out = {"total": len(rows), PENDING: 0, "approved": 0, "denied": 0, "expired": 0}
        for r in rows:
            if r.state in out:
                out[r.state] += 1
        return out


def _pending_line(a: dict[str, Any]) -> str:
    return (f"{a['action_id']} · {a['agent']} → {a['tool']} ({a['action_class'] or 'unclassified'}) "
            f"· warrant {a['warrant']} ({a['warrant_state']}) · receipt #{a['receipt']}")


def _mentioned(q: str, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows whose agent, tool or system the question names. Empty means: the question
    named none, and only then may an answer fall back to "the last one in the record"."""
    rows = []
    words = set(re.findall(r"[a-z0-9_.]+", q))          # punctuation is not a name
    for a in actions:
        agent = str(a.get("agent", "")).lower()
        tool = str(a.get("tool", "")).lower()
        system = tool.split(".")[0]
        if (agent and agent in q) or (tool and tool in q) or (system and system in words):
            rows.append(a)
    return rows


def answer(question: str, actions: list[dict[str, Any]], state: dict[str, Any]) -> dict[str, Any]:
    """A grounded answer: every sentence is a field of a record, or an admission that the
    record is empty. No model, no guessing - the same rule the brief puts on Hermes."""
    q = (question or "").lower().strip()
    pending = [a for a in actions if a.get("state") == PENDING]
    receipts = state.get("receipts", [])
    ev = {"run_id": None, "action_id": None, "warrant": None, "decision": None,
          "upstream_contacted": None, "receipt": None}

    def pick(rows):
        return rows[0] if rows else None

    def ev_of(a):
        if not a:
            return ev
        return {"run_id": a.get("run_id"), "action_id": a.get("action_id"),
                "warrant": a.get("warrant"), "decision": a.get("decision"),
                "upstream_contacted": a.get("upstream_contacted"), "receipt": a.get("receipt")}

    # "what happens if I approve this?"
    if "approve" in q or "if i allow" in q:
        a = pick(pending)
        if a is None:
            return {"answer": "Nothing is waiting for you, so there is nothing to approve. "
                              "The record has no pending action.", "evidence": ev, "grounded": True}
        return {"answer": f"Approving {a['action_id']} runs {a['tool']} for agent {a['agent']} exactly once, "
                          f"with the parameters the hold kept, and writes two receipts: the human decision first, "
                          f"then the execution (rows returned). Until then the upstream has not been contacted. "
                          f"If you deny it instead, no upstream call happens at all.",
                "evidence": ev_of(a), "grounded": True}

    # "which action is waiting for me?"
    if "waiting" in q or "pending" in q or "for me" in q:
        if not pending:
            return {"answer": "No action is waiting for a person: the record holds no pending action.",
                    "evidence": ev, "grounded": True}
        body = "; ".join(_pending_line(a) for a in pending)
        return {"answer": f"{len(pending)} action(s) waiting for a person: {body}.",
                "evidence": ev_of(pending[0]), "grounded": True}

    # "did it reach the CRM / upstream / contact?"
    if "reach" in q or "upstream" in q or "contact" in q or "crm got" in q:
        named = _mentioned(q, actions)
        if named:
            reached = [a for a in named if a.get("upstream_contacted")]
            if not reached:
                last = named[0]
                return {"answer": f"No action against {last['tool'].split('.')[0]} in the record "
                                  f"reached the upstream: the last one ({last['action_id']}, "
                                  f"{last['tool']}) was decided '{last['decision']}' with "
                                  f"upstream_contacted=false, receipt #{last['receipt']}.",
                        "evidence": ev_of(last), "grounded": True}
            a = reached[0]
            return {"answer": f"Yes: {a['action_id']} ({a['tool']}) reached the upstream — "
                              f"receipt #{a['receipt']}, rows "
                              f"{a.get('execution_result', {}).get('rows', 0)}.",
                    "evidence": ev_of(a), "grounded": True}
        a = pick([r for r in actions if r.get("upstream_contacted")])
        if a is None:
            return {"answer": "No action in the record contacted the upstream: every decision so far was "
                              "a refusal or a hold, and the chain proves it (executed=false on each).",
                    "evidence": ev, "grounded": True}
        last = actions[0] if actions else None
        if last is not None and not last.get("upstream_contacted"):
            return {"answer": f"The last action ({last['action_id']}, {last['tool']}) did NOT reach the upstream — "
                              f"decision {last['decision']}, upstream_contacted=false, receipt #{last['receipt']}. "
                              f"The most recent execution that did reach it was {a['action_id']} ({a['tool']}).",
                    "evidence": ev_of(last), "grounded": True}
        return {"answer": f"Yes: {a['action_id']} ({a['tool']}) reached the upstream — receipt #{a['receipt']}, "
                          f"rows {a.get('execution_result', {}).get('rows', 0)}.",
                "evidence": ev_of(a), "grounded": True}

    # "why was X blocked?"
    if "why" in q or "blocked" in q or "denied" in q:
        named = _mentioned(q, actions)
        if not named:
            # An agent the node knows about, but with nothing in the record: the honest
            # answer is that there is no data - not the last refusal of somebody else.
            registered = [*state.get("agents", []), *state.get("actors", [])]
            known = [a for a in registered if str(a.get("id", "")).lower() in q]
            if known:
                ids = ", ".join(str(a.get("id")) for a in known)
                return {"answer": f"The record holds no action for {ids}: nothing by that agent "
                                  f"has reached the gate in this run, so there is no decision and "
                                  f"no receipt. I will not invent one.",
                        "evidence": ev, "grounded": True}
        refusals = [a for a in (named or actions) if a.get("decision") in ("deny", "revoked", "human")]
        row = pick(refusals)
        if named and not refusals:
            who = ", ".join(sorted({str(a["agent"]) for a in named}))
            return {"answer": f"The record holds no refusal for {who}: "
                              f"{len(named)} action(s) are logged and none of them was denied, "
                              f"revoked or held. The class of the last one is "
                              f"{named[0]['action_class'] or 'unclassified'}.",
                    "evidence": ev_of(named[0]), "grounded": True}
        if row is None:
            return {"answer": "No refusal is in the record, so there is nothing to explain. "
                              "If you name the agent I will look again.", "evidence": ev, "grounded": True}
        return {"answer": f"{row['action_id']}: {row['agent']} → {row['tool']} was decided "
                          f"'{row['decision']}' ({row['reason']}). upstream_contacted="
                          f"{str(row['upstream_contacted']).lower()}, receipt #{row['receipt']}. "
                          f"Class {row['action_class'] or 'unclassified'}, warrant {row['warrant']} ({row['warrant_state']}).",
                "evidence": ev_of(row), "grounded": True}

    # "show me the warrant"
    if "warrant" in q or "order" in q:
        ws = state.get("warrants", [])
        if not ws:
            return {"answer": "The record holds no warrant.", "evidence": ev, "grounded": True}
        w = ws[0]
        return {"answer": f"Warrant {w['id']} for agent {w['agent']}: scope '{w['scope']}', state {w['state']}, "
                          f"ttl {w['ttl']}s, signature {'valid' if w.get('sig_ok') else 'INVALID'}.",
                "evidence": {**ev, "warrant": w["id"]}, "grounded": True}

    # default: what is happening
    if q:
        return {"answer": f"Record: {len(state.get('agents', []))} agent(s), {len(receipts)} receipt(s), "
                          f"{len(pending)} pending. Last decision: "
                          + (f"{actions[0]['action_id']} — {actions[0]['agent']} → {actions[0]['tool']} "
                             f"'{actions[0]['decision']}' (upstream_contacted="
                             f"{str(actions[0]['upstream_contacted']).lower()}, receipt #{actions[0]['receipt']})."
                             if actions else "none in the record."),
                "evidence": ev_of(actions[0]) if actions else ev, "grounded": True}
    return {"answer": "Ask about the record: what is happening, why an agent was blocked, "
                      "which action is waiting, whether a call reached the upstream, or the warrant.",
            "evidence": ev, "grounded": True}
