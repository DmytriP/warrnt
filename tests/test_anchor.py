"""Brick 4 hardening - the head anchor closes the consistent-rewrite gap (finding M1).

The chain alone detects an edit or a deletion. It does not detect a rewrite from genesis:
recompute every hash and verify() goes green again. The anchor seals the head with the
issuer key on every append, so a rewrite cannot be made to match what was signed.
"""
from __future__ import annotations

import hashlib

from warrnt.anchor import HeadAnchor
from warrnt.canonical import canon
from warrnt.registry import AppendOnlyRegistry
from warrnt.warrants import WarrantIssuer


def _anchor(tmp_path, issuer):
    return HeadAnchor(str(tmp_path / "anchors.jsonl"), issuer.sign, now=lambda: 1000.0)


def test_seal_then_verify_is_green(tmp_path):
    issuer = WarrantIssuer(key=b"k")
    a = _anchor(tmp_path, issuer)
    a.seal("a" * 64, 7)
    v = a.verify("a" * 64, 7)
    assert v["ok"] is True and v["signed"] is True and v["anchored"] is True


def test_a_rewritten_head_does_not_match_the_signed_anchor(tmp_path):
    issuer = WarrantIssuer(key=b"k")
    a = _anchor(tmp_path, issuer)
    a.seal("a" * 64, 7)
    forged = a.verify("b" * 64, 7)            # attacker rewrote the chain to a new head
    assert forged["ok"] is False and forged["signed"] is True
    assert "rewrite detected" in forged["reason"]


def test_editing_the_anchor_is_detected(tmp_path):
    issuer = WarrantIssuer(key=b"k")
    a = _anchor(tmp_path, issuer)
    a.seal("a" * 64, 7)
    a.records[-1]["head"] = "b" * 64          # attack the anchor itself, without the key
    v = a.verify("b" * 64, 7)
    assert v["ok"] is False and v["signed"] is False
    assert "anchor was edited" in v["reason"]


def test_without_an_anchor_a_consistent_rewrite_passes(tmp_path):
    """The attack the anchor defends against - proven, so the fix is not cosmetic."""
    path = tmp_path / "receipts.jsonl"
    reg = AppendOnlyRegistry(str(path))
    reg.append(decision="deny", agent="a", tool="t", reason="outside scope")
    reg.append(decision="allow", agent="a", tool="t2", reason="in scope")
    assert reg.verify()["ok"] is True

    prev = AppendOnlyRegistry.GENESIS
    forged = []
    for entry in reg.entries:
        body = {k: v for k, v in entry.items() if k != "hash"}
        if body.get("decision") == "deny":
            body["decision"] = "allow"        # the forgery
        body["prev"] = prev
        body["hash"] = hashlib.sha256((prev + canon(body)).encode()).hexdigest()
        prev = body["hash"]
        forged.append(body)

    forged_path = tmp_path / "forged.jsonl"
    forged_path.write_text("\n".join(canon(e) for e in forged) + "\n", encoding="utf-8")
    assert AppendOnlyRegistry(str(forged_path)).verify()["ok"] is True   # chain alone: fooled
    assert forged[-1]["hash"] != reg.entries[-1]["hash"]                 # anchor: head moved


def test_the_live_node_anchors_every_decision(client, tokens):
    reply = client.post("/mcp",
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "crm.read",
                                         "arguments": {"table": "tickets", "limit": 1}}},
                        headers={"X-WARRNT-Agent": "support-copilot",
                                 "X-WARRNT-Token": tokens.get("support-copilot", "")})
    assert reply.json()["result"]["decision"] == "allow"

    anchor = client.get("/anchor").json()
    chain = client.get("/verify").json()
    assert anchor["anchors"] >= 1
    assert anchor["verdict"]["ok"] is True
    assert chain["anchor"]["ok"] is True and chain["anchor"]["signed"] is True
    assert anchor["last"]["head"][:16] == chain["head"]


def test_reset_reanchors_the_empty_registry(client):
    client.post("/reset", json={})
    anchor = client.get("/anchor").json()
    assert anchor["verdict"]["ok"] is True
    assert anchor["last"]["length"] == 0
