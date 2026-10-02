"""Brick 4 - the append-only, hash-chained receipt registry."""
import json

from warrnt.registry import AppendOnlyRegistry


def test_chain_links_and_verifies(tmp_path):
    reg = AppendOnlyRegistry(str(tmp_path / "r.jsonl"))
    a = reg.append(decision="allow", tool="t")
    b = reg.append(decision="deny", tool="u")
    assert a["prev"] == AppendOnlyRegistry.GENESIS
    assert b["prev"] == a["hash"]
    assert reg.verify()["ok"] is True
    assert reg.verify()["length"] == 2


def test_persistence_across_reopen(tmp_path):
    path = str(tmp_path / "r.jsonl")
    AppendOnlyRegistry(path).append(decision="allow")
    reopened = AppendOnlyRegistry(path)
    assert reopened.verify()["ok"] is True
    assert len(reopened.entries) == 1
    assert reopened.head == reopened.entries[0]["hash"]


def test_editing_a_receipt_is_detected(tmp_path):
    path = tmp_path / "r.jsonl"
    reg = AppendOnlyRegistry(str(path))
    reg.append(decision="allow", tool="crm.read")
    reg.append(decision="deny", tool="crm.bulk_export")

    lines = path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["decision"] = "deny"            # rewrite history
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    result = AppendOnlyRegistry(str(path)).verify()
    assert result["ok"] is False
    assert result["broken_at"] == 0


def test_deleting_an_entry_is_detected(tmp_path):
    path = tmp_path / "r.jsonl"
    reg = AppendOnlyRegistry(str(path))
    reg.append(decision="allow")
    reg.append(decision="deny")
    reg.append(decision="allow")

    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")   # drop the middle

    assert AppendOnlyRegistry(str(path)).verify()["ok"] is False


def test_head_is_genesis_when_empty(tmp_path):
    reg = AppendOnlyRegistry(str(tmp_path / "empty.jsonl"))
    assert reg.head == AppendOnlyRegistry.GENESIS
    assert reg.verify() == {"ok": True, "length": 0, "head": AppendOnlyRegistry.GENESIS[:16]}
