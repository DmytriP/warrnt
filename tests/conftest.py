import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from fastapi.testclient import TestClient

from warrnt.api import create_app
from warrnt.config import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(
        home=tmp_path,
        registry_path=tmp_path / "receipts.jsonl",
        key_path=tmp_path / "issuer.key",
        upstream_url="",
        host="127.0.0.1",
        port=0,
        dev=True,
    )


@pytest.fixture
def app(settings):
    return create_app(settings=settings)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def tokens(client):
    return {a["id"]: a["token"] for a in client.get("/agents").json()}


def call(client, tokens, agent, tool, args):
    return client.post("/mcp",
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": tool, "arguments": args}},
                       headers={"X-WARRNT-Agent": agent, "X-WARRNT-Token": tokens.get(agent, "")})
