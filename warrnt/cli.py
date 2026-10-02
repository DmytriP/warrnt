"""``warrnt`` CLI: serve the node, run the demo vector, print the live state."""
from __future__ import annotations

import argparse
import json

from .config import Settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warrnt", description="WARRNT - MCP tool-call interception node")
    sub = parser.add_subparsers(dest="cmd")

    serve = sub.add_parser("serve", help="run the FastAPI node")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--no-seed", action="store_true", help="do not re-issue seed warrants on boot")

    demo = sub.add_parser("demo", help="run the 3:47 vector against a live node")
    demo.add_argument("--url", default="http://127.0.0.1:8099")

    state = sub.add_parser("state", help="print the live contract from a running node")
    state.add_argument("--url", default="http://127.0.0.1:8099")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        import uvicorn

        from .api import create_app

        settings = Settings.load()
        app = create_app(settings=settings, seed=not args.no_seed)
        uvicorn.run(app, host=args.host or settings.host, port=args.port or settings.port,
                    log_level="warning")
        return 0

    if args.cmd == "demo":
        from .demo import run

        print(json.dumps(run(args.url), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "state":
        import urllib.request

        with urllib.request.urlopen(args.url.rstrip("/") + "/state", timeout=5) as resp:
            print(json.dumps(json.loads(resp.read().decode()), indent=2, ensure_ascii=False))
        return 0

    parser.print_help()
    return 2
