#!/usr/bin/env python3
"""Drive the 3:47 vector against an already-running node.

    WARRNT_DEV=1 python3 -m warrnt serve --port 8099   # terminal A
    python3 scripts/demo_client.py http://127.0.0.1:8099   # terminal B
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from warrnt.demo import run  # noqa: E402

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8099"
    print(json.dumps(run(url), indent=2, ensure_ascii=False))
