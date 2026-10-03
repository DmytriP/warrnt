#!/usr/bin/env python3
"""Render the console screen to PNG from a LIVE node - evidence for the Design brick.

Not a mockup: this boots the real node, runs the real 3:47 vector through it (so the screen
has allow / deny / revoked receipts and a measured time-to-stop), then points headless
Chromium at the node's own URL and captures what it renders. It also captures the offline
`?source=demo` copy, which is what the file:// version of the screen shows.

    python3 scripts/console_shot.py --outdir state/shots
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warrnt import demo  # noqa: E402

CHROMIUM = shutil.which("chromium") or shutil.which("chromium-browser") or "chromium"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_up(url: str, timeout: float = 25.0) -> None:
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    raise RuntimeError("node never came up")


def shot(url: str, out: Path, wait_ms: int = 4500) -> None:
    cmd = [CHROMIUM, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
           "--force-device-scale-factor=1", "--window-size=1600,900",
           f"--virtual-time-budget={wait_ms}", f"--screenshot={out}", url]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    if not out.exists():
        raise RuntimeError(f"chromium produced no file: {res.stderr[-400:]}")
    print(f"  wrote {out} ({out.stat().st_size} bytes)")


def dom_qa(url: str, out: Path, wait_ms: int = 4500) -> str:
    """Deterministic check of what the live page rendered: no eyes needed.

    The page appends #qa-report (data-tiles + scrollHeight/innerHeight) once the first poll
    lands. Read it out of the DOM so 'the screen shows the node's data' is machine-checkable.
    """
    cmd = [CHROMIUM, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
           "--window-size=1600,900", f"--virtual-time-budget={wait_ms}", "--dump-dom", url]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    dom = res.stdout
    out.write_text(dom, encoding="utf-8")
    import re
    m = re.search(r'<div id="qa-report"[^>]*>(.*?)</div>', dom, re.S)
    line = m.group(1) if m else "qa-report MISSING"
    print(f"  qa: {line[:220]}")
    return line


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=str(ROOT / "state" / "shots"))
    ap.add_argument("--with-demo", action="store_true", default=True)
    args = ap.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    home = ROOT / "state" / "shot-home"
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)

    port = free_port()
    url = f"http://127.0.0.1:{port}"
    env = {**os.environ, "WARRNT_DEV": "1", "WARRNT_HOME": str(home), "WARRNT_PORT": str(port)}
    env.pop("WARRNT_UPSTREAM", None)
    log = open(home / "server.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "warrnt", "serve", "--port", str(port)],
                            cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_up(url)
        print(f"node up at {url}")
        demo.run(url)                       # real vector: allow, deny, revoke, stop latency
        time.sleep(2.0)
        shot(url + "/", outdir / "console-live.png")
        dom_qa(url + "/?qa=1", outdir / "console-qa-dom.html")
        if args.with_demo:
            shot(url + "/?source=demo", outdir / "console-offline-demo.png", 5000)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
