#!/usr/bin/env bash
set -euo pipefail
cd /root/.hermes/hackyeah/warrnt
uv pip install -r requirements.txt --python .venv/bin/python
