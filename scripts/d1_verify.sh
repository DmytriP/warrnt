#!/usr/bin/env bash
# D1 main-scenario verification: run every live suite from a clean checkout state.
set -uo pipefail
cd /root/.hermes/hackyeah/warrnt
PY=.venv/bin/python
OUT=docs
mkdir -p "$OUT" state/d1
{
  echo "### $(TZ=Europe/Warsaw date -Is)  D1 verification start"
  echo "### python: $($PY -V 2>&1)"
  echo "### git: $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
} | tee "$OUT/d1-verify-2026-10-03.out"

run () { # name, cmd...
  local name="$1"; shift
  echo "" | tee -a "$OUT/d1-verify-2026-10-03.out"
  echo "===== [$name] $* =====" | tee -a "$OUT/d1-verify-2026-10-03.out"
  local t0=$(date +%s)
  "$@" >"state/d1/$name.out" 2>&1
  local rc=$?
  local t1=$(date +%s)
  echo "----- exit=$rc  wall=$((t1-t0))s -----" | tee -a "$OUT/d1-verify-2026-10-03.out"
  tail -n 12 "state/d1/$name.out" | tee -a "$OUT/d1-verify-2026-10-03.out"
  echo "$name exit=$rc wall=$((t1-t0))s" >> "$OUT/d1-summary-2026-10-03.txt"
}

: > "$OUT/d1-summary-2026-10-03.txt"
run pytest            $PY -m pytest -q
run verify_live       $PY scripts/verify_live.py
run security          $PY scripts/security_boundaries.py
run redteam           $PY scripts/redteam_rewrite_gap.py
run first_demo        $PY scripts/first_demo_path.py
run console_check     $PY scripts/console_check.py
echo "" | tee -a "$OUT/d1-verify-2026-10-03.out"
echo "### DONE $(TZ=Europe/Warsaw date -Is)" | tee -a "$OUT/d1-verify-2026-10-03.out"
echo "DONE" >> "$OUT/d1-summary-2026-10-03.txt"
