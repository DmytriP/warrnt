#!/usr/bin/env bash
#
# F2 - one command that proves the demo on a CLEAN MACHINE.
#
# It starts from nothing: an empty temp dir, a fresh clone of the public repo from
# the network, a fresh virtualenv, deps from PyPI. It never touches an existing
# checkout, an inherited WARRNT_* variable or a cached venv. Then it runs every
# command the README prints, plus the two-terminal demo vector, and writes a
# verbatim transcript.
#
#   ./scripts/f2_clean_run.sh                     # clone from the public URL
#   REPO_URL=file:///path/to/warrnt ./scripts/f2_clean_run.sh   # clone a local copy
#   PYTHON=/usr/bin/python3 ./scripts/f2_clean_run.sh           # pick the base interpreter
#
# Exit code is non-zero if ANY gate fails. The transcript lands in OUTDIR.
set -uo pipefail

REPO_URL="${REPO_URL:-https://github.com/indrad3v4/warrnt.git}"
PYTHON="${PYTHON:-python3}"
WORK="${WORK:-$(mktemp -d -t warrnt-f2-XXXXXX)}"
OUTDIR="${OUTDIR:-$PWD/f2-out}"
STAMP="$(date +%Y-%m-%dT%H:%M:%S%z)"
CLONE="$WORK/warrnt"
LOG="$OUTDIR/f2-clean-run-$(date +%Y-%m-%d).out"
SUMMARY="$OUTDIR/f2-clean-summary.txt"
FAILED=0

mkdir -p "$OUTDIR"
: > "$SUMMARY"

say () { echo "$@" | tee -a "$LOG"; }

{
  echo "############################################################"
  echo "# F2 - clean-machine run"
  echo "# started : $STAMP"
  echo "# workdir : $WORK   (empty temp dir)"
  echo "# clone   : $REPO_URL"
  echo "# python  : $($PYTHON -V 2>&1)   ($(command -v "$PYTHON"))"
  echo "############################################################"
} | tee "$LOG"

echo "" | tee -a "$LOG"
echo "===== [bootstrap] clone -> venv -> pip install -r requirements.txt =====" | tee -a "$LOG"
t0="$(date +%s)"
{
  git clone --quiet "$REPO_URL" "$CLONE" || { echo "CLONE FAILED"; exit 1; }
  cd "$CLONE" || exit 1
  echo "cloned commit: $(git rev-parse HEAD) $(git log -1 --format=%s)"
  echo "tree         : $(git status --porcelain | wc -l) dirty file(s); state/ present: $([ -e state ] && echo yes || echo no)"
  "$PYTHON" -m venv .venv || { echo "VENV FAILED"; exit 1; }
  export PATH="$CLONE/.venv/bin:$PATH"
  unset WARRNT_DEV WARRNT_HOME WARRNT_UPSTREAM WARRNT_ANCHOR WARRNT_ISSUER_KEY WARRNT_PORT WARRNT_HOST
  python3 -m pip install --quiet --upgrade pip
  pip install --quiet -r requirements.txt || { echo "PIP FAILED"; exit 1; }
  echo "python3 now: $(command -v python3)"
  echo "venv deps  : $(pip freeze | wc -l) packages installed from PyPI"
} 2>&1 | tee -a "$LOG"
t1="$(date +%s)"
say "----- bootstrap wall=$((t1-t0))s -----"

run () { # name, cmd...
  local name="$1"; shift
  echo "" | tee -a "$LOG"
  echo "===== [$name] $* =====" | tee -a "$LOG"
  local t0 t1 rc
  t0="$(date +%s)"
  "$@" >"$OUTDIR/$name.out" 2>&1
  rc=$?
  t1="$(date +%s)"
  echo "----- exit=$rc  wall=$((t1-t0))s -----" | tee -a "$LOG"
  tail -n 14 "$OUTDIR/$name.out" | tee -a "$LOG"
  printf '%-22s exit=%-3s wall=%ss\n' "$name" "$rc" "$((t1-t0))" >> "$SUMMARY"
  [ "$rc" -eq 0 ] || FAILED=1
}

cd "$CLONE" || exit 1
export PATH="$CLONE/.venv/bin:$PATH"

# ---- the six checks the README prints, verbatim ----
run pytest          python3 -m pytest -q
run verify_live     python3 scripts/verify_live.py
run security        python3 scripts/security_boundaries.py
run redteam         python3 scripts/redteam_rewrite_gap.py
run upstream_check  python3 scripts/upstream_check.py
run console_check   python3 scripts/console_check.py
run first_demo      python3 scripts/first_demo_path.py

# ---- the two-terminal demo vector: node in the background, client + checkpoint ----
mkdir -p "$OUTDIR/demo_vector"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
echo "" | tee -a "$LOG"
echo "===== [demo_vector] node on :$PORT, then demo_client + checkpoint_p23 =====" | tee -a "$LOG"
WARRNT_DEV=1 python3 -m warrnt serve --port "$PORT" >"$OUTDIR/demo_vector/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 0.3; done
t0="$(date +%s)"
python3 scripts/demo_client.py "http://127.0.0.1:$PORT" >"$OUTDIR/demo_vector/transcript.json" 2>"$OUTDIR/demo_vector/demo_client.err"; rc_dc=$?
python3 scripts/checkpoint_p23.py "$OUTDIR/demo_vector/transcript.json" >"$OUTDIR/demo_vector/checkpoint.out" 2>&1; rc_ck=$?
t1="$(date +%s)"
kill "$NODE_PID" 2>/dev/null
echo "----- demo_client exit=$rc_dc | checkpoint_p23 exit=$rc_ck | wall=$((t1-t0))s -----" | tee -a "$LOG"
tail -n 20 "$OUTDIR/demo_vector/checkpoint.out" | tee -a "$LOG"
printf '%-22s exit=%-3s wall=%ss\n' "demo_vector" "$((rc_dc+rc_ck))" "$((t1-t0))" >> "$SUMMARY"
{ [ "$rc_dc" -eq 0 ] && [ "$rc_ck" -eq 0 ]; } || FAILED=1

# ---- the console rendered from a live node (Design evidence; needs chromium) ----
if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1; then
  run console_shot  python3 scripts/console_shot.py --outdir "$OUTDIR/shots"
else
  say ""
  say "===== [console_shot] SKIPPED - no chromium in PATH (only the Design screenshot needs it) ====="
  printf '%-22s %s\n' "console_shot" "skip (no chromium)" >> "$SUMMARY"
fi

{
  echo ""
  echo "===== SUMMARY ====="
  cat "$SUMMARY"
  echo ""
  echo "clone kept at : $CLONE"
  echo "finished      : $(date +%Y-%m-%dT%H:%M:%S%z)"
  echo "VERDICT       : $([ "$FAILED" -eq 0 ] && echo 'ALL GATES PASS on a clean machine' || echo 'FAILURE - see the transcript')"
} | tee -a "$LOG"

exit "$FAILED"
