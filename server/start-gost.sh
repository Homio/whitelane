#!/bin/bash
# ────────────────────────────────────────────────────────────────
# gost + proxy-auth launcher
# Started by systemd (root).  Spawns both gost (:8798) and the
# auth watchdog (:8799); exits (→ systemd restarts) if either dies.
# ────────────────────────────────────────────────────────────────
set -e

GOST_DIR="/home/wanghaomiao/software/gost"
GOST_BIN="$GOST_DIR/gost"
AUTH_PY="$GOST_DIR/proxy-auth.py"

cleanup() {
    echo "[$(date '+%F %T')] Shutting down gost & auth watchdog …"
    kill %1 %2 2>/dev/null || true
    wait 2>/dev/null || true
    echo "[$(date '+%F %T')] Shutdown complete."
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

# ── Launch gost (no auth – firewall does the guarding) ─────────
echo "[$(date '+%F %T')] Starting gost on :8798 (no auth) …"
"$GOST_BIN" -L "auto://:8798" &
PID_GOST=$!

# ── Launch auth watchdog ───────────────────────────────────────
echo "[$(date '+%F %T')] Starting auth watchdog on :8799 …"
python3 "$AUTH_PY" &
PID_AUTH=$!

echo "[$(date '+%F %T')] gost PID=$PID_GOST  |  auth-watchdog PID=$PID_AUTH"

# ── Monitor loop – exit if either child dies unexpectedly ──────
while kill -0 $PID_GOST 2>/dev/null && kill -0 $PID_AUTH 2>/dev/null; do
    sleep 2
done

echo "[$(date '+%F %T')] ERROR: a child process died unexpectedly!" >&2
cleanup
exit 1
