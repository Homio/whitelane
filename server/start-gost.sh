#!/bin/bash
# ────────────────────────────────────────────────────────────────
# gost + proxy-auth launcher
# Started by systemd (root).  Spawns gost (:8798) and the auth
# watchdog (:8799) 相互解耦：
#   - 任一个进程死亡都会被独立拉起（不连坐）
#   - 启动前等待认证端口释放，规避重启竞态
#   - auth 启动若因瞬时 bind 失败秒退，自动重试
#   - auth 卡死的自愈由 proxy-auth.py 内置健康检查负责：
#     检测到卡死会自行退出 → 本脚本检测到后重新拉起
# ────────────────────────────────────────────────────────────────
set -u

GOST_DIR="/home/wanghaomiao/software/gost"
GOST_BIN="$GOST_DIR/gost"
AUTH_PY="$GOST_DIR/proxy-auth.py"
AUTH_PORT="${AUTH_PORT:-8799}"

PID_GOST=""
PID_AUTH=""
RUNNING=1

log() { echo "[$(date '+%F %T')] $*"; }

cleanup() {
    RUNNING=0
    log "Shutting down gost & auth watchdog …"
    [ -n "$PID_GOST" ] && kill "$PID_GOST" 2>/dev/null || true
    [ -n "$PID_AUTH" ] && kill "$PID_AUTH" 2>/dev/null || true
    wait 2>/dev/null || true
    log "Shutdown complete."
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

# 判断进程是否真的活着（排除僵尸态）
is_alive() {
    [ -n "$1" ] || return 1
    [ -d "/proc/$1" ] || return 1
    local st
    st=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)
    [ "$st" = "Z" ] && return 1
    return 0
}

# 等待认证端口释放，避免旧进程 socket 未清干净导致 bind EADDRINUSE
wait_port_free() {
    local i
    for i in $(seq 1 10); do
        ss -ltn 2>/dev/null | grep -q ":$AUTH_PORT " || return 0
        log "Port $AUTH_PORT still busy, waiting… ($i/10)"
        sleep 1
    done
    log "WARN: port $AUTH_PORT still busy after 10s, starting anyway"
}

start_gost() {
    log "Starting gost on :8798 …"
    "$GOST_BIN" -L "auto://:8798" &
    PID_GOST=$!
}

start_auth() {
    # bind 竞态等瞬时失败会秒退，重试几次
    local attempt
    for attempt in $(seq 1 5); do
        log "Starting auth watchdog on :8799 (attempt $attempt/5) …"
        python3 "$AUTH_PY" &
        PID_AUTH=$!
        sleep 1
        if is_alive "$PID_AUTH"; then
            return 0
        fi
        log "auth watchdog exited immediately, retrying…"
    done
    log "ERROR: auth watchdog failed to start after 5 attempts"
    return 1
}

# ── 启动 ───────────────────────────────────────────────────────
wait_port_free
start_gost
if ! start_auth; then
    log "ERROR: giving up (auth failed to start)"
    cleanup
    exit 1
fi
log "gost PID=$PID_GOST  |  auth-watchdog PID=$PID_AUTH"

# ── 监控循环：子进程死亡各自独立重启 ─────────────────────────
while [ "$RUNNING" = "1" ]; do
    sleep 2
    if ! is_alive "$PID_GOST"; then
        log "gost died, restarting…"
        start_gost
    fi
    if ! is_alive "$PID_AUTH"; then
        log "auth watchdog died, restarting…"
        if ! start_auth; then
            log "ERROR: auth restart failed, exiting"
            RUNNING=0
        fi
    fi
done

log "Monitor loop ended, shutting down."
cleanup
exit 1
