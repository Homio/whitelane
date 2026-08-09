#!/bin/bash

# ============================================================
# 一键管理 GNOME 系统代理 + 命令行代理环境变量（白名单模式）
#
# v4 优化：
#   1) 命令名自适应：使用 $0 捕获当前执行指令，
#      原生即 proxy.sh，软链接则为软链接的名字
#   2) 代理服务器信息读取自配置文件 proxy.conf；
#      白名单读取自 whitelist.yaml（YAML 格式：- 开头 + 每行一个条目，# 为注释）
#   3) 白名单代理：只有白名单内域名 / IP 才走代理，其余默认直连
#       - GNOME 系统代理：manual 模式指向本地路由代理，按白名单自动分流
#       - 命令行：由 proxy.conf 的 CLI_MODE 决定
#           route  → 本地路由代理（推荐）：http_proxy 指向本地代理，
#                    白名单→远程代理，其余→本地直连；所有工具统一生效
#           proxy  → 导出代理变量指向远程代理，wget/curl 默认走代理
#                    （no_proxy 仅排除内网/本地）
#           direct → 不导出代理变量，默认直连；需要走代理的单条
#                    命令用 proxyrun 包装
#
#   关于命令行白名单的说明（重要）：
#   http_proxy/https_proxy/no_proxy 协议是"黑名单"语义——no_proxy
#   只能列出"不走代理的"，无法表达"只有白名单走代理"，且各工具支持
#   程度不一（实测：curl 认 CIDR 和 "*"；wget 只认精确 IP/域名）。
#   要让"默认直连 + 白名单走代理"对所有 CLI 工具统一生效，唯一办法是
#   route 模式：本地起一个路由代理做分流（见 proxy-route.py）
#
# 用法:
#   $(basename "$0") on [host]   敲门认证 → 配置系统代理（manual）+ 输出命令行环境
#   $(basename "$0") off         关闭系统代理 + 输出清除环境变量命令
#   $(basename "$0") [status]    查看当前代理状态
#
# 说明:
#   on/off 时将环境变量语句输出到 stdout（供 bashrc 函数 eval 使用），
#   人类可读提示信息输出到 stderr。
# ============================================================

set -euo pipefail

# ── 自身定位（支持软链接）──────────────────────────────────
SELF_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

# ── 配置文件 ───────────────────────────────────────────────
CONF_FILE="${PROXY_CONF:-$SCRIPT_DIR/proxy.conf}"
if [ ! -f "$CONF_FILE" ]; then
    echo "❌ 找不到配置文件: ${CONF_FILE}" >&2
    echo "   请先创建配置文件（模板见 proxy.conf），或用环境变量 PROXY_CONF 指定路径" >&2
    exit 1
fi

source "$CONF_FILE"

# ── 白名单 ─────────────────────────────────────────────────
# 从 whitelist.yaml 加载（YAML 列表：- 开头 + 每行一个条目，# 为注释）。
# 支持 域名 / .子域 / IP / CIDR 四种格式（详见 whitelist.yaml 头部说明）。
WHITELIST_FILE="${PROXY_WHITELIST:-$SCRIPT_DIR/whitelist.yaml}"
WHITELIST=()
if [ -f "$WHITELIST_FILE" ]; then
    while IFS= read -r w || [ -n "$w" ]; do
        w="${w%%#*}"                       # 去掉 # 注释
        w="${w#"${w%%[![:space:]]*}"}"     # 去首部空白
        w="${w#-}"                         # 去掉 YAML 列表项的 "- "
        w="${w#"${w%%[![:space:]]*}"}"     # 再去掉 "- " 后的空白
        w="${w%"${w##*[![:space:]]}"}"     # 去尾部空白
        [ -n "$w" ] && WHITELIST+=("$w")
    done < "$WHITELIST_FILE"
else
    echo "⚠️  未找到白名单文件: ${WHITELIST_FILE}，所有流量将直连" >&2
fi

# 默认值兜底（仅当配置文件中未定义时生效）
PROXY_HOST="${PROXY_HOST:-10.100.96.156}"
PROXY_PORT="${PROXY_PORT:-8798}"
AUTH_PORT="${AUTH_PORT:-8799}"
AUTH_TOKEN="${AUTH_TOKEN:-}"
CLI_MODE="${CLI_MODE:-route}"
NO_PROXY_EXTRA="${NO_PROXY_EXTRA:-}"
LOCAL_PROXY_PORT="${LOCAL_PROXY_PORT:-18080}"

# CLI_MODE=proxy 时使用的 no_proxy（黑名单式：内网/本地绕过代理，
# 其余默认走代理）。注意代理服务器自身要加进 no_proxy，避免请求代理
# 自身时又被指回代理导致死循环。
NO_PROXY_DEFAULT="localhost,127.0.0.0/8,::1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,${PROXY_HOST}"
[ -n "$NO_PROXY_EXTRA" ] && NO_PROXY_DEFAULT="${NO_PROXY_DEFAULT},${NO_PROXY_EXTRA}"

# 状态文件缓存目录
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/proxy"

# route 模式：本地路由代理的状态文件
ROUTE_CONF="$CACHE_DIR/proxy-route.json"
ROUTE_PID="$CACHE_DIR/proxy-route.pid"
ROUTE_LOG="$CACHE_DIR/proxy-route.log"

# ── 状态判断 ──────────────────────────────────────────────
# 判断 GNOME 手动代理是否指向指定端点（host:port）
gsettings_manual_matches() {
    local expect_host="$1" expect_port="$2"
    local mode h p
    mode=$(gsettings get org.gnome.system.proxy mode 2>/dev/null || echo "''")
    [ "$mode" = "'manual'" ] || return 1
    h=$(gsettings get org.gnome.system.proxy.http host 2>/dev/null | tr -d "'")
    p=$(gsettings get org.gnome.system.proxy.http port 2>/dev/null)
    [ "$h" = "$expect_host" ] && [ "$p" = "$expect_port" ]
}

route_proxy_is_running() {
    [ -f "$ROUTE_PID" ] && kill -0 "$(cat "$ROUTE_PID")" 2>/dev/null
}

# 按当前 CLI_MODE 判断系统代理是否处于对应的开启状态：
#   route  → manual 指向本地路由代理
#   proxy  → manual 指向远程代理
#   direct → 系统代理关闭（本身即"全部直连"）
system_proxy_is_on() {
    local host="${1:-$PROXY_HOST}"
    case "$CLI_MODE" in
        route)  gsettings_manual_matches "127.0.0.1" "$LOCAL_PROXY_PORT" ;;
        direct) system_proxy_is_off ;;
        *)      gsettings_manual_matches "$host" "$PROXY_PORT" ;;
    esac
}

env_proxy_is_on() {
    local host="${1:-$PROXY_HOST}"
    case "${http_proxy:-}" in
        "http://${host}:${PROXY_PORT}"*) return 0 ;;
        "http://127.0.0.1:${LOCAL_PROXY_PORT}"*) return 0 ;;
        *) return 1 ;;
    esac
}

system_proxy_is_off() {
    local mode
    mode=$(gsettings get org.gnome.system.proxy mode 2>/dev/null || echo "''")
    [ "$mode" = "'none'" ]
}

env_proxy_is_off() {
    [ -z "${http_proxy:-}" ]
}

# ── 敲门认证 ──────────────────────────────────────────────
do_knock() {
    local host="${1:-$PROXY_HOST}"
    local auth_url="http://${host}:${AUTH_PORT}/auth?token=${AUTH_TOKEN}"

    if ! command -v curl &>/dev/null; then
        echo "⚠️  curl 不可用，无法敲门认证" >&2
        return 1
    fi
    if [ -z "$AUTH_TOKEN" ]; then
        echo "⚠️  未配置 AUTH_TOKEN，跳过敲门认证" >&2
        return 1
    fi

    echo "🔑 敲门认证 ${host}:${AUTH_PORT} ..." >&2
    local result
    result=$(curl -s --connect-timeout 5 "$auth_url" 2>&1) || true

    if echo "$result" | grep -qi "Success\|already authorized\|localhost"; then
        echo "✅ ${result}" >&2
        return 0
    else
        echo "❌ 认证失败: ${result}" >&2
        return 1
    fi
}

# ── 本地路由代理（route 模式）─────────────────────────────
start_route_proxy() {
    local host="${1:-$PROXY_HOST}"

    # 生成 JSON 配置（供 python 路由代理读取）
    {
        printf '{"listen_port": %s, "proxy_host": "%s", "proxy_port": %s, "whitelist": [' \
            "$LOCAL_PROXY_PORT" "$host" "$PROXY_PORT"
        local first=1 e
        for e in "${WHITELIST[@]:-}"; do
            [ -z "$e" ] && continue
            [ "$first" = "1" ] || printf ','
            first=0
            printf '"%s"' "$(printf '%s' "$e" | sed 's/"/\\"/g')"
        done
        printf ']}'
    } > "$ROUTE_CONF"

    # 已在运行则跳过
    if [ -f "$ROUTE_PID" ] && kill -0 "$(cat "$ROUTE_PID")" 2>/dev/null; then
        return 0
    fi

    nohup python3 "$SCRIPT_DIR/proxy-route.py" "$ROUTE_CONF" >> "$ROUTE_LOG" 2>&1 &
    echo $! > "$ROUTE_PID"

    # 等待端口就绪
    local i
    for i in $(seq 1 25); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$LOCAL_PROXY_PORT") 2>/dev/null; then
            exec 3>&- 3<&- 2>/dev/null || true
            return 0
        fi
        sleep 0.2
    done
    echo "⚠️  本地路由代理启动超时，请检查 $ROUTE_LOG" >&2
    return 1
}

stop_route_proxy() {
    if [ -f "$ROUTE_PID" ]; then
        local pid
        pid=$(cat "$ROUTE_PID")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$ROUTE_PID"
    fi
}

# ── 开启代理 ──────────────────────────────────────────────
proxy_on() {
    local host="${1:-$PROXY_HOST}"

    # 已是开启状态则跳过，不重复设置
    # （direct 模式不导出 CLI 代理变量，只看系统代理是否已开启）
    if system_proxy_is_on "$host"; then
        if [ "$CLI_MODE" = "route" ] && ! route_proxy_is_running; then
            : # 路由代理未运行，继续重新配置
        elif [ "$CLI_MODE" = "direct" ] || env_proxy_is_on "$host"; then
            echo "✅ 代理已处于开启状态（${host}:${PROXY_PORT}），无需重复设置" >&2
            return 0
        fi
    fi

    # 1️⃣ 敲门认证
    do_knock "$host" || {
        echo "⚠️  敲门失败，代理可能无法连接。继续配置本地设置..." >&2
    }

    # 2️⃣ route 模式：启动本地路由代理（失败则回退 proxy 模式）
    if [ "$CLI_MODE" = "route" ]; then
        if ! command -v python3 &>/dev/null; then
            echo "⚠️  未安装 python3，route 模式不可用，已回退为 proxy 模式" >&2
            CLI_MODE="proxy"
        elif ! start_route_proxy "$host"; then
            echo "⚠️  本地路由代理启动失败，已回退为 proxy 模式（日志: $ROUTE_LOG）" >&2
            CLI_MODE="proxy"
        fi
    fi

    # 3️⃣ GNOME 系统代理（manual 模式，按 CLI_MODE 指向不同端点）
    case "$CLI_MODE" in
        route)
            # 指向本地路由代理：白名单→远程代理，其余→本地直连
            gsettings set org.gnome.system.proxy mode 'manual'
            gsettings set org.gnome.system.proxy.http enabled true
            gsettings set org.gnome.system.proxy.http host '127.0.0.1'
            gsettings set org.gnome.system.proxy.http port "$LOCAL_PROXY_PORT"
            gsettings set org.gnome.system.proxy.https host '127.0.0.1'
            gsettings set org.gnome.system.proxy.https port "$LOCAL_PROXY_PORT"
            gsettings set org.gnome.system.proxy.socks host '127.0.0.1'
            gsettings set org.gnome.system.proxy.socks port "$LOCAL_PROXY_PORT"
            gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']"
            echo "✅ GNOME 系统代理已开启（manual → 本地路由代理 ${LOCAL_PROXY_PORT}，白名单分流）" >&2
            ;;
        direct)
            # 全部直连：系统代理保持关闭
            gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null || true
            echo "✅ GNOME 系统代理保持关闭（direct 模式默认直连）" >&2
            ;;
        *)
            # proxy 模式：GUI 默认全走远程代理
            gsettings set org.gnome.system.proxy mode 'manual'
            gsettings set org.gnome.system.proxy.http enabled true
            gsettings set org.gnome.system.proxy.http host "$host"
            gsettings set org.gnome.system.proxy.http port "$PROXY_PORT"
            gsettings set org.gnome.system.proxy.https host "$host"
            gsettings set org.gnome.system.proxy.https port "$PROXY_PORT"
            gsettings set org.gnome.system.proxy.socks host "$host"
            gsettings set org.gnome.system.proxy.socks port "$PROXY_PORT"
            gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']"
            echo "✅ GNOME 系统代理已开启（manual → ${host}:${PROXY_PORT}）" >&2
            ;;
    esac

    # 4️⃣ 连通性测试（验证代理链路可达；direct 模式无需测试）
    if [ "$CLI_MODE" != "direct" ] && command -v curl &>/dev/null; then
        local test_url="https://www.google.com" e
        for e in "${WHITELIST[@]:-}"; do
            case "$e" in
                */*) continue ;;
                *.*) test_url="https://${e}"; break ;;
            esac
        done
        local proxy_endpoint HTTP_CODE
        if [ "$CLI_MODE" = "route" ]; then
            # 走本地路由代理，选白名单域名验证远程链路（其余会直连，测不出代理）
            proxy_endpoint="http://127.0.0.1:${LOCAL_PROXY_PORT}"
        else
            proxy_endpoint="http://${host}:${PROXY_PORT}"
        fi
        HTTP_CODE=$(curl -x "$proxy_endpoint" \
            -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "$test_url" 2>/dev/null || echo "超时")
        if [ "$HTTP_CODE" = "超时" ] || [ -z "$HTTP_CODE" ]; then
            echo "⚠️  警告: 代理链路不可达（${proxy_endpoint} → $test_url）" >&2
            echo "   请确认: 1) VPN 已连接  2) 敲门认证成功" >&2
        else
            echo "✅ 代理连通性测试通过 (HTTP $HTTP_CODE, $test_url)" >&2
        fi
    fi

    # 5️⃣ 输出命令行环境变量（stdout，供 bashrc 函数 eval）
    case "$CLI_MODE" in
        route)
            # 所有流量交给本地路由代理按白名单分流；no_proxy 必须清空，
            # 否则工具会绕过本地代理（例如环境里遗留的 no_proxy）
            cat << EOF
export http_proxy="http://127.0.0.1:${LOCAL_PROXY_PORT}"
export https_proxy="http://127.0.0.1:${LOCAL_PROXY_PORT}"
export all_proxy="http://127.0.0.1:${LOCAL_PROXY_PORT}"
export HTTP_PROXY="http://127.0.0.1:${LOCAL_PROXY_PORT}"
export HTTPS_PROXY="http://127.0.0.1:${LOCAL_PROXY_PORT}"
export ALL_PROXY="http://127.0.0.1:${LOCAL_PROXY_PORT}"
export no_proxy=""
export NO_PROXY=""
EOF
            echo "✅ 命令行走本地路由代理 127.0.0.1:${LOCAL_PROXY_PORT}（白名单→远程代理，其余→本地直连）" >&2
            ;;
        direct)
            # 不导出代理变量，默认直连；proxyrun 按需走代理。
            # 注：wget 只认 no_proxy 精确 IP/域名，不认 CIDR 和 "*"，
            #     所以 direct 干脆不导出代理变量，对所有工具都成立
            cat << EOF
# 命令行默认直连（未导出代理变量）；需要走代理的命令请用 proxyrun 包装
proxyrun() {
    env -u no_proxy -u NO_PROXY \\
        http_proxy="http://${host}:${PROXY_PORT}" \\
        https_proxy="http://${host}:${PROXY_PORT}" \\
        all_proxy="socks5://${host}:${PROXY_PORT}" \\
        HTTP_PROXY="http://${host}:${PROXY_PORT}" \\
        HTTPS_PROXY="http://${host}:${PROXY_PORT}" \\
        ALL_PROXY="socks5://${host}:${PROXY_PORT}" \\
        "\$@"
}
EOF
            echo "✅ 命令行默认直连（未导出代理变量）" >&2
            echo "   → 需要走代理的命令请用 proxyrun 包装，例如: proxyrun curl https://example.com" >&2
            ;;
        *)
            # proxy 模式：导出远程代理变量，默认走代理，no_proxy 排除内网/本地
            cat << EOF
export http_proxy="http://${host}:${PROXY_PORT}"
export https_proxy="http://${host}:${PROXY_PORT}"
export all_proxy="socks5://${host}:${PROXY_PORT}"
export HTTP_PROXY="http://${host}:${PROXY_PORT}"
export HTTPS_PROXY="http://${host}:${PROXY_PORT}"
export ALL_PROXY="socks5://${host}:${PROXY_PORT}"
export no_proxy="${NO_PROXY_DEFAULT}"
export NO_PROXY="${NO_PROXY_DEFAULT}"
proxyrun() {
    env -u no_proxy -u NO_PROXY \\
        http_proxy="http://${host}:${PROXY_PORT}" \\
        https_proxy="http://${host}:${PROXY_PORT}" \\
        all_proxy="socks5://${host}:${PROXY_PORT}" \\
        HTTP_PROXY="http://${host}:${PROXY_PORT}" \\
        HTTPS_PROXY="http://${host}:${PROXY_PORT}" \\
        ALL_PROXY="socks5://${host}:${PROXY_PORT}" \\
        "\$@"
}
EOF
            echo "✅ 命令行默认走代理（no_proxy 排除内网/本地）" >&2
            ;;
    esac
}

# ── 关闭代理 ──────────────────────────────────────────────
proxy_off() {
    # 已是关闭状态则跳过，不重复操作
    if system_proxy_is_off && env_proxy_is_off; then
        echo "✅ 代理已处于关闭状态，无需重复操作" >&2
        return 0
    fi

    echo "🔌 取消代理" >&2

    # 清除 GNOME 代理（manual 设置）
    gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null || true
    gsettings set org.gnome.system.proxy.http host '' 2>/dev/null || true
    gsettings set org.gnome.system.proxy.http port 0 2>/dev/null || true
    gsettings set org.gnome.system.proxy.http enabled false 2>/dev/null || true
    gsettings set org.gnome.system.proxy.http authentication-user '' 2>/dev/null || true
    gsettings set org.gnome.system.proxy.http authentication-password '' 2>/dev/null || true
    gsettings set org.gnome.system.proxy.https host '' 2>/dev/null || true
    gsettings set org.gnome.system.proxy.https port 0 2>/dev/null || true
    gsettings set org.gnome.system.proxy.socks host '' 2>/dev/null || true
    gsettings set org.gnome.system.proxy.socks port 0 2>/dev/null || true
    gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']" 2>/dev/null || true

    # 停止本地路由代理（route 模式）
    stop_route_proxy
    rm -f "$ROUTE_CONF" "$ROUTE_LOG" "$ROUTE_PID"

    echo "✅ GNOME 系统代理已关闭" >&2

    # 输出清除环境变量命令（stdout，供 bashrc 函数 eval）
    echo "unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY"
    echo "unset -f proxyrun 2>/dev/null || true"

    echo "✅ 命令行代理环境变量已清除（当前 shell）" >&2
}

# ── 查看状态 ──────────────────────────────────────────────
proxy_status() {
    local mode
    mode=$(gsettings get org.gnome.system.proxy mode 2>/dev/null || echo "''")
    echo "📋 GNOME 系统代理: $mode"
    if [ "$mode" = "'manual'" ]; then
        local h p
        h=$(gsettings get org.gnome.system.proxy.http host 2>/dev/null | tr -d "'")
        p=$(gsettings get org.gnome.system.proxy.http port 2>/dev/null)
        echo "   HTTP 代理: ${h}:${p}"
        if [ "$h" = "127.0.0.1" ]; then
            echo "   分流: 本地路由代理 → 仅白名单域名/IP 走远程代理，其余直连"
        else
            echo "   分流: 默认全走远程代理"
        fi
    fi

    echo ""
    echo "📋 代理服务器（配置文件: ${CONF_FILE}）:"
    echo "   HTTP/SOCKS: ${PROXY_HOST}:${PROXY_PORT}"
    echo "   认证: 无（IP 敲门方案，端口 ${AUTH_PORT}）"

    echo ""
    echo "📋 白名单（${WHITELIST_FILE}，共 ${#WHITELIST[@]} 项）"
    [ "${#WHITELIST[@]}" -eq 0 ] && echo "   （空，所有流量直连）"

    echo ""
    echo "📋 命令行模式（配置文件 CLI_MODE=${CLI_MODE}）:"
    case "$CLI_MODE" in
        route)
            echo "   → 本地路由代理 127.0.0.1:${LOCAL_PROXY_PORT}；白名单走远程代理，其余本地直连"
            if [ -f "$ROUTE_PID" ] && kill -0 "$(cat "$ROUTE_PID")" 2>/dev/null; then
                echo "   本地代理状态: 运行中 (PID $(cat "$ROUTE_PID"))"
            else
                echo "   本地代理状态: 未运行"
            fi
            ;;
        direct)
            echo "   → 默认直连（不导出代理变量）；需要走代理的命令用 proxyrun 包装"
            ;;
        *)
            echo "   → 默认走代理；no_proxy 排除内网/本地: ${NO_PROXY_DEFAULT}"
            ;;
    esac
    echo "📋 命令行环境变量（当前 shell）:"
    echo "   http_proxy=${http_proxy:-未设置}"
    echo "   https_proxy=${https_proxy:-未设置}"
    echo "   no_proxy=${no_proxy:-未设置}"

    echo ""
    echo "用法: ${SELF_NAME} on | off"
}

# ── 帮助 ──────────────────────────────────────────────────
usage() {
    echo "用法: ${SELF_NAME} {on|off|status}"
    echo ""
    echo "   on      开启代理：敲门认证 + GNOME 系统代理（白名单分流） + 命令行环境变量"
    echo "   off     关闭代理：GNOME 系统代理 + 命令行环境变量"
    echo "   status  查看当前代理状态（无参数时默认为 status）"
    echo ""
    echo "配置: ${CONF_FILE}"
}

# ── 入口 ──────────────────────────────────────────────────
case "${1:-}" in
    on)
        proxy_on "${2:-}"
        ;;
    off)
        proxy_off
        ;;
    "" | status)
        proxy_status
        ;;
    *)
        usage
        exit 1
        ;;
esac
