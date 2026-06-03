#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV_DIR="${AIMILI_DEV_DIR:-${ROOT_DIR}/.dev}"
CONFIG_FILE="${AIMILI_DEV_CONFIG:-${DEV_DIR}/config.json}"
WEB_PORT="${AIMILI_DEV_WEB_PORT:-18787}"
VITE_PORT="${AIMILI_DEV_VITE_PORT:-5173}"
SOCKS_PORT="${AIMILI_DEV_SOCKS_PORT:-17928}"
LISTEN_HOST="${AIMILI_DEV_LISTEN_HOST:-0.0.0.0}"
SECRET_PATH="${AIMILI_DEV_SECRET_PATH:-dev}"
ADMIN_USERNAME="${AIMILI_DEV_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${AIMILI_DEV_ADMIN_PASSWORD:-password}"
SOCKS_USERNAME="${AIMILI_DEV_SOCKS_USERNAME:-proxy}"
SOCKS_PASSWORD="${AIMILI_DEV_SOCKS_PASSWORD:-password}"

backend_pid=""
frontend_pid=""

cleanup() {
    if [ -n "$frontend_pid" ] && kill -0 "$frontend_pid" 2>/dev/null; then
        kill "$frontend_pid" 2>/dev/null || true
    fi
    if [ -n "$backend_pid" ] && kill -0 "$backend_pid" 2>/dev/null; then
        kill "$backend_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

require_command() {
    name="$1"
    if ! command -v "$name" >/dev/null 2>&1; then
        echo "错误: 未找到 ${name}，请先安装后再启动本地开发环境。" >&2
        exit 1
    fi
}

node_version_supported() {
    current="$(node --version | sed 's/^v//; s/-.*$//')"
    awk -v current="$current" '
        BEGIN {
            split(current, c, ".")
            major = c[1] + 0
            minor = c[2] + 0
            patch = c[3] + 0
            if (major == 20) {
                if (minor > 19 || (minor == 19 && patch >= 0)) exit 0
                exit 1
            }
            if (major == 22) {
                if (minor > 12 || (minor == 12 && patch >= 0)) exit 0
                exit 1
            }
            if (major > 22) exit 0
            exit 1
        }
    '
}

port_available() {
    port="$1"
    ! timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1
}

next_available_port() {
    port="$1"
    while ! port_available "$port"; do
        port=$((port + 1))
        if [ "$port" -gt 65535 ]; then
            echo "错误: 没有可用端口。" >&2
            exit 1
        fi
    done
    printf '%s\n' "$port"
}

write_default_config() {
    mkdir -p "$DEV_DIR"
    if [ -f "$CONFIG_FILE" ]; then
        return
    fi
    cat > "$CONFIG_FILE" <<EOF
{
  "web_host": "${LISTEN_HOST}",
  "web_port": ${WEB_PORT},
  "secret_path": "${SECRET_PATH}",
  "admin_username": "${ADMIN_USERNAME}",
  "admin_password": "${ADMIN_PASSWORD}",
  "openvpn_config": "",
  "openvpn_auth": "${DEV_DIR}/vpngate_auth.txt",
  "auto_connect": false,
  "refresh_seconds": 960,
  "routing_mode": "auto",
  "force_country": "",
  "fixed_node_id": "",
  "socks5_listeners": [
    {
      "name": "local-dev",
      "host": "${LISTEN_HOST}",
      "port": ${SOCKS_PORT},
      "username": "${SOCKS_USERNAME}",
      "password": "${SOCKS_PASSWORD}",
      "enabled": true
    }
  ]
}
EOF
    chmod 600 "$CONFIG_FILE"
    printf "vpn\nvpn\n" > "${DEV_DIR}/vpngate_auth.txt"
    chmod 600 "${DEV_DIR}/vpngate_auth.txt"
}

read_json_string() {
    key="$1"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$CONFIG_FILE" | head -n1
}

read_json_number() {
    key="$1"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$CONFIG_FILE" | head -n1
}

prepare_frontend() {
    cd "${ROOT_DIR}/frontend"
    npm ci
    npm run build
}

start_backend() {
    cd "${ROOT_DIR}/userspace-gateway"
    go run ./cmd/aimilivpn-server \
        --config "$CONFIG_FILE" \
        --web-root "${ROOT_DIR}/frontend/dist" &
    backend_pid="$!"
}

wait_for_backend() {
    origin="$1"
    for _ in $(seq 1 40); do
        if curl -fsS "${origin}/${SECRET_PATH}/" >/dev/null 2>&1; then
            return
        fi
        sleep 0.25
    done
    echo "错误: Go 后端未在预期时间内启动。" >&2
    exit 1
}

start_frontend() {
    cd "${ROOT_DIR}/frontend"
    VITE_DEV_SECRET_PATH="$SECRET_PATH" \
    VITE_DEV_API_ORIGIN="$1" \
    npm run dev -- --host "$LISTEN_HOST" --port "$VITE_PORT" &
    frontend_pid="$!"
}

require_command go
require_command node
require_command npm
require_command curl
require_command timeout

if ! node_version_supported; then
    echo "错误: 当前 Node.js 版本不满足 Vite 要求，请使用 Node.js ^20.19.0 或 >=22.12.0。" >&2
    exit 1
fi

WEB_PORT="$(next_available_port "$WEB_PORT")"
VITE_PORT="$(next_available_port "$VITE_PORT")"
write_default_config

config_web_port="$(read_json_number web_port)"
config_secret_path="$(read_json_string secret_path)"
config_admin_username="$(read_json_string admin_username)"
config_admin_password="$(read_json_string admin_password)"
config_admin_password_hash="$(read_json_string admin_password_hash)"

if [ "${config_web_port:-}" != "$WEB_PORT" ]; then
    echo "提示: 已存在 ${CONFIG_FILE}，使用配置内 Web 端口 ${config_web_port:-未知}。"
    WEB_PORT="${config_web_port:-$WEB_PORT}"
fi
if [ -n "${config_secret_path:-}" ]; then
    SECRET_PATH="$config_secret_path"
fi
if [ -n "${config_admin_username:-}" ]; then
    ADMIN_USERNAME="$config_admin_username"
fi
if [ -n "${config_admin_password:-}" ]; then
    ADMIN_PASSWORD="$config_admin_password"
elif [ -n "${config_admin_password_hash:-}" ]; then
    ADMIN_PASSWORD="配置已使用哈希保存，请使用你上次设置的管理密码。"
fi

if ! port_available "$WEB_PORT"; then
    echo "错误: 配置文件中的 Web 端口 ${WEB_PORT} 已被占用，请修改 ${CONFIG_FILE} 或设置 AIMILI_DEV_WEB_PORT。" >&2
    exit 1
fi

prepare_frontend
start_backend
backend_origin="http://127.0.0.1:${WEB_PORT}"
wait_for_backend "$backend_origin"
start_frontend "$backend_origin"

cat <<EOF

AimiliVPN 本地开发环境已启动
--------------------------------
前端开发地址: http://127.0.0.1:${VITE_PORT}/
后端管理地址: ${backend_origin}/${SECRET_PATH}/
管理账号: ${ADMIN_USERNAME}
管理密码: ${ADMIN_PASSWORD}
SOCKS5 默认端口: ${SOCKS_PORT}

按 Ctrl+C 停止前后端进程。
EOF

set +e
wait -n "$backend_pid" "$frontend_pid"
exit_code="$?"
echo "开发进程已退出，正在清理..."
exit "$exit_code"
