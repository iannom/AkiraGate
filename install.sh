#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

INSTALL_DIR="${INSTALL_DIR:-/opt/aimilivpn}"
DATA_DIR="${AIMILI_DATA_DIR:-${INSTALL_DIR}/aimili_data}"
CONFIG_FILE="${AIMILI_CONFIG:-${DATA_DIR}/config.json}"
GENERATED_ADMIN_PASSWORD=""
REQUIRED_GO_VERSION="1.23.1"
GO_INSTALL_VERSION="${GO_INSTALL_VERSION:-1.23.10}"
REQUIRED_NODE_VERSION="20.19.0"
NODE_INSTALL_VERSION="${NODE_INSTALL_VERSION:-22.12.0}"
DEFAULT_USER="baoweise-bot"
DEFAULT_REPO="aimili-vpngate"
GITHUB_USER="${1:-${DEFAULT_USER}}"
GITHUB_REPO="${2:-${DEFAULT_REPO}}"
GITHUB_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}.git"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 必须以 root 权限运行此脚本。${PLAIN}"
    exit 1
fi

version_ge() {
    awk -v current="$1" -v required="$2" '
        BEGIN {
            split(current, c, ".")
            split(required, r, ".")
            for (i = 1; i <= 3; i++) {
                cv = c[i] + 0
                rv = r[i] + 0
                if (cv > rv) exit 0
                if (cv < rv) exit 1
            }
            exit 0
        }
    '
}

current_go_version() {
    command -v go >/dev/null 2>&1 || return 1
    go version | awk '{print $3}' | sed 's/^go//; s/-.*$//'
}

current_node_version() {
    command -v node >/dev/null 2>&1 || return 1
    node --version | sed 's/^v//; s/-.*$//'
}

node_version_supported() {
    awk -v current="$1" '
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

random_token() {
    length="$1"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$length" | cut -c "1-${length}"
        return
    fi
    local token=""
    while [ "${#token}" -lt "$length" ]; do
        token="${token}$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    done
    printf '%s\n' "${token:0:length}"
}

json_value() {
    key="$1"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$CONFIG_FILE" | head -n1
}

json_number() {
    key="$1"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$CONFIG_FILE" | head -n1
}

install_go() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) go_arch="amd64" ;;
        aarch64|arm64) go_arch="arm64" ;;
        armv7l|armv6l) go_arch="armv6l" ;;
        *) echo -e "${RED}当前架构 ${arch} 不支持自动安装 Go。${PLAIN}"; exit 1 ;;
    esac
    tarball="go${GO_INSTALL_VERSION}.linux-${go_arch}.tar.gz"
    tmp="/tmp/${tarball}"
    curl -fsSL "https://go.dev/dl/${tarball}" -o "$tmp"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp"
    rm -f "$tmp"
    export PATH="/usr/local/go/bin:$PATH"
}

install_node() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) node_arch="x64" ;;
        aarch64|arm64) node_arch="arm64" ;;
        *) echo -e "${RED}当前架构 ${arch} 不支持自动安装 Node.js。${PLAIN}"; exit 1 ;;
    esac
    tarball="node-v${NODE_INSTALL_VERSION}-linux-${node_arch}.tar.xz"
    tmp="/tmp/${tarball}"
    curl -fsSL "https://nodejs.org/dist/v${NODE_INSTALL_VERSION}/${tarball}" -o "$tmp"
    rm -rf /usr/local/node
    mkdir -p /usr/local/node
    tar -C /usr/local/node --strip-components=1 -xJf "$tmp"
    rm -f "$tmp"
    ln -sf /usr/local/node/bin/node /usr/local/bin/node
    ln -sf /usr/local/node/bin/npm /usr/local/bin/npm
    ln -sf /usr/local/node/bin/npx /usr/local/bin/npx
    export PATH="/usr/local/node/bin:$PATH"
}

install_packages() {
    if [ -f /etc/os-release ]; then . /etc/os-release; else ID=""; fi
    case "${ID:-}" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -q || true
            apt-get install -y curl git ca-certificates psmisc tar xz-utils golang-go nodejs npm || true
            ;;
        alpine)
            apk update || true
            apk add curl git ca-certificates psmisc bash tar xz go nodejs npm || true
            ;;
        centos|rhel|rocky|almalinux|fedora)
            mgr="yum"; command -v dnf >/dev/null 2>&1 && mgr="dnf"
            $mgr install -y curl git ca-certificates psmisc tar xz golang nodejs npm || $mgr install -y curl git ca-certificates psmisc tar xz go nodejs npm || true
            ;;
        *)
            echo -e "${RED}不支持的操作系统。${PLAIN}"
            exit 1
            ;;
    esac
    installed="$(current_go_version || true)"
    if [ -z "$installed" ] || ! version_ge "$installed" "$REQUIRED_GO_VERSION"; then
        echo -e "${YELLOW}正在安装官方 Go ${GO_INSTALL_VERSION}...${PLAIN}"
        install_go
    fi
    installed_node="$(current_node_version || true)"
    if [ -z "$installed_node" ] || ! node_version_supported "$installed_node"; then
        echo -e "${YELLOW}正在安装官方 Node.js ${NODE_INSTALL_VERSION}...${PLAIN}"
        install_node
    fi
}

deploy_source() {
    if [ -f "${INSTALL_DIR}/.local_dev" ]; then
        echo -e "${GREEN}检测到本地开发模式，跳过源码更新。${PLAIN}"
        return
    fi
    if [ -d "${INSTALL_DIR}/.git" ]; then
        cd "$INSTALL_DIR"
        git fetch origin "$DEPLOY_BRANCH" || true
        git checkout "$DEPLOY_BRANCH"
        git pull --ff-only origin "$DEPLOY_BRANCH" || git pull origin "$DEPLOY_BRANCH"
    elif [ -f "${INSTALL_DIR}/userspace-gateway/go.mod" ]; then
        echo -e "${GREEN}检测到现有 Go 源码目录，直接构建。${PLAIN}"
    elif [ -d "$INSTALL_DIR" ]; then
        echo -e "${RED}${INSTALL_DIR} 已存在但不是 AimiliVPN Go 源码目录。请备份后删除该目录再安装。${PLAIN}"
        exit 1
    else
        git clone -b "$DEPLOY_BRANCH" "$GITHUB_URL" "$INSTALL_DIR" || git clone "$GITHUB_URL" "$INSTALL_DIR"
    fi
}

build_binaries() {
    cd "${INSTALL_DIR}/userspace-gateway"
    go build -o aimilivpn-server ./cmd/aimilivpn-server
    go build -o aimilivpn-gateway ./cmd/aimilivpn-gateway
}

build_frontend() {
    cd "${INSTALL_DIR}/frontend"
    npm ci
    npm run build
}

ensure_config() {
    mkdir -p "$DATA_DIR"
    if [ -f "$CONFIG_FILE" ] && grep -q '"socks5_listeners"' "$CONFIG_FILE"; then
        return
    fi
    if [ -f "$CONFIG_FILE" ]; then
        backup="${CONFIG_FILE}.legacy.$(date +%Y%m%d%H%M%S)"
        mv "$CONFIG_FILE" "$backup"
        echo -e "${YELLOW}检测到旧版配置，已备份到 ${backup} 并生成 Go 后端新配置。${PLAIN}"
    fi
    username="admin"
    password="$(random_token 16)"
    GENERATED_ADMIN_PASSWORD="$password"
    suffix="$(random_token 12)"
    proxy_password="$(random_token 16)"
    cat > "$CONFIG_FILE" <<EOF
{
  "web_host": "::",
  "web_port": 8787,
  "secret_path": "${suffix}",
  "admin_username": "${username}",
  "admin_password": "${password}",
  "openvpn_config": "",
  "openvpn_auth": "${DATA_DIR}/vpngate_auth.txt",
  "auto_connect": true,
  "refresh_seconds": 960,
  "routing_mode": "auto",
  "force_country": "",
  "fixed_node_id": "",
  "socks5_listeners": [
    {
      "name": "local",
      "host": "127.0.0.1",
      "port": 7928,
      "username": "proxy",
      "password": "${proxy_password}",
      "enabled": true
    }
  ]
}
EOF
    chmod 600 "$CONFIG_FILE"
    if [ ! -f "${DATA_DIR}/vpngate_auth.txt" ]; then
        printf "vpn\nvpn\n" > "${DATA_DIR}/vpngate_auth.txt"
        chmod 600 "${DATA_DIR}/vpngate_auth.txt"
    fi
}

configure_service() {
    mkdir -p /etc/default
    cat > /etc/default/aimilivpn <<EOF
AIMILI_DATA_DIR=${DATA_DIR}
AIMILI_CONFIG=${CONFIG_FILE}
AIMILI_WEB_ROOT=${INSTALL_DIR}/frontend/dist
EOF
    if command -v systemctl >/dev/null 2>&1; then
        cat > /lib/systemd/system/aimilivpn.service <<EOF
[Unit]
Description=AimiliVPN Go userspace proxy gateway
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-/etc/default/aimilivpn
ExecStart=${INSTALL_DIR}/userspace-gateway/aimilivpn-server --config ${CONFIG_FILE} --web-root ${INSTALL_DIR}/frontend/dist
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable aimilivpn.service
    elif command -v rc-service >/dev/null 2>&1; then
        cat > /etc/init.d/aimilivpn <<EOF
#!/sbin/openrc-run
description="AimiliVPN Go userspace proxy gateway"
command="${INSTALL_DIR}/userspace-gateway/aimilivpn-server"
command_args="--config ${CONFIG_FILE} --web-root ${INSTALL_DIR}/frontend/dist"
command_background="yes"
directory="${INSTALL_DIR}"
pidfile="/run/aimilivpn.pid"
depend() { need net; }
EOF
        chmod +x /etc/init.d/aimilivpn
        rc-update add aimilivpn default
    fi
}

install_ml() {
    cat > /usr/bin/ml <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${AIMILI_CONFIG:-/opt/aimilivpn/aimili_data/config.json}"
INSTALL_DIR="/opt/aimilivpn"

json_value() {
    key="$1"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$CONFIG_FILE" | head -n1
}

service_cmd() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl "$1" aimilivpn.service
    else
        rc-service aimilivpn "$1"
    fi
}

status_cmd() {
    web_port="$(sed -n 's/.*"web_port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$CONFIG_FILE" | head -n1)"
    secret_path="$(json_value secret_path)"
    admin_username="$(json_value admin_username)"
    admin_password="$(json_value admin_password)"
    if [ -z "$admin_password" ]; then
        admin_password="配置已使用哈希保存，请使用安装时记录的密码或在 Web 管理端修改。"
    fi
    echo "======================================================="
    echo "             AimiliVPN Go 管理终端"
    echo "======================================================="
    echo "网页登录地址: http://<服务器IP>:${web_port:-8787}/${secret_path}/"
    echo "管理账号: ${admin_username}"
    echo "管理密码: ${admin_password}"
    echo "SOCKS5 监听请在 Web 管理端查看和配置。"
}

logs_cmd() {
    journalctl -u aimilivpn.service -f -n 80
}

update_cmd() {
    cd "$INSTALL_DIR"
    git pull || true
    bash install.sh
}

uninstall_cmd() {
    printf "确认卸载 AimiliVPN? (y/N): "
    read -r ans
    [ "$ans" = "y" ] || exit 0
    service_cmd stop || true
    systemctl disable aimilivpn.service 2>/dev/null || true
    rm -f /lib/systemd/system/aimilivpn.service /etc/init.d/aimilivpn /usr/bin/ml
    rm -rf "$INSTALL_DIR"
}

case "${1:-status}" in
    start|stop|restart) service_cmd "$1" ;;
    status) status_cmd ;;
    logs) logs_cmd ;;
    update) update_cmd ;;
    uninstall) uninstall_cmd ;;
    *) echo "可用命令: ml status|start|stop|restart|logs|update|uninstall" ;;
esac
EOF
    chmod +x /usr/bin/ml
}

start_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart aimilivpn.service
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service aimilivpn restart || rc-service aimilivpn start
    fi
}

print_summary() {
    public_ip="$(curl -s --max-time 3 https://api.ipify.org || echo "服务器IP")"
    web_port="$(json_number web_port)"
    secret_path="$(json_value secret_path)"
    admin_username="$(json_value admin_username)"
    admin_password="${GENERATED_ADMIN_PASSWORD:-$(json_value admin_password)}"
    if [ -z "$admin_password" ]; then
        admin_password="配置已使用哈希保存，请使用安装时记录的密码或在 Web 管理端修改。"
    fi

    echo
    echo -e "${GREEN}==========================================================${PLAIN}"
    echo -e "${GREEN}             AimiliVPN Go 后端部署已完成${PLAIN}"
    echo -e "${GREEN}==========================================================${PLAIN}"
    echo "  * 网页控制面板: http://${public_ip}:${web_port:-8787}/${secret_path}/"
    echo "  * 网页管理账号: ${admin_username:-admin}"
    echo "  * 网页管理密码: ${admin_password}"
    echo "  * SOCKS5 监听:"
    print_socks_listeners
    echo "  * 快速状态指令: ml status"
    echo "  * 实时日志: ml logs"
    echo "=========================================================="
}

print_socks_listeners() {
    local in_list=0 in_object=0 host="" port="" username="" password="" enabled="true" line display_host auth printed=0
    while IFS= read -r line; do
        if [ "$in_list" -eq 0 ] && [[ "$line" == *'"socks5_listeners"'* ]]; then
            in_list=1
            continue
        fi
        if [ "$in_list" -eq 0 ]; then
            continue
        fi
        if [ "$in_object" -eq 0 ] && [[ "$line" == *']'* ]]; then
            break
        fi
        if [ "$in_object" -eq 0 ] && [[ "$line" == *'{'* ]]; then
            in_object=1
            host="127.0.0.1"
            port="7928"
            username=""
            password=""
            enabled="true"
            continue
        fi
        if [ "$in_object" -eq 1 ]; then
            if [[ "$line" =~ \"host\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]]; then host="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ \"port\"[[:space:]]*:[[:space:]]*([0-9]+) ]]; then port="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ \"username\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]]; then username="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ \"password\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]]; then password="${BASH_REMATCH[1]}"; fi
            if [[ "$line" =~ \"enabled\"[[:space:]]*:[[:space:]]*(true|false) ]]; then enabled="${BASH_REMATCH[1]}"; fi
            if [[ "$line" == *'}'* ]]; then
                if [ "$enabled" != "false" ]; then
                    display_host="$host"
                    if [[ "$display_host" == *:* && "$display_host" != \[* ]]; then
                        display_host="[${display_host}]"
                    fi
                    auth=""
                    if [ -n "$username" ] || [ -n "$password" ]; then
                        auth="${username}:${password}@"
                    fi
                    echo "    - socks5h://${auth}${display_host}:${port}"
                    printed=1
                fi
                in_object=0
            fi
        fi
    done < "$CONFIG_FILE"
    if [ "$printed" -eq 0 ]; then
        echo "    - 请登录 Web 管理端查看或启用 SOCKS5 监听。"
    fi
}

echo -e "${BLUE}==========================================================${PLAIN}"
echo -e "${BLUE}        AimiliVPN Go 后端一键部署脚本${PLAIN}"
echo -e "${BLUE}==========================================================${PLAIN}"
install_packages
deploy_source
build_binaries
build_frontend
ensure_config
configure_service
install_ml
start_service
print_summary
