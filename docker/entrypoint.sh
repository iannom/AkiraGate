#!/usr/bin/env sh
set -eu

fail() {
    echo "错误: $*" >&2
    exit 1
}

random_hex() {
    bytes="$1"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$bytes"
        return
    fi
    if command -v od >/dev/null 2>&1; then
        od -An -N"$bytes" -tx1 /dev/urandom | tr -d ' \n'
        return
    fi
    fail "无法生成随机密钥，容器内缺少 openssl 或 od"
}

validate_port() {
    name="$1"
    value="$2"
    case "$value" in
        ''|*[!0-9]*)
            fail "${name} 必须是 1-65535 之间的整数"
            ;;
    esac
    if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        fail "${name} 超出范围: ${value}"
    fi
}

validate_positive_seconds() {
    name="$1"
    value="$2"
    case "$value" in
        ''|*[!0-9]*)
            fail "${name} 必须是正整数"
            ;;
    esac
    if [ "$value" -lt 60 ]; then
        fail "${name} 不能小于 60 秒"
    fi
}

normalize_bool() {
    name="$1"
    value="$2"
    case "$value" in
        true|TRUE|1|yes|YES)
            printf 'true'
            ;;
        false|FALSE|0|no|NO|'')
            printf 'false'
            ;;
        *)
            fail "${name} 必须是 true 或 false"
            ;;
    esac
}

validate_secret_path() {
    value="$1"
    case "$value" in
        ''|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-]*)
            fail "AKIRAGATE_SECRET_PATH 只能包含字母、数字、下划线和短横线"
            ;;
    esac
}

json_escape() {
    printf '%s' "$1" | sed \
        -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g' \
        -e ':a;N;$!ba;s/\r/\\r/g;s/\n/\\n/g;s/\t/\\t/g'
}

if [ "$#" -eq 0 ]; then
    set -- akiragate-server
fi
if [ "${1#-}" != "$1" ]; then
    set -- akiragate-server "$@"
fi

config_file="${AKIRAGATE_CONFIG:-/data/config.json}"
data_dir="${AKIRAGATE_DATA_DIR:-$(dirname "$config_file")}"
web_root="${AKIRAGATE_WEB_ROOT:-/app/frontend/dist}"
export AKIRAGATE_CONFIG="$config_file"
export AKIRAGATE_DATA_DIR="$data_dir"
export AKIRAGATE_WEB_ROOT="$web_root"

if [ -e "$config_file" ] && [ ! -f "$config_file" ]; then
    fail "配置路径已存在但不是普通文件: ${config_file}"
fi

if [ ! -f "$config_file" ]; then
    config_dir="$(dirname "$config_file")"
    mkdir -p "$config_dir" "$data_dir"

    web_host="${AKIRAGATE_WEB_HOST:-0.0.0.0}"
    web_port="${AKIRAGATE_WEB_PORT:-8787}"
    secret_path="${AKIRAGATE_SECRET_PATH:-$(random_hex 6)}"
    admin_username="${AKIRAGATE_ADMIN_USERNAME:-admin}"
    admin_password="${AKIRAGATE_ADMIN_PASSWORD:-$(random_hex 12)}"
    api_token="${AKIRAGATE_API_TOKEN:-$(random_hex 32)}"
    openvpn_config="${AKIRAGATE_OPENVPN_CONFIG:-}"
    openvpn_auth="${AKIRAGATE_OPENVPN_AUTH:-${data_dir}/vpngate_auth.txt}"
    auto_connect="$(normalize_bool AKIRAGATE_AUTO_CONNECT "${AKIRAGATE_AUTO_CONNECT:-false}")"
    refresh_seconds="${AKIRAGATE_REFRESH_SECONDS:-960}"
    proxy_cache_ttl_seconds="${AKIRAGATE_PROXY_CACHE_TTL_SECONDS:-3600}"
    proxy_lease_seconds="${AKIRAGATE_PROXY_LEASE_SECONDS:-3600}"
    proxy_listen_host="${AKIRAGATE_PROXY_LISTEN_HOST:-0.0.0.0}"
    routing_mode="${AKIRAGATE_ROUTING_MODE:-auto}"
    force_country="${AKIRAGATE_FORCE_COUNTRY:-}"
    fixed_node_id="${AKIRAGATE_FIXED_NODE_ID:-}"
    socks_name="${AKIRAGATE_SOCKS_NAME:-local}"
    socks_host="${AKIRAGATE_SOCKS_HOST:-0.0.0.0}"
    socks_port="${AKIRAGATE_SOCKS_PORT:-7928}"
    socks_username="${AKIRAGATE_SOCKS_USERNAME:-proxy}"
    socks_password="${AKIRAGATE_SOCKS_PASSWORD:-$(random_hex 12)}"

    validate_port AKIRAGATE_WEB_PORT "$web_port"
    validate_port AKIRAGATE_SOCKS_PORT "$socks_port"
    validate_positive_seconds AKIRAGATE_REFRESH_SECONDS "$refresh_seconds"
    validate_positive_seconds AKIRAGATE_PROXY_CACHE_TTL_SECONDS "$proxy_cache_ttl_seconds"
    validate_positive_seconds AKIRAGATE_PROXY_LEASE_SECONDS "$proxy_lease_seconds"
    validate_secret_path "$secret_path"

    if [ -z "$admin_username" ]; then
        fail "AKIRAGATE_ADMIN_USERNAME 不能为空"
    fi
    if [ -z "$admin_password" ]; then
        fail "AKIRAGATE_ADMIN_PASSWORD 不能为空"
    fi
    if [ -z "$api_token" ]; then
        fail "AKIRAGATE_API_TOKEN 不能为空"
    fi
    if [ -z "$socks_username" ] || [ -z "$socks_password" ]; then
        fail "SOCKS5 公网监听必须配置用户名和密码"
    fi

    openvpn_auth_dir="$(dirname "$openvpn_auth")"
    mkdir -p "$openvpn_auth_dir"
    if [ ! -f "$openvpn_auth" ]; then
        printf 'vpn\nvpn\n' > "$openvpn_auth"
        chmod 0600 "$openvpn_auth"
    fi

    tmp_config="${config_file}.tmp.$$"
    cat > "$tmp_config" <<EOF
{
  "web_host": "$(json_escape "$web_host")",
  "web_port": ${web_port},
  "secret_path": "$(json_escape "$secret_path")",
  "admin_username": "$(json_escape "$admin_username")",
  "admin_password": "$(json_escape "$admin_password")",
  "api_token": "$(json_escape "$api_token")",
  "openvpn_config": "$(json_escape "$openvpn_config")",
  "openvpn_auth": "$(json_escape "$openvpn_auth")",
  "auto_connect": ${auto_connect},
  "refresh_seconds": ${refresh_seconds},
  "proxy_cache_ttl_seconds": ${proxy_cache_ttl_seconds},
  "proxy_lease_seconds": ${proxy_lease_seconds},
  "proxy_listen_host": "$(json_escape "$proxy_listen_host")",
  "routing_mode": "$(json_escape "$routing_mode")",
  "force_country": "$(json_escape "$force_country")",
  "fixed_node_id": "$(json_escape "$fixed_node_id")",
  "socks5_listeners": [
    {
      "name": "$(json_escape "$socks_name")",
      "host": "$(json_escape "$socks_host")",
      "port": ${socks_port},
      "username": "$(json_escape "$socks_username")",
      "password": "$(json_escape "$socks_password")",
      "enabled": true
    }
  ]
}
EOF
    chmod 0600 "$tmp_config"
    mv "$tmp_config" "$config_file"

    cat <<EOF
AkiraGate Docker 首次配置已生成
--------------------------------
网页登录地址: http://<宿主机IP>:${web_port}/${secret_path}/
管理账号: ${admin_username}
管理密码: ${admin_password}
机器 API Token: ${api_token}
SOCKS5 地址: socks5h://${socks_username}:${socks_password}@<宿主机IP>:${socks_port}
配置文件: ${config_file}

提示: 明文凭据只在首次生成配置时输出；服务启动后会将配置中的密码和 Token 迁移为哈希值。
EOF
else
    chmod 0600 "$config_file" 2>/dev/null || true
fi

exec "$@"
