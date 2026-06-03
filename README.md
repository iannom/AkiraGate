# AkiraGate

AkiraGate 现在使用 **Go 用户态后端 + React 前端**：Go 管理服务负责配置保存、OpenVPN 用户态隧道、用户态 TCP/IP 栈和 SOCKS5 网关；React/Vite 前端作为独立目录构建后由 Go 服务托管。旧 Python 管理端已移除，不再作为安装脚本或运行时入口。

## 一键部署

```bash
bash <(curl -Ls https://raw.githubusercontent.com/iannom/AkiraGate/main/install.sh)
```

部署脚本会：

- 安装 Go 工具链。
- 安装满足 Vite 要求的 Node.js 工具链。
- 构建 `userspace-gateway/akiragate-server` 和 `userspace-gateway/akiragate-gateway`。
- 构建 `frontend/dist` React 管理端静态文件。
- 创建 `akiragate.service`，直接启动 Go 管理服务。
- 生成 `/opt/akiragate/akiragate_data/config.json`。

终端会输出 Web 管理地址、管理账号和初始密码。管理端使用应用内登录会话，后端 API 会校验登录 Cookie。

## 功能

- 不创建 Linux `tun0`，OpenVPN 包由 Go 用户态后端处理。
- 使用 gVisor 用户态 TCP/IP 栈出站。
- 支持同时开放多个 SOCKS5 TCP CONNECT 监听端口。
- 每个 SOCKS5 监听端口可单独设置用户名和密码。
- 默认生成的本地 SOCKS5 监听也会带用户名密码，不再默认裸开。
- 绑定 `0.0.0.0`、`::` 或等价公网地址的 SOCKS5 监听必须启用用户名密码鉴权。
- React Web 管理页面可配置 Web 地址、OpenVPN 配置路径、SOCKS5 多端口和鉴权。
- Web 管理端使用单用户登录系统，密码落盘为 bcrypt 哈希，后端接口统一校验会话 Cookie。
- Web 管理页面可刷新 VPNGate 官方节点列表、测试节点连通性，并选择节点建立用户态 OpenVPN 连接。
- Web 管理页面可检测 SOCKS5 出口 IP、查看网关组件状态和运行日志。
- 后台可定时刷新 VPNGate 节点；启动自动连接仅用于已配置的本地 OpenVPN 配置文件。

## 配置文件

默认配置路径：

```text
/opt/akiragate/akiragate_data/config.json
```

示例：

```json
{
  "web_host": "::",
  "web_port": 8787,
  "secret_path": "examplepath",
  "admin_username": "admin",
  "admin_password_hash": "$2a$10$example-bcrypt-hash",
  "openvpn_config": "/opt/akiragate/client.ovpn",
  "openvpn_auth": "/opt/akiragate/akiragate_data/vpngate_auth.txt",
  "auto_connect": false,
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
      "password": "local-pass",
      "enabled": true
    },
    {
      "name": "public",
      "host": "::",
      "port": 7929,
      "username": "proxyuser",
      "password": "proxypass",
      "enabled": true
    }
  ]
}
```

`admin_password_hash` 由服务首次读取明文初始密码或在 Web 页面修改密码时自动生成。`openvpn_config` 可用于手动连接本地 OpenVPN 配置文件；`auto_connect` 只会在已设置可读 `openvpn_config` 时于服务启动后自动连接。也可以在 Web 页面点击“刷新 VPNGate 节点”，手动选择公开节点连接。

## 使用 SOCKS5

带用户名密码的本地端口：

```bash
curl -x socks5h://proxy:local-pass@127.0.0.1:7928 https://api.ipify.org
```

带用户名密码的端口：

```bash
curl -x socks5h://proxyuser:proxypass@127.0.0.1:7929 https://api.ipify.org
```

## 管理命令

```bash
ml status
ml logs
ml restart
ml stop
ml start
ml reset-password
ml uninstall
```

## 开发

一键启动本地开发环境：

```bash
bash dev.sh
```

脚本会创建 `.dev/config.json`，启动 Go 后端和 Vite 前端，并输出本地访问地址。默认账号是 `admin`，默认密码是 `password`。

单独启动后端：

```bash
cd userspace-gateway
go test ./...
go run ./cmd/akiragate-server --config ../akiragate_data/config.json --web-root ../frontend/dist
```

前端：

```bash
cd frontend
npm install
npm run dev
```

生产构建：

```bash
cd frontend
npm ci
npm run build
```

## 旧 Python 端

旧 Python 管理端已经从仓库中移除。当前部署、管理 API、VPNGate 节点连接和 SOCKS5 网关均以 `userspace-gateway/cmd/akiragate-server` 为准，管理页面源码位于 `frontend/`。
