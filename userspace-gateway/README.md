# AimiliVPN Go 后端

这是 AimiliVPN 当前主后端。React 管理端源码位于仓库根目录 `frontend/`，生产构建后由 Go 管理服务通过 `--web-root` 托管。

它提供：

- Go Web 管理服务：`cmd/aimilivpn-server`
- 用户态 OpenVPN 隧道：`internal/vpn`
- gVisor 用户态 TCP/IP 栈
- 多 SOCKS5 TCP CONNECT 监听端口
- 每个 SOCKS5 监听端口可选 username/password 鉴权
- VPNGate 节点刷新、节点连通性测试、固定国家/固定节点路由策略、出口检测和运行日志

旧 Python 管理端已移除，部署入口应使用 `aimilivpn-server`。

## 管理服务

```bash
go run ./cmd/aimilivpn-server \
  --config /opt/aimilivpn/aimili_data/config.json \
  --web-root /opt/aimilivpn/frontend/dist
```

也可以用 `AIMILI_WEB_ROOT` 指定前端构建目录。

管理端认证使用单用户登录系统。配置中的 `admin_password_hash` 保存 bcrypt 哈希，`POST /api/login` 登录后通过 HttpOnly Cookie 访问其它管理 API。

配置文件中的 `socks5_listeners` 控制多个 SOCKS5 端口：

```json
{
  "socks5_listeners": [
    {"name": "local", "host": "127.0.0.1", "port": 7928, "enabled": true},
    {"name": "public", "host": "::", "port": 7929, "username": "user", "password": "pass", "enabled": true}
  ]
}
```

公网监听地址 `0.0.0.0`、`::` 或等价地址必须配置用户名和密码。

## 低层网关工具

`aimilivpn-gateway` 仍可作为无 Web 管理的低层工具使用：

```bash
go run ./cmd/aimilivpn-gateway \
  --ovpn /path/to/client.ovpn \
  --auth-file /path/to/auth.txt \
  --socks5 127.0.0.1:7928 \
  --socks5 '[::]:7929,user,pass'
```

低层工具不会自动创建默认 SOCKS5 监听，必须显式传入至少一个 `--socks5` 或设置 `AIMILI_SOCKS5_LISTENERS`。

## 验证

```bash
go test ./...
go build ./cmd/aimilivpn-server
go build ./cmd/aimilivpn-gateway
```
