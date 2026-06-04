# AkiraGate Go 后端

这是 AkiraGate 当前主后端。React 管理端源码位于仓库根目录 `frontend/`，生产构建后由 Go 管理服务通过 `--web-root` 托管。

它提供：

- Go Web 管理服务：`cmd/akiragate-server`
- 用户态 OpenVPN 隧道：`internal/vpn`
- gVisor 用户态 TCP/IP 栈
- 多 SOCKS5 TCP CONNECT 监听端口
- 每个 SOCKS5 监听端口可选 username/password 鉴权
- VPNGate 节点刷新、节点连通性测试、固定国家/固定节点路由策略、出口检测和运行日志
- 机器 API 按国家码分配临时 SOCKS5 入口，过滤真实出口为家宽类型的代理，并支持释放和超时自动释放

旧 Python 管理端已移除，部署入口应使用 `akiragate-server`。

## 管理服务

```bash
go run ./cmd/akiragate-server \
  --config /opt/akiragate/akiragate_data/config.json \
  --web-root /opt/akiragate/frontend/dist
```

也可以用 `AKIRAGATE_WEB_ROOT` 指定前端构建目录。

管理端认证使用单用户登录系统。配置中的 `admin_password_hash` 保存 bcrypt 哈希，`POST /api/login` 登录后通过 HttpOnly Cookie 访问其它管理 API。机器 API 使用 `Authorization: Bearer <api_token>`，服务首次读取明文 `api_token` 后会迁移为 `api_token_hash`。

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

机器 API 分配入口：

```bash
curl -X POST "http://<服务器IP>:8787/<secret_path>/api/proxy/allocate" \
  -H "Authorization: Bearer <api_token>" \
  -H "Content-Type: application/json" \
  -d '{"country_code":"JP"}'
```

释放入口：

```bash
curl -X POST "http://<服务器IP>:8787/<secret_path>/api/proxy/release" \
  -H "Authorization: Bearer <api_token>" \
  -H "Content-Type: application/json" \
  -d '{"allocation_id":"<allocation_id>"}'
```

## 低层网关工具

`akiragate-gateway` 仍可作为无 Web 管理的低层工具使用：

```bash
go run ./cmd/akiragate-gateway \
  --ovpn /path/to/client.ovpn \
  --auth-file /path/to/auth.txt \
  --socks5 127.0.0.1:7928 \
  --socks5 '[::]:7929,user,pass'
```

低层工具不会自动创建默认 SOCKS5 监听，必须显式传入至少一个 `--socks5` 或设置 `AKIRAGATE_SOCKS5_LISTENERS`。

## 验证

```bash
go test ./...
go build ./cmd/akiragate-server
go build ./cmd/akiragate-gateway
```
