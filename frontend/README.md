# AkiraGate 前端

AkiraGate 管理端前端使用 React + Vite，构建产物由 Go 管理服务通过 `--web-root` 托管。

## 本地开发

推荐在仓库根目录启动完整开发环境：

```bash
bash dev.sh
```

只启动前端：

```bash
npm install
npm run dev
```

如需把 Vite 开发服务器代理到本地 Go 管理服务：

```bash
VITE_DEV_SECRET_PATH=<登录安全后缀> \
VITE_DEV_API_ORIGIN=http://127.0.0.1:8787 \
npm run dev
```

打开前端后使用 Go 管理端账号登录。登录成功后浏览器会保存 HttpOnly 会话 Cookie，后端 API 会统一校验该会话。

## 生产构建

```bash
npm ci
npm run build
```

部署时让 Go 管理服务指向构建目录：

```bash
akiragate-server --config /opt/akiragate/akiragate_data/config.json --web-root /opt/akiragate/frontend/dist
```
