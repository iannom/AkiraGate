package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	gatewayconfig "akiragate/userspace-gateway/internal/config"
	"akiragate/userspace-gateway/internal/vpngate"
)

func TestRouteRequiresSessionAuth(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/secret/api/state", nil)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未认证请求应返回 401，实际: %d", rec.Code)
	}
}

func TestLoginCreatesSessionAndStateUsesCookie(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/secret/api/state", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("认证状态请求失败: %d", rec.Code)
	}
	var state State
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("状态响应不是有效 JSON: %v", err)
	}
	if state.AdminPassword != "" {
		t.Fatal("状态接口不应回显管理密码")
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	server := testServer(t)
	body := bytes.NewReader([]byte(`{"username":"admin","password":"bad"}`))
	req := httptest.NewRequest(http.MethodPost, "/secret/api/login", body)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误密码应返回 401，实际: %d", rec.Code)
	}
}

func TestSessionStateRequiresCookie(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/secret/api/session", nil)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录会话检查应返回 401，实际: %d", rec.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/secret/api/session", nil)
	addLoginCookie(t, server, authReq)
	authRec := httptest.NewRecorder()
	server.route(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("已登录会话检查失败: %d", authRec.Code)
	}
	var state AuthState
	if err := json.Unmarshal(authRec.Body.Bytes(), &state); err != nil {
		t.Fatalf("会话响应不是有效 JSON: %v", err)
	}
	if !state.Authenticated || state.Username != "admin" {
		t.Fatalf("会话状态不符合预期: %+v", state)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	server := testServer(t)
	cookie := loginCookie(t, server)

	logoutReq := httptest.NewRequest(http.MethodPost, "/secret/api/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	server.route(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("登出失败: %d", logoutRec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/secret/api/state", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.route(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("登出后的会话应失效，实际: %d", rec.Code)
	}
}

func TestUpdateSettingsKeepsExistingAdminPasswordHashWhenBlank(t *testing.T) {
	server := testServer(t)
	server.listenHost = server.config.WebHost
	server.listenPort = server.config.WebPort
	next := server.config
	next.WebPort = 8788
	next.AdminPassword = ""
	next.AdminPasswordHash = ""
	body, _ := json.Marshal(next)
	req := httptest.NewRequest(http.MethodPost, "/secret/api/settings", bytes.NewReader(body))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("保存设置失败: %d %s", rec.Code, rec.Body.String())
	}
	if !verifyPassword(server.config.AdminPasswordHash, "password") {
		t.Fatal("空管理密码更新应保留旧密码哈希")
	}
	var payload struct {
		RestartNeeded bool `json:"restart_needed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("保存响应不是有效 JSON: %v", err)
	}
	if !payload.RestartNeeded {
		t.Fatal("Web 端口变化后应提示需要重启服务")
	}
}

func TestUpdateSettingsRejectsPublicSocksWithoutAuth(t *testing.T) {
	server := testServer(t)
	next := server.config
	next.SocksListeners = []gatewayconfig.Listener{
		gatewayconfig.NewListener("public", "::", 7929, true),
	}
	body, _ := json.Marshal(next)
	req := httptest.NewRequest(http.MethodPost, "/secret/api/settings", bytes.NewReader(body))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("公网无鉴权 SOCKS5 应被拒绝，实际: %d", rec.Code)
	}
}

func TestLogsAPIRequiresAuthAndReturnsBufferedEntries(t *testing.T) {
	buffer := NewLogBuffer(10)
	logger := slog.New(buffer.Handler())
	config := testConfig()
	server := NewServer(filepath.Join(t.TempDir(), "config.json"), config, logger, buffer)
	logger.Info("测试日志", "component", "manager")

	req := httptest.NewRequest(http.MethodGet, "/secret/api/logs", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("日志接口请求失败: %d", rec.Code)
	}
	var payload struct {
		Logs []LogEntry `json:"logs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("日志响应不是有效 JSON: %v", err)
	}
	if len(payload.Logs) != 1 {
		t.Fatalf("日志数量不符合预期: %d", len(payload.Logs))
	}
	if payload.Logs[0].Message != "测试日志" || payload.Logs[0].Fields["component"] != "manager" {
		t.Fatalf("日志内容不符合预期: %+v", payload.Logs[0])
	}
}

func TestGatewayStatusAPI(t *testing.T) {
	server := testServer(t)
	server.listenHost = "127.0.0.1"
	server.listenPort = 8787
	req := httptest.NewRequest(http.MethodGet, "/secret/api/gateway_status", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("网关状态接口请求失败: %d", rec.Code)
	}
	var payload struct {
		Components []GatewayComponent `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("网关状态响应不是有效 JSON: %v", err)
	}
	if len(payload.Components) != 4 {
		t.Fatalf("网关状态组件数量不符合预期: %d", len(payload.Components))
	}
}

func TestRouteServesReactFrontendFiles(t *testing.T) {
	server := testServer(t)
	webRoot := t.TempDir()
	assetsDir := filepath.Join(webRoot, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatalf("创建静态资源目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(webRoot, "index.html"), []byte("<!doctype html><div id=\"root\"></div>"), 0o644); err != nil {
		t.Fatalf("写入前端入口失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "app.js"), []byte("console.log('akiragate')"), 0o644); err != nil {
		t.Fatalf("写入前端资源失败: %v", err)
	}
	if err := server.SetWebRoot(webRoot); err != nil {
		t.Fatalf("设置前端目录失败: %v", err)
	}

	indexReq := httptest.NewRequest(http.MethodGet, "/secret/", nil)
	indexRec := httptest.NewRecorder()
	server.route(indexRec, indexReq)
	if indexRec.Code != http.StatusOK {
		t.Fatalf("前端入口请求失败: %d", indexRec.Code)
	}
	if indexRec.Body.String() != "<!doctype html><div id=\"root\"></div>" {
		t.Fatalf("前端入口内容不符合预期: %q", indexRec.Body.String())
	}

	assetReq := httptest.NewRequest(http.MethodGet, "/secret/assets/app.js", nil)
	assetRec := httptest.NewRecorder()
	server.route(assetRec, assetReq)
	if assetRec.Code != http.StatusOK {
		t.Fatalf("前端资源请求失败: %d", assetRec.Code)
	}
	if assetRec.Body.String() != "console.log('akiragate')" {
		t.Fatalf("前端资源内容不符合预期: %q", assetRec.Body.String())
	}
}

func TestTestProxyRejectsWhenGatewayIsStopped(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/secret/api/test_proxy", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("未启动 SOCKS5 时出口检测应失败，实际: %d", rec.Code)
	}
	var payload ProxyTestResult
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("出口检测响应不是有效 JSON: %v", err)
	}
	if payload.OK || payload.Error == "" {
		t.Fatalf("出口检测失败响应不符合预期: %+v", payload)
	}
}

func TestFetchIPPureInfoParsesExitProfile(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ip":"203.0.113.10",
			"asn":64500,
			"asOrganization":"Example Network",
			"country":"Japan",
			"countryCode":"JP",
			"region":"Tokyo",
			"city":"Tokyo",
			"fraudScore":35,
			"isResidential":false,
			"isBroadcast":true
		}`))
	}))
	defer upstream.Close()

	info, err := fetchIPPureInfo(t.Context(), upstream.Client(), upstream.URL)
	if err != nil {
		t.Fatalf("解析 ippure 出口画像失败: %v", err)
	}
	if info.IP != "203.0.113.10" || info.ASN != "AS64500" || info.ASOrganization != "Example Network" {
		t.Fatalf("出口画像基础字段不符合预期: %+v", info)
	}
	if info.CountryCode != "JP" || info.IPType != "datacenter" || !info.Hosting {
		t.Fatalf("出口画像分类不符合预期: %+v", info)
	}
}

func TestTestNodeRejectsMissingNodeID(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/secret/api/test_node", bytes.NewReader([]byte(`{}`)))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺少节点 ID 应返回 400，实际: %d", rec.Code)
	}
}

func TestTestNodesWithEmptyList(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/secret/api/test_nodes", bytes.NewReader([]byte(`{"node_ids":[]}`)))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("空批量节点测试应返回 200，实际: %d", rec.Code)
	}
	var payload struct {
		Nodes []vpngate.Node `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("批量节点测试响应不是有效 JSON: %v", err)
	}
	if len(payload.Nodes) != 0 {
		t.Fatalf("空节点列表不应产生测试结果: %d", len(payload.Nodes))
	}
}

func TestProbeNodesConcurrentlyReturnsFailedNodes(t *testing.T) {
	server := testServer(t)

	nodes, cancelled := server.probeNodesConcurrently(context.Background(), []string{"missing-a", "missing-b"})
	if cancelled {
		t.Fatal("未取消的批量测试不应返回 cancelled=true")
	}

	if len(nodes) != 2 {
		t.Fatalf("批量测试应返回所有节点结果，实际: %d", len(nodes))
	}
	for _, node := range nodes {
		if node.ProbeStatus != "unavailable" || node.ProbeMessage == "" {
			t.Fatalf("失败节点应返回 unavailable 和错误信息: %+v", node)
		}
	}
}

func TestBatchNodeTestLifecycleRejectsConcurrentBatch(t *testing.T) {
	server := testServer(t)

	_, batch, ok := server.startBatchNodeTest()
	if !ok {
		t.Fatal("首次批量测试应能启动")
	}
	if _, _, ok := server.startBatchNodeTest(); ok {
		t.Fatal("已有批量测试时不应允许再次启动")
	}

	server.finishBatchNodeTest(batch)
	if _, batch, ok := server.startBatchNodeTest(); !ok {
		t.Fatal("批量测试结束后应允许再次启动")
	} else {
		server.finishBatchNodeTest(batch)
	}
}

func TestCancelTestNodesAPI(t *testing.T) {
	server := testServer(t)
	_, batch, ok := server.startBatchNodeTest()
	if !ok {
		t.Fatal("测试前置批量任务启动失败")
	}
	defer server.finishBatchNodeTest(batch)

	req := httptest.NewRequest(http.MethodPost, "/secret/api/cancel_test_nodes", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("取消批量测试应返回 200，实际: %d", rec.Code)
	}
	var payload struct {
		Cancelled bool `json:"cancelled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("取消批量测试响应不是有效 JSON: %v", err)
	}
	if !payload.Cancelled {
		t.Fatal("取消已有批量测试时应返回 cancelled=true")
	}
}

func TestProbeNodesConcurrentlyMarksCancelledNodes(t *testing.T) {
	server := testServer(t)
	server.nodes = []vpngate.Node{{
		ID:           "node-a",
		ProbeStatus:  "not_checked",
		ProbeMessage: "",
	}, {
		ID:           "node-b",
		ProbeStatus:  "not_checked",
		ProbeMessage: "",
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	nodes, cancelled := server.probeNodesConcurrently(ctx, []string{"node-a", "node-b"})
	if !cancelled {
		t.Fatal("已取消的批量测试应返回 cancelled=true")
	}
	if len(nodes) != 2 {
		t.Fatalf("已取消的批量测试应返回所有节点状态，实际: %d", len(nodes))
	}
	for _, node := range nodes {
		if node.ProbeStatus != "cancelled" || node.ProbeMessage != "批量测试已取消" {
			t.Fatalf("取消节点应标记为 cancelled: %+v", node)
		}
	}
}

func TestMarkNodeProbeTestingUpdatesState(t *testing.T) {
	server := testServer(t)
	server.nodes = []vpngate.Node{{
		ID:           "node-a",
		ProbeStatus:  "unavailable",
		ProbeMessage: "previous failure",
		ProbeLatency: 1200,
		ExitIPInfo:   &vpngate.IPInfo{IP: "198.51.100.10"},
	}}
	server.failed["node-a"] = "previous failure"

	node, _, ok := server.markNodeProbeTesting("node-a")
	if !ok {
		t.Fatal("已存在节点应能进入测试中状态")
	}
	if node.ProbeStatus != probeStatusTesting {
		t.Fatalf("节点应立即标记为测试中，实际: %q", node.ProbeStatus)
	}

	state := server.state()
	if len(state.Nodes) != 1 {
		t.Fatalf("状态接口应返回测试节点，实际数量: %d", len(state.Nodes))
	}
	testingNode := state.Nodes[0]
	if testingNode.ProbeStatus != probeStatusTesting {
		t.Fatalf("状态接口应暴露测试中状态，实际: %q", testingNode.ProbeStatus)
	}
	if testingNode.ProbeMessage == "" {
		t.Fatal("测试中状态应包含可读提示")
	}
	if testingNode.ProbeLatency != 0 {
		t.Fatalf("重新测试时应清空旧延迟，实际: %d", testingNode.ProbeLatency)
	}
	if testingNode.ExitIPInfo != nil {
		t.Fatalf("重新测试时应清空旧出口信息: %+v", testingNode.ExitIPInfo)
	}
	if _, failed := state.FailedNodes["node-a"]; failed {
		t.Fatal("重新测试中的节点不应继续留在失败列表")
	}
}

func TestLocalProxyURLsEscapesCredentials(t *testing.T) {
	listener := gatewayconfig.NewListener("local", "127.0.0.1", 7928, true)
	listener.Username = "proxy user"
	listener.Password = "p@ss:word"

	values := localProxyURLs([]gatewayconfig.Listener{listener})

	if len(values) != 1 {
		t.Fatalf("代理 URL 数量不符合预期: %d", len(values))
	}
	if values[0] != "socks5h://proxy%20user:p%40ss%3Aword@127.0.0.1:7928" {
		t.Fatalf("代理 URL 编码不符合预期: %s", values[0])
	}
}

func TestProxyURLForListenerUsesLoopbackForUnspecifiedAddress(t *testing.T) {
	listener := gatewayconfig.NewListener("public", "::", 7928, true)

	value := proxyURLForListener(listener, "[::]:7928")

	if value != "socks5h://[::1]:7928" {
		t.Fatalf("未指定监听地址的健康检查代理应使用本机回环地址，实际: %s", value)
	}
}

func TestTryAutoConnectSkipsVPNGateNodesWithoutConfiguredOpenVPN(t *testing.T) {
	config := testConfig()
	config.AutoConnect = true
	config.OpenVPNConfig = ""
	server := NewServer(filepath.Join(t.TempDir(), "config.json"), config, nil)
	server.nodes = []vpngate.Node{{
		ID:         "jp-1",
		ConfigText: "client\nremote 203.0.113.10 1194\n",
	}}

	server.tryAutoConnect()

	if server.session != nil {
		t.Fatal("没有监听器绑定策略时，启动自动连接不应使用 VPNGate 节点生成临时 OpenVPN 配置")
	}
}

func TestSelectNodeIDHonorsRoutingPolicy(t *testing.T) {
	nodes := []vpngate.Node{
		{ID: "jp-1", CountryShort: "JP"},
		{ID: "us-1", CountryShort: "US"},
	}

	config := testConfig()
	config.RoutingMode = "auto"
	if got := selectNodeID(config, nodes, nil); got != "jp-1" {
		t.Fatalf("自动模式应选择第一个节点，实际: %s", got)
	}

	config.RoutingMode = "fixed_region"
	config.ForceCountry = "US"
	if got := selectNodeID(config, nodes, nil); got != "us-1" {
		t.Fatalf("固定国家模式选择错误，实际: %s", got)
	}

	config.RoutingMode = "fixed_ip"
	config.FixedNodeID = "jp-1"
	if got := selectNodeID(config, nodes, nil); got != "jp-1" {
		t.Fatalf("固定节点模式选择错误，实际: %s", got)
	}
}

func TestSelectNodeIDSkipsFailedNodes(t *testing.T) {
	nodes := []vpngate.Node{
		{ID: "jp-1", CountryShort: "JP"},
		{ID: "jp-2", CountryShort: "JP"},
	}
	failed := map[string]string{"jp-1": "连接失败"}

	config := testConfig()
	config.RoutingMode = "auto"
	if got := selectNodeID(config, nodes, failed); got != "jp-2" {
		t.Fatalf("自动模式应跳过失败节点，实际: %s", got)
	}

	config.RoutingMode = "fixed_region"
	config.ForceCountry = "JP"
	if got := selectNodeID(config, nodes, failed); got != "jp-2" {
		t.Fatalf("固定国家模式应跳过失败节点，实际: %s", got)
	}
}

func TestSelectListenerNodeIDsHonorsListenerPolicy(t *testing.T) {
	nodes := []vpngate.Node{
		{ID: "jp-1", CountryShort: "JP", RemoteHost: "203.0.113.10", IP: "198.51.100.10"},
		{ID: "jp-2", CountryShort: "JP", RemoteHost: "203.0.114.10", IP: "198.51.100.11"},
		{ID: "us-1", CountryShort: "US", RemoteHost: "192.0.2.10", IP: "192.0.2.10"},
	}
	listener := gatewayconfig.NewListener("local", "127.0.0.1", 7928, true)
	listener.CountryCode = "JP"
	listener.EntryCIDRs = []string{"203.0.113.0/24"}

	ids, err := selectListenerNodeIDs(testConfig(), listener, nodes, nil, 10)
	if err != nil {
		t.Fatalf("监听器策略选择失败: %v", err)
	}
	if len(ids) != 1 || ids[0] != "jp-1" {
		t.Fatalf("监听器策略应按国家和入口 CIDR 过滤节点，实际: %+v", ids)
	}
}

func TestSelectListenerNodeIDsUsesVPNGateIPWhenRemoteHostIsDomain(t *testing.T) {
	nodes := []vpngate.Node{
		{ID: "jp-1", CountryShort: "JP", RemoteHost: "vpn.example.test", IP: "203.0.113.20"},
	}
	listener := gatewayconfig.NewListener("local", "127.0.0.1", 7928, true)
	listener.EntryCIDRs = []string{"203.0.113.0/24"}

	ids, err := selectListenerNodeIDs(testConfig(), listener, nodes, nil, 10)
	if err != nil {
		t.Fatalf("监听器策略选择失败: %v", err)
	}
	if len(ids) != 1 || ids[0] != "jp-1" {
		t.Fatalf("remote_host 为域名时应回退使用 VPNGate 入口 IP，实际: %+v", ids)
	}
}

func TestSelectListenerNodeIDsPrefersListenerFixedNode(t *testing.T) {
	nodes := []vpngate.Node{
		{ID: "jp-1", CountryShort: "JP", RemoteHost: "203.0.113.10"},
		{ID: "jp-2", CountryShort: "US", RemoteHost: "192.0.2.20"},
	}
	listener := gatewayconfig.NewListener("local", "127.0.0.1", 7928, true)
	listener.CountryCode = "JP"
	listener.EntryCIDRs = []string{"203.0.113.0/24"}
	listener.FixedNodeID = "jp-2"

	ids, err := selectListenerNodeIDs(testConfig(), listener, nodes, nil, 10)
	if err != nil {
		t.Fatalf("监听器策略选择失败: %v", err)
	}
	if len(ids) != 1 || ids[0] != "jp-2" {
		t.Fatalf("监听器固定节点应优先生效，实际: %+v", ids)
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(filepath.Join(t.TempDir(), "config.json"), testConfig(), nil)
}

func testConfig() Config {
	adminPasswordHash, err := hashPassword("password")
	if err != nil {
		panic(err)
	}
	return Config{
		WebHost:           "127.0.0.1",
		WebPort:           8787,
		SecretPath:        "secret",
		AdminUsername:     "admin",
		AdminPasswordHash: adminPasswordHash,
		SocksListeners: []gatewayconfig.Listener{
			gatewayconfig.NewListener("local", "127.0.0.1", 7928, true),
		},
	}
}

func addLoginCookie(t *testing.T, server *Server, req *http.Request) {
	t.Helper()
	req.AddCookie(loginCookie(t, server))
}

func loginCookie(t *testing.T, server *Server) *http.Cookie {
	t.Helper()
	body := bytes.NewReader([]byte(`{"username":"admin","password":"password"}`))
	req := httptest.NewRequest(http.MethodPost, "/secret/api/login", body)
	rec := httptest.NewRecorder()
	server.route(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("登录失败: %d %s", rec.Code, rec.Body.String())
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	t.Fatal("登录响应缺少会话 Cookie")
	return nil
}
