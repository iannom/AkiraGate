package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestGatewayStatusDoesNotReportProxyRunningBeforeAllBackendsRun(t *testing.T) {
	server := testServer(t)
	server.listenHost = "127.0.0.1"
	server.listenPort = 8787
	config := testConfig()
	config.SocksListeners = []gatewayconfig.Listener{
		gatewayconfig.NewListener("socks-a", "127.0.0.1", 7928, true),
		gatewayconfig.NewListener("socks-b", "127.0.0.1", 7929, true),
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.session = &Session{
		startedAt: time.Now(),
		config:    config,
		cancel:    cancel,
		status:    "starting",
		message:   "正在启动",
		listenerBackends: map[string]ListenerBackendState{
			"127.0.0.1:7928": {ListenerName: "socks-a", ListenAddress: "127.0.0.1:7928", Status: "running", ProxyURL: "socks5h://127.0.0.1:7928"},
			"127.0.0.1:7929": {ListenerName: "socks-b", ListenAddress: "127.0.0.1:7929", Status: "switching", Error: "健康检查失败"},
		},
	}

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
	var proxyComponent GatewayComponent
	for _, component := range payload.Components {
		if component.Name == "SOCKS5 网关" {
			proxyComponent = component
			break
		}
	}
	if proxyComponent.Status != "switching" {
		t.Fatalf("部分后端未运行时 SOCKS5 网关不应显示 running，实际: %+v", proxyComponent)
	}
}

func TestListenerBackendUpdatesAggregateSessionStatus(t *testing.T) {
	server := testServer(t)
	config := testConfig()
	listenerA := gatewayconfig.NewListener("socks-a", "127.0.0.1", 7928, true)
	listenerB := gatewayconfig.NewListener("socks-b", "127.0.0.1", 7929, true)
	config.SocksListeners = []gatewayconfig.Listener{listenerA, listenerB}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &Session{
		startedAt:        time.Now(),
		config:           config,
		cancel:           cancel,
		status:           "starting",
		message:          "正在启动",
		listenerBackends: map[string]ListenerBackendState{},
	}
	server.session = session

	server.updateListenerBackendState(session, listenerA, ListenerBackendState{Status: "running", ProxyURL: "socks5h://127.0.0.1:7928"})
	server.updateListenerBackendState(session, listenerB, ListenerBackendState{Status: "switching", Error: "健康检查失败"})
	if session.status == "running" {
		t.Fatalf("只有部分入口运行时，会话不应显示 running: status=%s message=%s", session.status, session.message)
	}

	server.updateListenerBackendState(session, listenerB, ListenerBackendState{Status: "running", ProxyURL: "socks5h://127.0.0.1:7929"})
	if session.status != "running" {
		t.Fatalf("所有入口运行后，会话应显示 running: status=%s message=%s", session.status, session.message)
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

func TestTestProxyReturnsPerListenerResults(t *testing.T) {
	server := testServer(t)
	config := testConfig()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.session = &Session{
		startedAt: time.Now(),
		config:    config,
		cancel:    cancel,
		status:    "switching",
		message:   "正在切换",
		listenerBackends: map[string]ListenerBackendState{
			"127.0.0.1:7928": {
				ListenerName:  "socks-a",
				ListenAddress: "127.0.0.1:7928",
				Status:        "switching",
				ProxyURL:      "socks5h://127.0.0.1:7928",
			},
			"127.0.0.1:7929": {
				ListenerName:  "socks-b",
				ListenAddress: "127.0.0.1:7929",
				Status:        "error",
				ProxyURL:      "socks5h://127.0.0.1:7929",
			},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/secret/api/test_proxy", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("入口未全部运行时出口检测应失败，实际: %d", rec.Code)
	}
	var payload ProxyTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("出口检测响应不是有效 JSON: %v", err)
	}
	if payload.OK {
		t.Fatal("入口未全部运行时出口检测不应成功")
	}
	if len(payload.Results) != 2 {
		t.Fatalf("出口检测应返回每个监听入口结果，实际: %d", len(payload.Results))
	}
	for _, result := range payload.Results {
		if result.Listener == "" || result.Listen == "" || result.Error == "" {
			t.Fatalf("入口检测失败结果应包含入口信息和错误: %+v", result)
		}
	}
}

func TestConnectRejectsVPNGateNodesWithoutOpenVPNOrListenerPolicy(t *testing.T) {
	server := testServer(t)
	server.config.OpenVPNConfig = ""
	server.nodes = []vpngate.Node{{
		ID:         "jp-1",
		ConfigText: "client\nremote 203.0.113.10 1194\n",
	}}
	req := httptest.NewRequest(http.MethodPost, "/secret/api/connect", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无 OpenVPN 配置且无入口绑定策略时手动连接应失败，实际: %d", rec.Code)
	}
	if server.session != nil {
		t.Fatal("手动连接失败后不应创建会话")
	}
}

func TestConnectRejectsDisabledListenerBackendPolicy(t *testing.T) {
	server := testServer(t)
	server.config.OpenVPNConfig = ""
	listener := server.config.SocksListeners[0]
	listener.BackendPolicyEnabled = boolPtr(false)
	listener.CountryCode = "JP"
	server.config.SocksListeners[0] = listener
	server.nodes = []vpngate.Node{{
		ID:         "jp-1",
		ConfigText: "client\nremote 203.0.113.10 1194\n",
	}}
	req := httptest.NewRequest(http.MethodPost, "/secret/api/connect", nil)
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("绑定策略关闭时不应把国家代码当作可用策略，实际: %d", rec.Code)
	}
	if server.session != nil {
		t.Fatal("绑定策略关闭的连接失败后不应创建会话")
	}
}

func TestBindNodeToListenerSetsFixedNodePolicy(t *testing.T) {
	config := testConfig()
	listener := config.SocksListeners[0]
	listener.BackendPolicyEnabled = boolPtr(false)
	listener.CountryCode = "JP"
	listener.EntryCIDRs = []string{"203.0.113.0/24"}
	config.SocksListeners[0] = listener

	next, bound, err := bindNodeToListener(config, "jp-1", "", "127.0.0.1:7928")
	if err != nil {
		t.Fatalf("绑定节点到 SOCKS5 入口失败: %v", err)
	}
	if !bound.BackendPolicyIsEnabled() {
		t.Fatal("节点绑定后应启用入口绑定策略")
	}
	if bound.FixedNodeID != "jp-1" {
		t.Fatalf("入口应固定到选择的节点，实际: %q", bound.FixedNodeID)
	}
	if bound.CountryCode != "JP" || len(bound.EntryCIDRs) != 1 {
		t.Fatalf("固定节点绑定不应清理旧国家/网段策略: %+v", bound)
	}
	if next.SocksListeners[0].FixedNodeID != "jp-1" {
		t.Fatalf("返回配置应包含新绑定: %+v", next.SocksListeners[0])
	}
	if config.SocksListeners[0].FixedNodeID != "" {
		t.Fatal("绑定函数不应原地修改输入配置")
	}
}

func TestConnectNodeToListenerPersistsConfigAndClearsFailedNode(t *testing.T) {
	server := testServer(t)
	server.nodes = []vpngate.Node{{
		ID:         "jp-1",
		ConfigText: "client\nremote 203.0.113.10 1194\n",
	}}
	server.failed["jp-1"] = "previous failure"
	req := httptest.NewRequest(http.MethodPost, "/secret/api/connect", bytes.NewReader([]byte(`{"node_id":"jp-1","listen_address":"127.0.0.1:7928"}`)))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)
	defer server.disconnect(httptest.NewRecorder())

	if rec.Code != http.StatusOK {
		t.Fatalf("绑定节点到入口并连接应成功，实际: %d %s", rec.Code, rec.Body.String())
	}
	if _, failed := server.failed["jp-1"]; failed {
		t.Fatal("显式绑定节点后应清理该节点的失败状态")
	}
	config, err := LoadConfig(server.configPath)
	if err != nil {
		t.Fatalf("读取持久化配置失败: %v", err)
	}
	listener := config.SocksListeners[0]
	if !listener.BackendPolicyIsEnabled() || listener.FixedNodeID != "jp-1" {
		t.Fatalf("绑定节点应持久化到配置文件: %+v", listener)
	}
}

func TestConnectSwitchesExistingSession(t *testing.T) {
	server := testServer(t)
	server.config.SocksListeners = []gatewayconfig.Listener{}
	server.nodes = []vpngate.Node{{
		ID:         "jp-1",
		ConfigText: "client\nremote 203.0.113.10 1194\n",
	}}
	cancelled := false
	server.session = &Session{
		startedAt:        time.Now(),
		cancel:           func() { cancelled = true },
		status:           "running",
		message:          "旧连接",
		listenerBackends: map[string]ListenerBackendState{},
	}
	req := httptest.NewRequest(http.MethodPost, "/secret/api/connect", bytes.NewReader([]byte(`{"node_id":"jp-1"}`)))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)
	defer server.disconnect(httptest.NewRecorder())

	if rec.Code != http.StatusOK {
		t.Fatalf("已有连接时连接新节点应切换而不是拒绝，实际: %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Switched bool `json:"switched"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("切换连接响应不是有效 JSON: %v", err)
	}
	if !payload.Switched {
		t.Fatal("切换连接响应应标记 switched=true")
	}
	if !cancelled {
		t.Fatal("切换连接应取消旧会话")
	}
}

func TestFinishOldSessionDoesNotClearNewSessionActiveNodes(t *testing.T) {
	server := testServer(t)
	listener := gatewayconfig.NewListener("local", "127.0.0.1", 7928, true)
	oldSession := &Session{
		startedAt:        time.Now(),
		cancel:           func() {},
		listenerBackends: map[string]ListenerBackendState{},
	}
	newSession := &Session{
		startedAt: time.Now(),
		cancel:    func() {},
		listenerBackends: map[string]ListenerBackendState{
			listenerBackendKey(listener): {
				ListenerName:  listener.Name,
				ListenAddress: listener.ListenAddress(),
				Status:        "running",
				NodeID:        "node-new",
			},
		},
	}
	server.session = newSession
	server.nodes = []vpngate.Node{{ID: "node-new", Active: true}}

	server.finishSession(oldSession, "stopped", "旧连接已退出")

	if server.session != newSession {
		t.Fatal("旧会话退出不应清空当前新会话")
	}
	if !server.nodes[0].Active {
		t.Fatal("旧会话退出不应清空新会话活动节点状态")
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

func TestTestNodeRejectsUnknownNodeID(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/secret/api/test_node", bytes.NewReader([]byte(`{"node_id":"missing"}`)))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("不存在节点 ID 应返回 404，实际: %d", rec.Code)
	}
	if _, failed := server.failed["missing"]; failed {
		t.Fatal("不存在节点测试不应污染失败节点表")
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

func TestProbeNodesConcurrentlyReturnsMoreThanEightNodes(t *testing.T) {
	server := testServer(t)
	nodeIDs := make([]string, 12)
	for idx := range nodeIDs {
		nodeIDs[idx] = fmt.Sprintf("node-%02d", idx)
	}
	probe := func(_ context.Context, nodeID string) (vpngate.Node, error) {
		return vpngate.Node{ID: nodeID, ProbeStatus: "available"}, nil
	}

	nodes, cancelled := server.probeNodesConcurrentlyWith(context.Background(), nodeIDs, batchProbeWorkerCount(len(nodeIDs)), probe)
	if cancelled {
		t.Fatal("未取消的批量测试不应返回 cancelled=true")
	}
	if len(nodes) != len(nodeIDs) {
		t.Fatalf("批量测试应返回所有节点结果，实际: %d，预期: %d", len(nodes), len(nodeIDs))
	}
	for idx, node := range nodes {
		if node.ID != nodeIDs[idx] {
			t.Fatalf("批量测试结果顺序或节点 ID 不符合预期，idx=%d node=%+v", idx, node)
		}
	}
}

func TestBatchProbeWorkerCountMatchesSelectedNodesUpToCap(t *testing.T) {
	if workerCount := batchProbeWorkerCount(12); workerCount != 12 {
		t.Fatalf("批量真测 worker 应等于选中节点数，实际: %d", workerCount)
	}
	if workerCount := batchProbeWorkerCount(maxBatchTestWorkers + 10); workerCount != maxBatchTestWorkers {
		t.Fatalf("超出上限时 worker 应受保护性上限限制，实际: %d", workerCount)
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

func TestBatchProbeWatchdogTimeoutScalesByWorkerBatches(t *testing.T) {
	timeout := batchProbeWatchdogTimeout(17, 8)
	expected := 3 * (batchProbeTimeout + batchProbeGraceTime)
	if timeout != expected {
		t.Fatalf("批量测试 watchdog 应按 worker 批次数扩展，实际: %v，预期: %v", timeout, expected)
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

func TestCancelTestNodeAPIOnlyCancelsSelectedTestingNode(t *testing.T) {
	server := testServer(t)
	server.nodes = []vpngate.Node{{
		ID:           "node-a",
		ProbeStatus:  probeStatusTesting,
		ProbeMessage: "正在测试节点真实出口",
	}}
	_, batch, ok := server.startBatchNodeTest()
	if !ok {
		t.Fatal("测试前置批量任务启动失败")
	}
	defer server.finishBatchNodeTest(batch)
	server.setBatchNodeTestIDs(batch, []string{"node-a"})

	req := httptest.NewRequest(http.MethodPost, "/secret/api/cancel_test_node", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("取消单节点测试应返回 200，实际: %d", rec.Code)
	}
	var payload struct {
		Cancelled bool         `json:"cancelled"`
		Node      vpngate.Node `json:"node"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("取消单节点响应不是有效 JSON: %v", err)
	}
	if !payload.Cancelled || payload.Node.ProbeStatus != "cancelled" {
		t.Fatalf("单节点取消响应不符合预期: %+v", payload)
	}
}

func TestCancelTestNodeAPIDoesNotCancelAlreadyAvailableNode(t *testing.T) {
	server := testServer(t)
	cancelled := false
	token := &nodeTestToken{}
	server.nodes = []vpngate.Node{{
		ID:          "node-a",
		ProbeStatus: "available",
	}}
	server.nodeTests["node-a"] = nodeTestCancel{
		cancel: func() { cancelled = true },
		token:  token,
	}
	_, batch, ok := server.startBatchNodeTest()
	if !ok {
		t.Fatal("测试前置批量任务启动失败")
	}
	defer server.finishBatchNodeTest(batch)
	server.setBatchNodeTestIDs(batch, []string{"node-a"})

	req := httptest.NewRequest(http.MethodPost, "/secret/api/cancel_test_node", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	addLoginCookie(t, server, req)
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("取消已完成节点应返回 200，实际: %d", rec.Code)
	}
	var payload struct {
		Cancelled bool `json:"cancelled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("取消单节点响应不是有效 JSON: %v", err)
	}
	if payload.Cancelled {
		t.Fatal("已通过测试的节点不应被单独取消")
	}
	if cancelled {
		t.Fatal("已完成节点即使存在尚未注销的测试 token，也不应触发取消")
	}
	if server.nodes[0].ProbeStatus != "available" {
		t.Fatalf("已通过节点状态不应被改写，实际: %+v", server.nodes[0])
	}
}

func TestProbeNodesConcurrentlyCancelsSingleQueuedNode(t *testing.T) {
	server := testServer(t)
	server.nodes = []vpngate.Node{{
		ID:           "node-a",
		ProbeStatus:  probeStatusTesting,
		ProbeMessage: "正在测试节点真实出口",
	}, {
		ID:           "node-b",
		ProbeStatus:  probeStatusTesting,
		ProbeMessage: "正在测试节点真实出口",
	}}
	_, batch, ok := server.startBatchNodeTest()
	if !ok {
		t.Fatal("测试前置批量任务启动失败")
	}
	defer server.finishBatchNodeTest(batch)
	server.setBatchNodeTestIDs(batch, []string{"node-a", "node-b"})
	if _, cancelled := server.cancelNodeTest("node-b"); !cancelled {
		t.Fatal("应能取消批量任务中的单个节点")
	}
	probe := func(_ context.Context, nodeID string) (vpngate.Node, error) {
		return vpngate.Node{ID: nodeID, ProbeStatus: "available"}, nil
	}

	nodes, cancelled := server.probeNodesConcurrentlyWith(context.Background(), []string{"node-a", "node-b"}, 1, probe)

	if !cancelled {
		t.Fatal("单节点取消后批量结果应标记 cancelled=true")
	}
	if len(nodes) != 2 {
		t.Fatalf("批量测试应返回所有节点状态，实际: %d", len(nodes))
	}
	if nodes[0].ProbeStatus != "available" || nodes[1].ProbeStatus != "cancelled" {
		t.Fatalf("单节点取消结果不符合预期: %+v", nodes)
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

func TestProbeNodesConcurrentlyCancelsHungProbe(t *testing.T) {
	server := testServer(t)
	server.nodes = []vpngate.Node{{
		ID:           "node-a",
		ProbeStatus:  probeStatusTesting,
		ProbeMessage: "正在测试节点真实出口",
	}}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	probe := func(context.Context, string) (vpngate.Node, error) {
		close(started)
		<-release
		return vpngate.Node{ID: "node-a", ProbeStatus: "available"}, nil
	}
	done := make(chan struct {
		nodes     []vpngate.Node
		cancelled bool
	}, 1)
	go func() {
		nodes, cancelled := server.probeNodesConcurrentlyWith(ctx, []string{"node-a"}, 1, probe)
		done <- struct {
			nodes     []vpngate.Node
			cancelled bool
		}{nodes: nodes, cancelled: cancelled}
	}()

	select {
	case <-started:
		cancel()
	case <-time.After(500 * time.Millisecond):
		t.Fatal("测试探测函数未启动")
	}

	select {
	case result := <-done:
		if !result.cancelled {
			t.Fatal("取消后的批量测试应返回 cancelled=true")
		}
		if len(result.nodes) != 1 || result.nodes[0].ProbeStatus != "cancelled" {
			t.Fatalf("未返回的节点应被标记为 cancelled: %+v", result.nodes)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("底层探测不返回时批量测试不应阻塞等待")
	}
}

func TestProbeNodesConcurrentlyTimesOutHungProbe(t *testing.T) {
	server := testServer(t)
	nodeIDs := []string{"node-a", "node-b", "node-c"}
	for _, nodeID := range nodeIDs {
		server.nodes = append(server.nodes, vpngate.Node{
			ID:           nodeID,
			ProbeStatus:  probeStatusTesting,
			ProbeMessage: "正在测试节点真实出口",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := make(chan struct{}, len(nodeIDs))
	release := make(chan struct{})
	defer close(release)

	probe := func(context.Context, string) (vpngate.Node, error) {
		started <- struct{}{}
		<-release
		return vpngate.Node{}, nil
	}
	done := make(chan struct {
		nodes     []vpngate.Node
		cancelled bool
	}, 1)
	go func() {
		nodes, cancelled := server.probeNodesConcurrentlyWith(ctx, nodeIDs, 2, probe)
		done <- struct {
			nodes     []vpngate.Node
			cancelled bool
		}{nodes: nodes, cancelled: cancelled}
	}()

	select {
	case <-started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("测试探测函数未启动")
	}

	select {
	case result := <-done:
		if !result.cancelled {
			t.Fatal("deadline 后批量测试应返回 cancelled=true")
		}
		if len(result.nodes) != len(nodeIDs) {
			t.Fatalf("deadline 后应返回所有节点状态，实际: %d", len(result.nodes))
		}
		for _, node := range result.nodes {
			if node.ProbeStatus != "unavailable" || node.ProbeMessage != "节点测试超时" {
				t.Fatalf("deadline 后节点应标记为超时失败: %+v", node)
			}
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("底层探测不返回时 deadline 应自动收敛")
	}
}

func TestProbeNodesConcurrentlyMarksPanicAsFailure(t *testing.T) {
	server := testServer(t)
	server.nodes = []vpngate.Node{{
		ID:           "node-a",
		ProbeStatus:  probeStatusTesting,
		ProbeMessage: "正在测试节点真实出口",
	}}
	probe := func(context.Context, string) (vpngate.Node, error) {
		panic("boom")
	}

	nodes, cancelled := server.probeNodesConcurrentlyWith(context.Background(), []string{"node-a"}, 1, probe)
	if cancelled {
		t.Fatal("探测 panic 不应被标记为取消")
	}
	if len(nodes) != 1 || nodes[0].ProbeStatus != "unavailable" {
		t.Fatalf("探测 panic 应返回失败节点: %+v", nodes)
	}
	if !strings.Contains(nodes[0].ProbeMessage, "节点测试异常") {
		t.Fatalf("探测 panic 应包含可读失败原因: %+v", nodes[0])
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

func TestRunSessionCancelsOtherWorkersOnListenerError(t *testing.T) {
	server := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := false
	session := &Session{
		startedAt: time.Now(),
		cancel: func() {
			cancelled = true
			cancel()
		},
		listenerBackends: map[string]ListenerBackendState{},
	}
	server.session = session
	resultCh := make(chan listenerWorkerResult, 1)
	resultCh <- listenerWorkerResult{
		Listener: gatewayconfig.NewListener("local", "127.0.0.1", 7928, true),
		Err:      errors.New("监听失败"),
	}

	server.consumeListenerResults(ctx, session, resultCh)

	if !cancelled {
		t.Fatal("任一 SOCKS5 入口失败时应取消会话上下文以清理其它后端")
	}
	if server.session != nil {
		t.Fatal("入口失败后会话应结束")
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
	listener.BackendPolicyEnabled = boolPtr(true)
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

func TestSelectListenerNodeIDsIgnoresPolicyValuesWhenPolicyDisabled(t *testing.T) {
	nodes := []vpngate.Node{
		{ID: "jp-1", CountryShort: "JP", RemoteHost: "203.0.113.10", IP: "198.51.100.10"},
		{ID: "us-1", CountryShort: "US", RemoteHost: "192.0.2.10", IP: "192.0.2.10"},
	}
	listener := gatewayconfig.NewListener("local", "127.0.0.1", 7928, true)
	listener.BackendPolicyEnabled = boolPtr(false)
	listener.CountryCode = "JP"
	listener.EntryCIDRs = []string{"203.0.113.0/24"}

	ids, err := selectListenerNodeIDs(testConfig(), listener, nodes, nil, 10)
	if err != nil {
		t.Fatalf("监听器策略关闭时选择节点失败: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("绑定策略关闭时不应按国家或入口 CIDR 过滤节点，实际: %+v", ids)
	}
}

func TestSelectListenerNodeIDsUsesVPNGateIPWhenRemoteHostIsDomain(t *testing.T) {
	nodes := []vpngate.Node{
		{ID: "jp-1", CountryShort: "JP", RemoteHost: "vpn.example.test", IP: "203.0.113.20"},
	}
	listener := gatewayconfig.NewListener("local", "127.0.0.1", 7928, true)
	listener.BackendPolicyEnabled = boolPtr(true)
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
	listener.BackendPolicyEnabled = boolPtr(true)
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

func TestProxyAllocateRequiresAPIToken(t *testing.T) {
	server := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/secret/api/proxy/allocate", bytes.NewReader([]byte(`{"country_code":"JP"}`)))
	rec := httptest.NewRecorder()

	server.route(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("未配置 API Token 时应拒绝机器接口，实际: %d", rec.Code)
	}
}

func TestProxyAllocateCreatesDynamicSocksEntryAndSkipsRecentExitIP(t *testing.T) {
	server, token, closed := testProxyAPIServer(t)
	now := time.Now()
	server.nodes = []vpngate.Node{
		proxyTestNode("jp-1", "JP", "198.51.100.10"),
		proxyTestNode("jp-2", "JP", "198.51.100.11"),
	}
	server.proxyCache = map[string]proxyCacheEntry{
		"jp-1": proxyTestCache("jp-1", "JP", "198.51.100.10", now.Add(time.Hour)),
		"jp-2": proxyTestCache("jp-2", "JP", "198.51.100.11", now.Add(time.Hour)),
	}

	first := proxyAllocateRequest(t, server, token, "JP")
	if first.Code != http.StatusOK {
		t.Fatalf("首次分配应成功: %d %s", first.Code, first.Body.String())
	}
	var firstPayload ProxyAllocateResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstPayload); err != nil {
		t.Fatalf("首次分配响应不是有效 JSON: %v", err)
	}
	if firstPayload.NodeID != "jp-1" || firstPayload.ExitIP != "198.51.100.10" {
		t.Fatalf("首次分配应返回第一个家宽节点，实际: %+v", firstPayload)
	}
	if firstPayload.Host != "203.0.113.200" || firstPayload.Port != 19080 {
		t.Fatalf("动态入口应返回外部可连接地址，实际: %+v", firstPayload)
	}
	if firstPayload.Username == "" || firstPayload.Password == "" || !strings.Contains(firstPayload.ProxyURL, "@203.0.113.200:19080") {
		t.Fatalf("动态入口应返回带鉴权 SOCKS5 信息，实际: %+v", firstPayload)
	}

	second := proxyAllocateRequest(t, server, token, "JP")
	if second.Code != http.StatusOK {
		t.Fatalf("第二次分配应跳过一小时内已返回的出口 IP: %d %s", second.Code, second.Body.String())
	}
	var secondPayload ProxyAllocateResponse
	if err := json.Unmarshal(second.Body.Bytes(), &secondPayload); err != nil {
		t.Fatalf("第二次分配响应不是有效 JSON: %v", err)
	}
	if secondPayload.NodeID != "jp-2" || secondPayload.ExitIP != "198.51.100.11" {
		t.Fatalf("第二次分配应返回不同出口 IP，实际: %+v", secondPayload)
	}

	release := proxyReleaseRequest(t, server, token, firstPayload.AllocationID)
	if release.Code != http.StatusOK {
		t.Fatalf("释放动态入口失败: %d %s", release.Code, release.Body.String())
	}
	if *closed != 1 {
		t.Fatalf("释放 API 应关闭对应动态入口，实际关闭次数: %d", *closed)
	}
}

func TestProxyAllocateFiltersResidentialAndCacheTTL(t *testing.T) {
	server, token, _ := testProxyAPIServer(t)
	now := time.Now()
	server.nodes = []vpngate.Node{
		proxyTestNode("jp-dc", "JP", "198.51.100.20"),
		proxyTestNode("jp-expired", "JP", "198.51.100.21"),
		proxyTestNode("jp-home", "JP", "198.51.100.22"),
	}
	server.proxyCache = map[string]proxyCacheEntry{
		"jp-dc":      {NodeID: "jp-dc", CountryCode: "JP", ExitIP: "198.51.100.20", IPType: "datacenter", Available: true, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)},
		"jp-expired": proxyTestCache("jp-expired", "JP", "198.51.100.21", now.Add(-time.Second)),
		"jp-home":    proxyTestCache("jp-home", "JP", "198.51.100.22", now.Add(time.Hour)),
	}

	rec := proxyAllocateRequest(t, server, token, "JP")

	if rec.Code != http.StatusOK {
		t.Fatalf("应选择未过期的家宽缓存节点: %d %s", rec.Code, rec.Body.String())
	}
	var payload ProxyAllocateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("分配响应不是有效 JSON: %v", err)
	}
	if payload.NodeID != "jp-home" {
		t.Fatalf("应过滤数据中心和过期缓存，实际: %+v", payload)
	}
}

func TestReleaseProxyIsIdempotent(t *testing.T) {
	server, token, _ := testProxyAPIServer(t)
	rec := proxyReleaseRequest(t, server, token, "missing")

	if rec.Code != http.StatusOK {
		t.Fatalf("释放不存在动态入口也应幂等成功: %d %s", rec.Code, rec.Body.String())
	}
	var payload ProxyReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("释放响应不是有效 JSON: %v", err)
	}
	if payload.Released {
		t.Fatalf("不存在的动态入口不应标记为已释放: %+v", payload)
	}
}

func TestReleaseProxyKeepsAllocationWhenCloseFails(t *testing.T) {
	server := testServer(t)
	closeErr := errors.New("close failed")
	server.dynamicProxies["lease-1"] = dynamicProxyAllocation{
		ID:        "lease-1",
		ExpiresAt: time.Now().Add(time.Hour),
		Handle: dynamicProxyHandle{close: func() error {
			return closeErr
		}},
	}

	released, err := server.releaseProxyAllocation("lease-1")

	if !released || err == nil {
		t.Fatalf("关闭失败时应返回释放失败: released=%t err=%v", released, err)
	}
	if _, ok := server.dynamicProxies["lease-1"]; !ok {
		t.Fatal("关闭失败时应保留分配记录，允许后续重试释放")
	}
	if len(server.releasingProxies) != 0 {
		t.Fatalf("关闭失败后应清理释放中标记: %+v", server.releasingProxies)
	}
}

func TestCleanupExpiredProxyAllocationsClosesHandles(t *testing.T) {
	server := testServer(t)
	closed := 0
	server.dynamicProxies["lease-1"] = dynamicProxyAllocation{
		ID:        "lease-1",
		ExpiresAt: time.Now().Add(-time.Second),
		Handle: dynamicProxyHandle{close: func() error {
			closed++
			return nil
		}},
	}

	server.cleanupExpiredProxyAllocations(time.Now())

	if closed != 1 {
		t.Fatalf("过期动态入口应自动关闭，实际关闭次数: %d", closed)
	}
	if len(server.dynamicProxies) != 0 {
		t.Fatalf("过期动态入口应从状态中清理: %+v", server.dynamicProxies)
	}
}

func TestCleanupExpiredProxyAllocationsKeepsFailedClose(t *testing.T) {
	server := testServer(t)
	server.dynamicProxies["lease-1"] = dynamicProxyAllocation{
		ID:        "lease-1",
		ExpiresAt: time.Now().Add(-time.Second),
		Handle: dynamicProxyHandle{close: func() error {
			return errors.New("close failed")
		}},
	}

	server.cleanupExpiredProxyAllocations(time.Now())

	if _, ok := server.dynamicProxies["lease-1"]; !ok {
		t.Fatal("自动释放失败时应保留分配记录，等待下次重试")
	}
}

func TestMergeRetainedNodesKeepsAllocatedAndCachedNodes(t *testing.T) {
	server := testServer(t)
	now := time.Now()
	server.nodes = []vpngate.Node{
		{ID: "cached", CountryShort: "JP"},
		{ID: "allocated", CountryShort: "US"},
		{ID: "stale", CountryShort: "TH"},
	}
	server.proxyCache["cached"] = proxyCacheEntry{NodeID: "cached", ExpiresAt: now.Add(time.Hour)}
	server.dynamicProxies["lease"] = dynamicProxyAllocation{ID: "lease", NodeID: "allocated", ExpiresAt: now.Add(time.Hour)}

	merged := server.mergeRetainedNodesLocked([]vpngate.Node{{ID: "fresh", CountryShort: "RO"}}, now)

	ids := map[string]struct{}{}
	for _, node := range merged {
		ids[node.ID] = struct{}{}
	}
	for _, expected := range []string{"fresh", "cached", "allocated"} {
		if _, ok := ids[expected]; !ok {
			t.Fatalf("刷新节点后应保留 %s，实际: %+v", expected, merged)
		}
	}
	if _, ok := ids["stale"]; ok {
		t.Fatalf("无活跃、无分配、缓存过期外的旧节点不应保留: %+v", merged)
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(filepath.Join(t.TempDir(), "config.json"), testConfig(), nil)
}

func testConfig() Config {
	adminPasswordHash, err := HashPassword("password")
	if err != nil {
		panic(err)
	}
	return Config{
		WebHost:           "127.0.0.1",
		WebPort:           8787,
		SecretPath:        "secret",
		AdminUsername:     "admin",
		AdminPasswordHash: adminPasswordHash,
		ProxyCacheTTL:     3600,
		ProxyLeaseSeconds: 3600,
		ProxyListenHost:   "0.0.0.0",
		RefreshSeconds:    960,
		RoutingMode:       "auto",
		SocksListeners: []gatewayconfig.Listener{
			gatewayconfig.NewListener("local", "127.0.0.1", 7928, true),
		},
	}
}

func testProxyAPIServer(t *testing.T) (*Server, string, *int) {
	t.Helper()
	config := testConfig()
	token := "machine-token"
	hash, err := HashAPIToken(token)
	if err != nil {
		t.Fatalf("生成 API Token 哈希失败: %v", err)
	}
	config.APITokenHash = hash
	server := NewServer(filepath.Join(t.TempDir(), "config.json"), config, nil)
	closed := 0
	server.startDynamicProxy = func(_ context.Context, options dynamicProxyStartOptions) (dynamicProxyHandle, error) {
		if options.Listener.Username == "" || options.Listener.Password == "" {
			return dynamicProxyHandle{}, errors.New("动态 SOCKS5 入口必须启用鉴权")
		}
		return dynamicProxyHandle{
			ProxyAddress: "0.0.0.0:19080",
			close: func() error {
				closed++
				return nil
			},
		}, nil
	}
	return server, token, &closed
}

func proxyTestNode(id string, countryCode string, exitIP string) vpngate.Node {
	return vpngate.Node{
		ID:           id,
		CountryShort: countryCode,
		IP:           "203.0.113.10",
		RemoteHost:   "203.0.113.10",
		ConfigText:   "client\nremote 203.0.113.10 1194 udp\n",
		ProbeStatus:  "available",
		ProbeLatency: 120,
		ExitIPInfo: &vpngate.IPInfo{
			IP:          exitIP,
			CountryCode: countryCode,
			IPType:      "broadband",
			Residential: true,
		},
	}
}

func proxyTestCache(nodeID string, countryCode string, exitIP string, expiresAt time.Time) proxyCacheEntry {
	return proxyCacheEntry{
		NodeID:      nodeID,
		CountryCode: countryCode,
		EntryIP:     "203.0.113.10",
		ExitIP:      exitIP,
		IPType:      "broadband",
		Residential: true,
		Available:   true,
		LatencyMS:   120,
		UpdatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
	}
}

func proxyAllocateRequest(t *testing.T, server *Server, token string, countryCode string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/secret/api/proxy/allocate", bytes.NewReader([]byte(fmt.Sprintf(`{"country_code":"%s"}`, countryCode))))
	req.Host = "203.0.113.200:8787"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.route(rec, req)
	return rec
}

func proxyReleaseRequest(t *testing.T, server *Server, token string, allocationID string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(ProxyReleaseRequest{AllocationID: allocationID})
	if err != nil {
		t.Fatalf("构造释放请求失败: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/secret/api/proxy/release", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.route(rec, req)
	return rec
}

func boolPtr(value bool) *bool {
	return &value
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
