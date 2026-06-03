package manager

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gatewayconfig "aimilivpn/userspace-gateway/internal/config"
	"aimilivpn/userspace-gateway/internal/socks"
	"aimilivpn/userspace-gateway/internal/vpn"
	"aimilivpn/userspace-gateway/internal/vpngate"
)

const (
	sessionCookieName    = "aimili_session"
	defaultIPPureInfoURL = "https://my.ippure.com/v1/info"
	maxBatchNodeTests    = 8
	exitInfoRequestLimit = 16 * 1024
)

type Server struct {
	configPath string
	config     Config
	logger     *slog.Logger
	logBuffer  *LogBuffer
	httpServer *http.Server
	webRoot    string
	listenHost string
	listenPort int

	mu           sync.Mutex
	session      *Session
	authSessions map[string]authSession
	nodes        []vpngate.Node
	failed       map[string]string
}

type authSession struct {
	Username  string
	ExpiresAt time.Time
}

type Session struct {
	startedAt time.Time
	config    Config
	cancel    context.CancelFunc
	status    string
	message   string
	socksURLs []string
	nodeID    string
}

type GatewayComponent struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details"`
	Error   string `json:"error,omitempty"`
}

type ProxyTestResult struct {
	OK        bool            `json:"ok"`
	IP        string          `json:"ip,omitempty"`
	LatencyMS int             `json:"latency_ms,omitempty"`
	Error     string          `json:"error,omitempty"`
	ProxyURL  string          `json:"proxy_url,omitempty"`
	Info      *vpngate.IPInfo `json:"info,omitempty"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResult struct {
	OK        bool   `json:"ok"`
	Username  string `json:"username,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type AuthState struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

type State struct {
	Connected      bool                     `json:"connected"`
	Status         string                   `json:"status"`
	Message        string                   `json:"message"`
	WebHost        string                   `json:"web_host"`
	WebPort        int                      `json:"web_port"`
	RuntimeWebHost string                   `json:"runtime_web_host"`
	RuntimeWebPort int                      `json:"runtime_web_port"`
	RestartNeeded  bool                     `json:"restart_needed"`
	SecretPath     string                   `json:"secret_path"`
	OpenVPNConfig  string                   `json:"openvpn_config"`
	OpenVPNAuth    string                   `json:"openvpn_auth"`
	SocksListeners []gatewayconfig.Listener `json:"socks5_listeners"`
	LocalProxyURLs []string                 `json:"local_proxy_urls"`
	ConnectedSince string                   `json:"connected_since,omitempty"`
	AdminUsername  string                   `json:"admin_username"`
	AdminPassword  string                   `json:"admin_password"`
	Nodes          []vpngate.Node           `json:"nodes"`
	ActiveNodeID   string                   `json:"active_node_id,omitempty"`
	FailedNodes    map[string]string        `json:"failed_nodes,omitempty"`
	AutoConnect    bool                     `json:"auto_connect"`
	RefreshSeconds int                      `json:"refresh_seconds"`
	RoutingMode    string                   `json:"routing_mode"`
	ForceCountry   string                   `json:"force_country"`
	FixedNodeID    string                   `json:"fixed_node_id"`
}

func NewServer(configPath string, config Config, logger *slog.Logger, logBuffer ...*LogBuffer) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	var buffer *LogBuffer
	if len(logBuffer) > 0 {
		buffer = logBuffer[0]
	}
	return &Server{
		configPath:   configPath,
		config:       config,
		logger:       logger,
		logBuffer:    buffer,
		webRoot:      defaultWebRoot(),
		authSessions: map[string]authSession{},
		failed:       map[string]string{},
	}
}

func (s *Server) SetWebRoot(webRoot string) error {
	cleaned := strings.TrimSpace(webRoot)
	if cleaned == "" {
		return errors.New("前端静态目录不能为空")
	}
	absoluteRoot, err := filepath.Abs(cleaned)
	if err != nil {
		return fmt.Errorf("前端静态目录路径无效: %w", err)
	}
	info, err := os.Stat(absoluteRoot)
	if err != nil {
		return fmt.Errorf("前端静态目录不可读: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("前端静态目录不是目录: %s", absoluteRoot)
	}
	indexPath := filepath.Join(absoluteRoot, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		return fmt.Errorf("前端入口文件不可读: %w", err)
	}
	s.mu.Lock()
	s.webRoot = absoluteRoot
	s.mu.Unlock()
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.route)
	address := net.JoinHostPort(s.config.WebHost, fmt.Sprintf("%d", s.config.WebPort))
	s.mu.Lock()
	s.listenHost = s.config.WebHost
	s.listenPort = s.config.WebPort
	s.mu.Unlock()
	s.httpServer = &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Info("Go 管理服务已启动", "listen", address, "secret_path", s.config.SecretPath)
	go s.maintenanceLoop(ctx)
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	config := s.configSnapshot()
	prefix := "/" + config.SecretPath + "/"
	if r.URL.Path == "/"+config.SecretPath {
		http.Redirect(w, r, prefix, http.StatusFound)
		return
	}
	if !stringsHasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	path := "/" + r.URL.Path[len(prefix):]
	switch {
	case r.Method == http.MethodGet && (path == "/" || path == "/index.html"):
		s.sendIndex(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/assets/"):
		s.sendStatic(w, r, path)
	case r.Method == http.MethodGet && path == "/favicon.ico":
		s.sendStatic(w, r, path)
	case r.Method == http.MethodPost && path == "/api/login":
		s.login(w, r, config)
	case r.Method == http.MethodPost && path == "/api/logout":
		s.logout(w, r)
	case r.Method == http.MethodGet && path == "/api/session":
		s.sessionState(w, r)
	case r.Method == http.MethodGet && path == "/api/state":
		if !s.requireAuth(w, r) {
			return
		}
		s.sendJSON(w, s.state())
	case r.Method == http.MethodGet && path == "/api/logs":
		if !s.requireAuth(w, r) {
			return
		}
		s.logs(w)
	case r.Method == http.MethodGet && path == "/api/gateway_status":
		if !s.requireAuth(w, r) {
			return
		}
		s.gatewayStatus(w)
	case r.Method == http.MethodPost && path == "/api/settings":
		if !s.requireAuth(w, r) {
			return
		}
		s.updateSettings(w, r)
	case r.Method == http.MethodPost && path == "/api/connect":
		if !s.requireAuth(w, r) {
			return
		}
		s.connect(w, r)
	case r.Method == http.MethodPost && path == "/api/refresh_nodes":
		if !s.requireAuth(w, r) {
			return
		}
		s.refreshNodes(w)
	case r.Method == http.MethodPost && path == "/api/test_proxy":
		if !s.requireAuth(w, r) {
			return
		}
		s.testProxy(w)
	case r.Method == http.MethodPost && path == "/api/test_node":
		if !s.requireAuth(w, r) {
			return
		}
		s.testNode(w, r)
	case r.Method == http.MethodPost && path == "/api/test_nodes":
		if !s.requireAuth(w, r) {
			return
		}
		s.testNodes(w, r)
	case r.Method == http.MethodPost && path == "/api/disconnect":
		if !s.requireAuth(w, r) {
			return
		}
		s.disconnect(w)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) gatewayStatus(w http.ResponseWriter) {
	s.mu.Lock()
	session := s.session
	config := s.config
	nodesCount := len(s.nodes)
	listenHost := s.listenHost
	listenPort := s.listenPort
	s.mu.Unlock()

	webStatus := "running"
	webDetails := net.JoinHostPort(listenHost, fmt.Sprintf("%d", listenPort))
	if listenHost == "" || listenPort == 0 {
		webStatus = "starting"
		webDetails = "Web 服务正在启动"
	}

	vpnStatus := "stopped"
	vpnDetails := "未连接"
	proxyStatus := "stopped"
	proxyDetails := "SOCKS5 网关未启动"
	if session != nil {
		vpnStatus = session.status
		vpnDetails = session.message
		if len(session.socksURLs) > 0 {
			proxyStatus = "running"
			proxyDetails = strings.Join(session.socksURLs, "\n")
		}
	}

	refreshDetails := fmt.Sprintf("节点数: %d，刷新间隔: %d 秒，自动连接: %t，路由模式: %s", nodesCount, config.RefreshSeconds, config.AutoConnect, config.RoutingMode)
	s.sendJSON(w, map[string]any{
		"components": []GatewayComponent{
			{Name: "Web 管理服务", Status: webStatus, Details: webDetails},
			{Name: "用户态 OpenVPN", Status: vpnStatus, Details: vpnDetails},
			{Name: "SOCKS5 网关", Status: proxyStatus, Details: proxyDetails},
			{Name: "VPNGate 节点维护", Status: "running", Details: refreshDetails},
		},
	})
}

func (s *Server) testProxy(w http.ResponseWriter) {
	s.mu.Lock()
	session := s.session
	var proxyURL string
	if session != nil && len(session.socksURLs) > 0 {
		proxyURL = session.socksURLs[0]
	}
	s.mu.Unlock()

	result := checkProxy(proxyURL)
	status := http.StatusOK
	if !result.OK {
		status = http.StatusBadGateway
	}
	s.sendJSONWithStatus(w, status, result)
}

func (s *Server) configSnapshot() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

func (s *Server) logs(w http.ResponseWriter) {
	if s.logBuffer == nil {
		s.sendJSON(w, map[string]any{"logs": []LogEntry{}})
		return
	}
	s.sendJSON(w, map[string]any{"logs": s.logBuffer.Entries()})
}

func (s *Server) sendIndex(w http.ResponseWriter, r *http.Request) {
	webRoot := s.webRootSnapshot()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, filepath.Join(webRoot, "index.html"))
}

func (s *Server) sendStatic(w http.ResponseWriter, r *http.Request, requestPath string) {
	webRoot := s.webRootSnapshot()
	cleanPath := path.Clean("/" + requestPath)
	if cleanPath != "/favicon.ico" && !strings.HasPrefix(cleanPath, "/assets/") {
		http.NotFound(w, r)
		return
	}
	relativePath := strings.TrimPrefix(cleanPath, "/")
	if relativePath == "" || strings.HasPrefix(relativePath, "..") {
		http.NotFound(w, r)
		return
	}
	filePath := filepath.Join(webRoot, filepath.FromSlash(relativePath))
	if !strings.HasPrefix(filePath, filepath.Clean(webRoot)+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}
	if contentType := mime.TypeByExtension(filepath.Ext(filePath)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeFile(w, r, filePath)
}

func (s *Server) webRootSnapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.webRoot
}

func defaultWebRoot() string {
	if value := strings.TrimSpace(os.Getenv("AIMILI_WEB_ROOT")); value != "" {
		return value
	}
	return filepath.Join("frontend", "dist")
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, config Config) {
	var request LoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil {
		s.sendError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	username := strings.TrimSpace(request.Username)
	password := request.Password
	if username == "" || password == "" {
		s.sendError(w, http.StatusBadRequest, "管理账号和密码不能为空")
		return
	}
	if !constantTimeEqual(username, config.AdminUsername) || !verifyPassword(config.AdminPasswordHash, password) {
		s.sendError(w, http.StatusUnauthorized, "管理账号或密码错误")
		return
	}
	token, err := newSessionToken()
	if err != nil {
		s.logger.Error("生成会话令牌失败", "error", err)
		s.sendError(w, http.StatusInternalServerError, "生成登录会话失败")
		return
	}
	expiresAt := time.Now().Add(12 * time.Hour)
	s.mu.Lock()
	s.authSessions[token] = authSession{Username: username, ExpiresAt: expiresAt}
	s.mu.Unlock()
	setSessionCookie(w, token, expiresAt)
	s.sendJSON(w, LoginResult{OK: true, Username: username, ExpiresAt: expiresAt.Format(time.RFC3339)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.authSessions, cookie.Value)
		s.mu.Unlock()
	}
	clearSessionCookie(w)
	s.sendJSON(w, map[string]any{"ok": true})
}

func (s *Server) sessionState(w http.ResponseWriter, r *http.Request) {
	session, ok := s.authSession(r)
	if !ok {
		s.sendJSONWithStatus(w, http.StatusUnauthorized, AuthState{Authenticated: false})
		return
	}
	s.sendJSON(w, AuthState{
		Authenticated: true,
		Username:      session.Username,
		ExpiresAt:     session.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := s.authSession(r); ok {
		return true
	}
	s.sendJSONWithStatus(w, http.StatusUnauthorized, map[string]any{
		"ok":    false,
		"error": "未登录或登录已过期",
	})
	return false
}

func (s *Server) authSession(r *http.Request) (authSession, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return authSession{}, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.authSessions[cookie.Value]
	if !ok {
		return authSession{}, false
	}
	if !session.ExpiresAt.After(now) {
		delete(s.authSessions, cookie.Value)
		return authSession{}, false
	}
	return session, true
}

func (s *Server) sendJSON(w http.ResponseWriter, value any) {
	s.sendJSONWithStatus(w, http.StatusOK, value)
}

func (s *Server) sendJSONWithStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) sendError(w http.ResponseWriter, status int, message string) {
	s.sendJSONWithStatus(w, status, map[string]any{"ok": false, "error": message})
}

func (s *Server) state() State {
	s.mu.Lock()
	defer s.mu.Unlock()

	connected := s.session != nil
	status := "stopped"
	message := "未连接"
	connectedSince := ""
	if s.session != nil {
		status = s.session.status
		message = s.session.message
		connectedSince = s.session.startedAt.Format(time.RFC3339)
	}
	nodes := make([]vpngate.Node, len(s.nodes))
	copy(nodes, s.nodes)
	failed := make(map[string]string, len(s.failed))
	for key, value := range s.failed {
		failed[key] = value
	}
	activeNodeID := ""
	if s.session != nil {
		for _, node := range nodes {
			if node.Active {
				activeNodeID = node.ID
				break
			}
		}
	}
	return State{
		Connected:      connected,
		Status:         status,
		Message:        message,
		WebHost:        s.config.WebHost,
		WebPort:        s.config.WebPort,
		RuntimeWebHost: s.listenHost,
		RuntimeWebPort: s.listenPort,
		RestartNeeded:  s.webRestartNeededLocked(),
		SecretPath:     s.config.SecretPath,
		OpenVPNConfig:  s.config.OpenVPNConfig,
		OpenVPNAuth:    s.config.OpenVPNAuth,
		SocksListeners: s.config.SocksListeners,
		LocalProxyURLs: localProxyURLs(s.config.SocksListeners),
		ConnectedSince: connectedSince,
		AdminUsername:  s.config.AdminUsername,
		AdminPassword:  "",
		Nodes:          nodes,
		ActiveNodeID:   activeNodeID,
		FailedNodes:    failed,
		AutoConnect:    s.config.AutoConnect,
		RefreshSeconds: s.config.RefreshSeconds,
		RoutingMode:    s.config.RoutingMode,
		ForceCountry:   s.config.ForceCountry,
		FixedNodeID:    s.config.FixedNodeID,
	}
}

func (s *Server) webRestartNeededLocked() bool {
	if s.listenHost == "" || s.listenPort == 0 {
		return false
	}
	return s.config.WebHost != s.listenHost || s.config.WebPort != s.listenPort
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var next Config
	if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
		s.sendError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	s.mu.Lock()
	currentHash := s.config.AdminPasswordHash
	currentUsername := s.config.AdminUsername
	s.mu.Unlock()
	passwordChanged := strings.TrimSpace(next.AdminPassword) != ""
	if passwordChanged {
		hash, err := hashPassword(next.AdminPassword)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		next.AdminPasswordHash = hash
	} else {
		next.AdminPasswordHash = currentHash
	}
	next.AdminPassword = ""
	normalizeConfig(&next)
	if err := SaveConfig(s.configPath, next); err != nil {
		s.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.Lock()
	s.config = next
	if passwordChanged || next.AdminUsername != currentUsername {
		s.authSessions = map[string]authSession{}
		clearSessionCookie(w)
	}
	restartNeeded := s.webRestartNeededLocked()
	s.mu.Unlock()
	message := "配置已保存，重新连接后生效"
	if restartNeeded {
		message = "配置已保存，Web 监听地址或端口将在重启服务后生效"
	}
	s.sendJSON(w, map[string]any{"ok": true, "message": message, "restart_needed": restartNeeded})
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		NodeID string `json:"node_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	s.mu.Lock()
	if s.session != nil {
		s.mu.Unlock()
		s.sendError(w, http.StatusConflict, "当前已有活动连接，请先断开")
		return
	}
	config := s.config
	nodeID := ""
	if payload.NodeID != "" {
		node, ok := s.findNodeLocked(payload.NodeID)
		if !ok {
			s.mu.Unlock()
			s.sendError(w, http.StatusNotFound, "节点不存在，请先刷新节点列表")
			return
		}
		path, err := s.writeNodeConfig(node)
		if err != nil {
			s.mu.Unlock()
			s.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		config.OpenVPNConfig = path
		nodeID = payload.NodeID
		for idx := range s.nodes {
			s.nodes[idx].Active = s.nodes[idx].ID == payload.NodeID
		}
	} else {
		if config.OpenVPNConfig == "" {
			s.mu.Unlock()
			s.sendError(w, http.StatusBadRequest, "请先设置 OpenVPN 配置文件路径或选择节点")
			return
		}
		if _, err := os.Stat(config.OpenVPNConfig); err != nil {
			s.mu.Unlock()
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("OpenVPN 配置不可读: %v", err))
			return
		}
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	session := &Session{
		startedAt: time.Now(),
		config:    config,
		cancel:    cancel,
		status:    "starting",
		message:   "正在启动用户态 OpenVPN 网关",
		nodeID:    nodeID,
	}
	s.session = session
	s.mu.Unlock()

	go s.runSession(sessionCtx, session)
	s.sendJSON(w, map[string]any{"ok": true, "message": "连接流程已启动"})
}

func (s *Server) startNodeSession(nodeID string) error {
	s.mu.Lock()
	if s.session != nil {
		s.mu.Unlock()
		return errors.New("当前已有活动连接")
	}
	node, ok := s.findNodeLocked(nodeID)
	if !ok {
		s.mu.Unlock()
		return errors.New("节点不存在")
	}
	config := s.config
	path, err := s.writeNodeConfig(node)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	config.OpenVPNConfig = path
	for idx := range s.nodes {
		s.nodes[idx].Active = s.nodes[idx].ID == nodeID
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	session := &Session{
		startedAt: time.Now(),
		config:    config,
		cancel:    cancel,
		status:    "starting",
		message:   "正在自动连接 VPNGate 节点 " + nodeID,
		nodeID:    nodeID,
	}
	s.session = session
	s.mu.Unlock()
	go s.runSession(sessionCtx, session)
	return nil
}

func (s *Server) refreshNodes(w http.ResponseWriter) {
	nodes, err := vpngate.FetchNodes(nil, vpngate.DefaultAPIURL)
	if err != nil {
		s.sendError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.mu.Lock()
	s.nodes = nodes
	s.failed = map[string]string{}
	s.mu.Unlock()
	s.sendJSON(w, map[string]any{"ok": true, "nodes": nodes})
}

func (s *Server) testNode(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		NodeID string `json:"node_id"`
		ID     string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	nodeID := payload.NodeID
	if nodeID == "" {
		nodeID = payload.ID
	}
	if nodeID == "" {
		s.sendError(w, http.StatusBadRequest, "节点 ID 不能为空")
		return
	}
	node, err := s.probeNode(nodeID)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.sendJSON(w, map[string]any{"ok": true, "node": node})
}

func (s *Server) testNodes(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		NodeIDs []string `json:"node_ids"`
		IDs     []string `json:"ids"`
		Limit   int      `json:"limit"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	nodeIDs := payload.NodeIDs
	if len(nodeIDs) == 0 {
		nodeIDs = payload.IDs
	}
	if len(nodeIDs) == 0 {
		s.mu.Lock()
		limit := payload.Limit
		if limit <= 0 || limit > len(s.nodes) {
			limit = len(s.nodes)
		}
		for idx := 0; idx < limit; idx++ {
			nodeIDs = append(nodeIDs, s.nodes[idx].ID)
		}
		s.mu.Unlock()
	}
	if len(nodeIDs) > maxBatchNodeTests {
		nodeIDs = nodeIDs[:maxBatchNodeTests]
	}
	results := make([]vpngate.Node, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		node, err := s.probeNode(nodeID)
		if err != nil {
			s.logger.Warn("节点测试失败", "node", nodeID, "error", err)
			continue
		}
		results = append(results, node)
	}
	s.sendJSON(w, map[string]any{"ok": true, "nodes": results})
}

func (s *Server) probeNode(nodeID string) (vpngate.Node, error) {
	s.mu.Lock()
	node, ok := s.findNodeLocked(nodeID)
	config := s.config
	s.mu.Unlock()
	if !ok {
		return vpngate.Node{}, errors.New("节点不存在")
	}
	path, err := s.writeNodeConfig(node)
	if err != nil {
		return vpngate.Node{}, err
	}
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(context.Background(), gatewayconfig.DefaultHandshakeTimeout)
	defer cancel()
	tunnel, err := vpn.Start(probeCtx, vpn.StartOptions{
		ConfigPath:       path,
		AuthFilePath:     config.OpenVPNAuth,
		HandshakeTimeout: gatewayconfig.DefaultHandshakeTimeout,
		Logger:           s.logger.With("probe_node", nodeID),
	})
	status := "available"
	message := "节点真实出口可用"
	var exitInfo *vpngate.IPInfo
	if err != nil {
		status = "unavailable"
		message = err.Error()
	} else {
		exitInfo, err = s.checkTunnelExit(probeCtx, tunnel, nodeID)
		if err != nil {
			status = "unavailable"
			message = err.Error()
		}
	}
	latency := int(time.Since(started).Milliseconds())

	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.nodes {
		if s.nodes[idx].ID == nodeID {
			s.nodes[idx].ProbeStatus = status
			s.nodes[idx].ProbeMessage = message
			s.nodes[idx].ProbeLatency = latency
			s.nodes[idx].ExitIPInfo = exitInfo
			if status == "available" {
				delete(s.failed, nodeID)
			} else {
				s.failed[nodeID] = message
			}
			return s.nodes[idx], nil
		}
	}
	return vpngate.Node{}, errors.New("节点不存在")
}

func (s *Server) disconnect(w http.ResponseWriter) {
	s.mu.Lock()
	session := s.session
	if session != nil {
		session.cancel()
		s.session = nil
	}
	for idx := range s.nodes {
		s.nodes[idx].Active = false
	}
	s.mu.Unlock()
	s.sendJSON(w, map[string]any{"ok": true})
}

func (s *Server) runSession(ctx context.Context, session *Session) {
	config := session.config
	tunnel, err := vpn.Start(ctx, vpn.StartOptions{
		ConfigPath:       config.OpenVPNConfig,
		AuthFilePath:     config.OpenVPNAuth,
		HandshakeTimeout: gatewayconfig.DefaultHandshakeTimeout,
		Logger:           s.logger,
	})
	if err != nil {
		s.finishSession(session, "error", fmt.Sprintf("启动用户态 OpenVPN 失败: %v", err))
		return
	}
	defer tunnel.Close()

	dialer, err := vpn.NewDialer(ctx, tunnel, s.logger)
	if err != nil {
		s.finishSession(session, "error", fmt.Sprintf("初始化用户态 TCP/IP 栈失败: %v", err))
		return
	}
	defer dialer.Close()

	servers := make([]*socks.Server, 0, len(config.SocksListeners))
	errCh := make(chan error, len(config.SocksListeners))
	for _, listener := range config.SocksListeners {
		if !listener.IsEnabled() {
			continue
		}
		server := socks.NewServer(
			listener.ListenAddress(),
			dialer,
			gatewayconfig.DefaultConnectTimeout,
			s.logger.With("listener", listener.Name),
			socks.AuthConfig{Username: listener.Username, Password: listener.Password},
		)
		servers = append(servers, server)
		go func() {
			errCh <- server.Serve(ctx)
		}()
	}
	if len(servers) == 0 {
		s.finishSession(session, "error", "没有启用任何 SOCKS5 监听端口")
		return
	}
	s.updateSessionSocksURLs(session, localProxyURLs(config.SocksListeners))
	defer func() {
		for _, server := range servers {
			_ = server.Close()
		}
	}()

	s.updateSession(session, "running", "用户态 OpenVPN 已连接，SOCKS5 网关已启动")
	for {
		select {
		case <-ctx.Done():
			s.finishSession(session, "stopped", "已断开")
			return
		case err := <-errCh:
			if err != nil && ctx.Err() == nil {
				s.finishSession(session, "error", fmt.Sprintf("SOCKS5 网关异常退出: %v", err))
				return
			}
		}
	}
}

func (s *Server) updateSession(session *Session, status string, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == session {
		session.status = status
		session.message = message
	}
}

func (s *Server) updateSessionSocksURLs(session *Session, socksURLs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == session {
		session.socksURLs = socksURLs
	}
}

func (s *Server) finishSession(session *Session, status string, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == session {
		session.status = status
		session.message = message
		s.session = nil
	}
	s.logger.Info("用户态会话结束", "status", status, "message", message)
	if status == "error" {
		if session.nodeID != "" {
			s.failed[session.nodeID] = message
			for idx := range s.nodes {
				if s.nodes[idx].ID == session.nodeID {
					s.nodes[idx].Active = false
				}
			}
		}
		go s.tryAutoConnect()
	}
}

func (s *Server) maintenanceLoop(ctx context.Context) {
	s.refreshNodesInBackground()
	s.tryAutoConnect()

	for {
		timer := time.NewTimer(s.refreshInterval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			s.refreshNodesInBackground()
			s.tryAutoConnect()
		}
	}
}

func (s *Server) refreshInterval() time.Duration {
	s.mu.Lock()
	seconds := s.config.RefreshSeconds
	s.mu.Unlock()
	if seconds <= 0 {
		seconds = 960
	}
	return time.Duration(seconds) * time.Second
}

func (s *Server) refreshNodesInBackground() {
	nodes, err := vpngate.FetchNodes(nil, vpngate.DefaultAPIURL)
	if err != nil {
		s.logger.Warn("刷新 VPNGate 节点失败", "error", err)
		return
	}
	s.mu.Lock()
	activeID := ""
	for _, node := range s.nodes {
		if node.Active {
			activeID = node.ID
			break
		}
	}
	for idx := range nodes {
		nodes[idx].Active = nodes[idx].ID == activeID
	}
	s.nodes = nodes
	s.mu.Unlock()
	s.logger.Info("VPNGate 节点已刷新", "count", len(nodes))
}

func (s *Server) tryAutoConnect() {
	s.mu.Lock()
	if !s.config.AutoConnect || s.session != nil || len(s.nodes) == 0 {
		s.mu.Unlock()
		return
	}
	config := s.config
	failed := make(map[string]string, len(s.failed))
	for key, value := range s.failed {
		failed[key] = value
	}
	nodeID := selectNodeID(config, s.nodes, failed)
	s.mu.Unlock()
	if nodeID == "" {
		s.logger.Warn("自动连接未找到符合路由策略的节点", "routing_mode", config.RoutingMode, "country", config.ForceCountry, "fixed_node", config.FixedNodeID)
		return
	}
	if err := s.startNodeSession(nodeID); err != nil {
		s.logger.Warn("自动连接节点失败", "node", nodeID, "error", err)
	}
}

func selectNodeID(config Config, nodes []vpngate.Node, failed map[string]string) string {
	switch config.RoutingMode {
	case "fixed_ip":
		for _, node := range nodes {
			if node.ID == config.FixedNodeID && !nodeFailed(node.ID, failed) {
				return node.ID
			}
		}
		return ""
	case "fixed_region":
		for _, node := range nodes {
			if strings.EqualFold(node.CountryShort, config.ForceCountry) && !nodeFailed(node.ID, failed) {
				return node.ID
			}
		}
		return ""
	default:
		for _, node := range nodes {
			if !nodeFailed(node.ID, failed) {
				return node.ID
			}
		}
		return ""
	}
}

func nodeFailed(nodeID string, failed map[string]string) bool {
	if len(failed) == 0 {
		return false
	}
	_, ok := failed[nodeID]
	return ok
}

func localProxyURLs(listeners []gatewayconfig.Listener) []string {
	var values []string
	for _, listener := range listeners {
		if !listener.IsEnabled() {
			continue
		}
		proxyURL := url.URL{
			Scheme: "socks5h",
			Host:   net.JoinHostPort(listener.Host, fmt.Sprintf("%d", listener.Port)),
		}
		if listener.HasAuth() {
			proxyURL.User = url.UserPassword(listener.Username, listener.Password)
		}
		values = append(values, proxyURL.String())
	}
	return values
}

func checkProxy(proxyURL string) ProxyTestResult {
	if proxyURL == "" {
		return ProxyTestResult{OK: false, Error: "SOCKS5 网关未启动"}
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return ProxyTestResult{OK: false, Error: "SOCKS5 代理地址无效: " + err.Error(), ProxyURL: proxyURL}
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(parsed),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	started := time.Now()
	info, err := fetchIPPureInfo(context.Background(), client, defaultIPPureInfoURL)
	if err != nil {
		return ProxyTestResult{OK: false, Error: err.Error(), ProxyURL: proxyURL}
	}
	return ProxyTestResult{OK: true, IP: info.IP, LatencyMS: int(time.Since(started).Milliseconds()), ProxyURL: proxyURL, Info: info}
}

func (s *Server) checkTunnelExit(ctx context.Context, tunnel *vpn.Tunnel, nodeID string) (*vpngate.IPInfo, error) {
	dialer, err := vpn.NewDialer(ctx, tunnel, s.logger.With("probe_node", nodeID))
	if err != nil {
		_ = tunnel.Close()
		return nil, fmt.Errorf("初始化用户态 TCP/IP 栈失败: %w", err)
	}
	defer dialer.Close()

	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := socks.NewServer("127.0.0.1:0", dialer, gatewayconfig.DefaultConnectTimeout, s.logger.With("probe_node", nodeID, "temporary_socks", true))
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(proxyCtx)
	}()
	proxyAddress, err := waitSocksAddress(ctx, server, errCh)
	if err != nil {
		_ = server.Close()
		return nil, err
	}
	defer func() {
		cancel()
		_ = server.Close()
	}()

	proxyURL := &url.URL{Scheme: "socks5h", Host: proxyAddress}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	return fetchIPPureInfo(ctx, client, defaultIPPureInfoURL)
}

func waitSocksAddress(ctx context.Context, server *socks.Server, errCh <-chan error) (string, error) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		address := server.Address()
		if address != "" {
			return address, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case err := <-errCh:
			if err == nil {
				return "", errors.New("临时 SOCKS5 服务异常退出")
			}
			return "", fmt.Errorf("临时 SOCKS5 服务启动失败: %w", err)
		case <-timer.C:
			return "", errors.New("等待临时 SOCKS5 服务启动超时")
		case <-ticker.C:
		}
	}
}

func fetchIPPureInfo(ctx context.Context, client *http.Client, infoURL string) (*vpngate.IPInfo, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if infoURL == "" {
		infoURL = defaultIPPureInfoURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AimiliVPN-Go/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ippure 出口画像 HTTP %d", resp.StatusCode)
	}
	var payload struct {
		IP             string `json:"ip"`
		ASN            int    `json:"asn"`
		ASOrganization string `json:"asOrganization"`
		Country        string `json:"country"`
		CountryCode    string `json:"countryCode"`
		Region         string `json:"region"`
		City           string `json:"city"`
		FraudScore     int    `json:"fraudScore"`
		IsResidential  bool   `json:"isResidential"`
		IsBroadcast    bool   `json:"isBroadcast"`
		IsMobile       bool   `json:"isMobile"`
		IsProxy        bool   `json:"isProxy"`
		IsVPN          bool   `json:"isVPN"`
		IsHosting      bool   `json:"isHosting"`
		IsDatacenter   bool   `json:"isDatacenter"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, exitInfoRequestLimit)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析 ippure 出口画像失败: %w", err)
	}
	if net.ParseIP(strings.TrimSpace(payload.IP)) == nil {
		return nil, fmt.Errorf("ippure 返回的出口 IP 无效: %q", payload.IP)
	}
	info := &vpngate.IPInfo{
		IP:             strings.TrimSpace(payload.IP),
		Country:        strings.TrimSpace(payload.Country),
		CountryCode:    strings.ToUpper(strings.TrimSpace(payload.CountryCode)),
		Region:         strings.TrimSpace(payload.Region),
		City:           strings.TrimSpace(payload.City),
		ASNNumber:      payload.ASN,
		ASN:            formatASN(payload.ASN),
		ASOrganization: strings.TrimSpace(payload.ASOrganization),
		Organization:   strings.TrimSpace(payload.ASOrganization),
		Mobile:         payload.IsMobile,
		Residential:    payload.IsResidential,
		Proxy:          payload.IsProxy || payload.IsVPN,
		Hosting:        payload.IsHosting || payload.IsDatacenter || (payload.IsBroadcast && !payload.IsResidential),
		FraudScore:     payload.FraudScore,
		FetchedAt:      time.Now().Format(time.RFC3339),
	}
	info.IPType = classifyIPType(info)
	return info, nil
}

func formatASN(asn int) string {
	if asn <= 0 {
		return ""
	}
	return fmt.Sprintf("AS%d", asn)
}

func classifyIPType(info *vpngate.IPInfo) string {
	if info == nil {
		return "unknown"
	}
	if info.Mobile {
		return "mobile"
	}
	if info.Proxy {
		return "proxy"
	}
	if info.Hosting {
		return "datacenter"
	}
	if info.Residential {
		return "broadband"
	}
	return "unknown"
}

func (s *Server) findNodeLocked(nodeID string) (vpngate.Node, bool) {
	for _, node := range s.nodes {
		if node.ID == nodeID {
			return node, true
		}
	}
	return vpngate.Node{}, false
}

func (s *Server) writeNodeConfig(node vpngate.Node) (string, error) {
	if node.ConfigText == "" {
		return "", errors.New("节点缺少 OpenVPN 配置")
	}
	dir := filepath.Join(filepath.Dir(s.configPath), "configs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, node.ID+".ovpn")
	if err := os.WriteFile(path, []byte(node.ConfigText), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func stringsHasPrefix(value string, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func constantTimeEqual(left string, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
