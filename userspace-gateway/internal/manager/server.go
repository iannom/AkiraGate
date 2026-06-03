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
	"sort"
	"strings"
	"sync"
	"time"

	gatewayconfig "akiragate/userspace-gateway/internal/config"
	"akiragate/userspace-gateway/internal/socks"
	"akiragate/userspace-gateway/internal/vpn"
	"akiragate/userspace-gateway/internal/vpngate"
)

const (
	sessionCookieName    = "akiragate_session"
	defaultIPPureInfoURL = "https://my.ippure.com/v1/info"
	maxBatchNodeTests    = 8
	maxBatchTestWorkers  = 8
	batchProbeTimeout    = gatewayconfig.DefaultHandshakeTimeout * 70 / 100
	batchProbeGraceTime  = 15 * time.Second
	exitInfoRequestLimit = 16 * 1024
	probeStatusTesting   = "testing"
	healthCheckInterval  = 60 * time.Second
)

type nodeTestJob struct {
	Index  int
	NodeID string
}

type nodeTestResult struct {
	Index  int
	NodeID string
	Node   vpngate.Node
	Err    error
}

type nodeProbeFunc func(context.Context, string) (vpngate.Node, error)

type listenerWorkerResult struct {
	Listener gatewayconfig.Listener
	Err      error
}

type listenerBackendPlan struct {
	ConfigPath   string
	NodeID       string
	CountryCode  string
	EntryIP      string
	EntryCIDRs   []string
	StaticConfig bool
}

type batchNodeTest struct {
	cancel context.CancelFunc
}

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
	batchTest    *batchNodeTest
}

type authSession struct {
	Username  string
	ExpiresAt time.Time
}

type Session struct {
	startedAt        time.Time
	config           Config
	cancel           context.CancelFunc
	status           string
	message          string
	socksURLs        []string
	nodeID           string
	listenerBackends map[string]ListenerBackendState
}

type GatewayComponent struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details"`
	Error   string `json:"error,omitempty"`
}

type ListenerBackendState struct {
	ListenerName  string   `json:"listener_name"`
	ListenAddress string   `json:"listen_address"`
	ProxyURL      string   `json:"proxy_url"`
	Status        string   `json:"status"`
	Message       string   `json:"message"`
	NodeID        string   `json:"node_id,omitempty"`
	CountryCode   string   `json:"country_code,omitempty"`
	EntryCIDRs    []string `json:"entry_cidrs,omitempty"`
	EntryIP       string   `json:"entry_ip,omitempty"`
	ExitIP        string   `json:"exit_ip,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type ProxyTestResult struct {
	OK        bool            `json:"ok"`
	Listener  string          `json:"listener,omitempty"`
	Listen    string          `json:"listen,omitempty"`
	IP        string          `json:"ip,omitempty"`
	LatencyMS int             `json:"latency_ms,omitempty"`
	Error     string          `json:"error,omitempty"`
	ProxyURL  string          `json:"proxy_url,omitempty"`
	Info      *vpngate.IPInfo `json:"info,omitempty"`
}

type ProxyTestResponse struct {
	OK        bool              `json:"ok"`
	IP        string            `json:"ip,omitempty"`
	LatencyMS int               `json:"latency_ms,omitempty"`
	Error     string            `json:"error,omitempty"`
	ProxyURL  string            `json:"proxy_url,omitempty"`
	Info      *vpngate.IPInfo   `json:"info,omitempty"`
	Results   []ProxyTestResult `json:"results,omitempty"`
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
	Connected        bool                     `json:"connected"`
	Status           string                   `json:"status"`
	Message          string                   `json:"message"`
	WebHost          string                   `json:"web_host"`
	WebPort          int                      `json:"web_port"`
	RuntimeWebHost   string                   `json:"runtime_web_host"`
	RuntimeWebPort   int                      `json:"runtime_web_port"`
	RestartNeeded    bool                     `json:"restart_needed"`
	SecretPath       string                   `json:"secret_path"`
	OpenVPNConfig    string                   `json:"openvpn_config"`
	OpenVPNAuth      string                   `json:"openvpn_auth"`
	SocksListeners   []gatewayconfig.Listener `json:"socks5_listeners"`
	LocalProxyURLs   []string                 `json:"local_proxy_urls"`
	ConnectedSince   string                   `json:"connected_since,omitempty"`
	AdminUsername    string                   `json:"admin_username"`
	AdminPassword    string                   `json:"admin_password"`
	Nodes            []vpngate.Node           `json:"nodes"`
	ActiveNodeID     string                   `json:"active_node_id,omitempty"`
	ActiveNodeIDs    []string                 `json:"active_node_ids,omitempty"`
	ListenerBackends []ListenerBackendState   `json:"listener_backends,omitempty"`
	FailedNodes      map[string]string        `json:"failed_nodes,omitempty"`
	AutoConnect      bool                     `json:"auto_connect"`
	RefreshSeconds   int                      `json:"refresh_seconds"`
	RoutingMode      string                   `json:"routing_mode"`
	ForceCountry     string                   `json:"force_country"`
	FixedNodeID      string                   `json:"fixed_node_id"`
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
	case r.Method == http.MethodPost && path == "/api/cancel_test_nodes":
		if !s.requireAuth(w, r) {
			return
		}
		s.cancelTestNodes(w)
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
	sessionStatus := ""
	sessionMessage := ""
	var backends []ListenerBackendState
	var socksURLs []string
	if session != nil {
		sessionStatus = session.status
		sessionMessage = session.message
		backends = listenerBackendStates(session.listenerBackends)
		socksURLs = append([]string(nil), session.socksURLs...)
	}
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
		vpnStatus = sessionStatus
		vpnDetails = sessionMessage
		if len(backends) > 0 {
			var details []string
			for _, backend := range backends {
				item := fmt.Sprintf("%s %s", backend.ListenAddress, backend.Status)
				if backend.NodeID != "" {
					item += " node=" + backend.NodeID
				}
				if backend.EntryIP != "" {
					item += " entry=" + backend.EntryIP
				}
				if backend.ExitIP != "" {
					item += " exit=" + backend.ExitIP
				}
				if backend.Error != "" {
					item += " error=" + backend.Error
				}
				details = append(details, item)
			}
			proxyStatus = aggregateBackendStatus(backends)
			proxyDetails = strings.Join(details, "\n")
		} else if len(socksURLs) > 0 {
			proxyStatus = "starting"
			proxyDetails = strings.Join(socksURLs, "\n")
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
	backends := []ListenerBackendState{}
	if session != nil {
		backends = listenerBackendStates(session.listenerBackends)
	}
	s.mu.Unlock()

	response := testListenerProxies(backends)
	status := http.StatusOK
	if !response.OK {
		status = http.StatusBadGateway
	}
	s.sendJSONWithStatus(w, status, response)
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
	if value := strings.TrimSpace(os.Getenv("AKIRAGATE_WEB_ROOT")); value != "" {
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
	listenerBackends := []ListenerBackendState{}
	if s.session != nil {
		status = s.session.status
		message = s.session.message
		connectedSince = s.session.startedAt.Format(time.RFC3339)
		listenerBackends = listenerBackendStates(s.session.listenerBackends)
	}
	nodes := make([]vpngate.Node, len(s.nodes))
	copy(nodes, s.nodes)
	failed := make(map[string]string, len(s.failed))
	for key, value := range s.failed {
		failed[key] = value
	}
	activeNodeID := ""
	activeNodeIDs := []string{}
	if s.session != nil {
		for _, node := range nodes {
			if node.Active {
				if activeNodeID == "" {
					activeNodeID = node.ID
				}
				activeNodeIDs = append(activeNodeIDs, node.ID)
			}
		}
	}
	return State{
		Connected:        connected,
		Status:           status,
		Message:          message,
		WebHost:          s.config.WebHost,
		WebPort:          s.config.WebPort,
		RuntimeWebHost:   s.listenHost,
		RuntimeWebPort:   s.listenPort,
		RestartNeeded:    s.webRestartNeededLocked(),
		SecretPath:       s.config.SecretPath,
		OpenVPNConfig:    s.config.OpenVPNConfig,
		OpenVPNAuth:      s.config.OpenVPNAuth,
		SocksListeners:   s.config.SocksListeners,
		LocalProxyURLs:   localProxyURLs(s.config.SocksListeners),
		ConnectedSince:   connectedSince,
		AdminUsername:    s.config.AdminUsername,
		AdminPassword:    "",
		Nodes:            nodes,
		ActiveNodeID:     activeNodeID,
		ActiveNodeIDs:    activeNodeIDs,
		ListenerBackends: listenerBackends,
		FailedNodes:      failed,
		AutoConnect:      s.config.AutoConnect,
		RefreshSeconds:   s.config.RefreshSeconds,
		RoutingMode:      s.config.RoutingMode,
		ForceCountry:     s.config.ForceCountry,
		FixedNodeID:      s.config.FixedNodeID,
	}
}

func (s *Server) webRestartNeededLocked() bool {
	if s.listenHost == "" || s.listenPort == 0 {
		return false
	}
	return s.config.WebHost != s.listenHost || s.config.WebPort != s.listenPort
}

func listenerBackendStates(backends map[string]ListenerBackendState) []ListenerBackendState {
	if len(backends) == 0 {
		return []ListenerBackendState{}
	}
	values := make([]ListenerBackendState, 0, len(backends))
	for _, backend := range backends {
		backend.EntryCIDRs = append([]string(nil), backend.EntryCIDRs...)
		values = append(values, backend)
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].ListenAddress < values[j].ListenAddress
	})
	return values
}

func aggregateBackendStatus(backends []ListenerBackendState) string {
	if len(backends) == 0 {
		return "starting"
	}
	running := 0
	errorsCount := 0
	switching := 0
	for _, backend := range backends {
		switch backend.Status {
		case "running":
			running++
		case "error":
			errorsCount++
		case "switching":
			switching++
		}
	}
	if running == len(backends) {
		return "running"
	}
	if errorsCount == len(backends) {
		return "error"
	}
	if switching > 0 || errorsCount > 0 {
		return "switching"
	}
	return "starting"
}

func aggregateBackendMessage(backends []ListenerBackendState) string {
	if len(backends) == 0 {
		return "正在为每个 SOCKS5 入口启动独立 OpenVPN 后端"
	}
	running := 0
	for _, backend := range backends {
		if backend.Status == "running" {
			running++
		}
	}
	switch aggregateBackendStatus(backends) {
	case "running":
		return "每个 SOCKS5 入口均已绑定独立 OpenVPN 后端"
	case "error":
		return "所有 SOCKS5 入口的 OpenVPN 后端均不可用"
	case "switching":
		return fmt.Sprintf("SOCKS5 入口后端正在切换，已运行 %d/%d", running, len(backends))
	default:
		return fmt.Sprintf("SOCKS5 入口后端正在启动，已运行 %d/%d", running, len(backends))
	}
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
		NodeID        string `json:"node_id"`
		ListenerName  string `json:"listener_name"`
		ListenAddress string `json:"listen_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
		s.sendError(w, http.StatusBadRequest, "请求 JSON 无效")
		return
	}
	payload.NodeID = strings.TrimSpace(payload.NodeID)
	payload.ListenerName = strings.TrimSpace(payload.ListenerName)
	payload.ListenAddress = strings.TrimSpace(payload.ListenAddress)

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
		if payload.ListenerName != "" || payload.ListenAddress != "" {
			if node.ConfigText == "" {
				s.mu.Unlock()
				s.sendError(w, http.StatusBadRequest, "节点缺少 OpenVPN 配置")
				return
			}
			nextConfig, listener, err := bindNodeToListener(config, payload.NodeID, payload.ListenerName, payload.ListenAddress)
			if err != nil {
				s.mu.Unlock()
				s.sendError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := SaveConfig(s.configPath, nextConfig); err != nil {
				s.mu.Unlock()
				s.sendError(w, http.StatusBadRequest, err.Error())
				return
			}
			config = nextConfig
			s.config = nextConfig
			delete(s.failed, payload.NodeID)
			nodeID = payload.NodeID
			s.logger.Info("已将节点绑定到 SOCKS5 入口", "node", payload.NodeID, "listener", listener.Name, "listen", listener.ListenAddress())
		} else {
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
		}
	} else {
		if config.OpenVPNConfig == "" {
			if !hasListenerBackendPolicy(config.SocksListeners) {
				s.mu.Unlock()
				s.sendError(w, http.StatusBadRequest, "请先设置 OpenVPN 配置文件路径、选择节点或配置 SOCKS5 入口绑定策略")
				return
			}
		} else if _, err := os.Stat(config.OpenVPNConfig); err != nil {
			s.mu.Unlock()
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("OpenVPN 配置不可读: %v", err))
			return
		}
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	session := &Session{
		startedAt:        time.Now(),
		config:           config,
		cancel:           cancel,
		status:           "starting",
		message:          "正在启动用户态 OpenVPN 网关",
		nodeID:           nodeID,
		listenerBackends: map[string]ListenerBackendState{},
	}
	s.session = session
	s.mu.Unlock()

	go s.runSession(sessionCtx, session)
	s.sendJSON(w, map[string]any{"ok": true, "message": "连接流程已启动"})
}

func (s *Server) refreshNodes(w http.ResponseWriter) {
	nodes, err := vpngate.FetchNodes(nil, vpngate.DefaultAPIURL)
	if err != nil {
		s.sendError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.mu.Lock()
	activeIDs := s.activeNodeIDsLocked()
	for idx := range nodes {
		_, active := activeIDs[nodes[idx].ID]
		nodes[idx].Active = active
	}
	s.nodes = nodes
	s.failed = map[string]string{}
	s.mu.Unlock()
	s.sendJSON(w, map[string]any{"ok": true, "nodes": nodes})
}

func bindNodeToListener(config Config, nodeID string, listenerName string, listenAddress string) (Config, gatewayconfig.Listener, error) {
	nodeID = strings.TrimSpace(nodeID)
	listenerName = strings.TrimSpace(listenerName)
	listenAddress = strings.TrimSpace(listenAddress)
	if nodeID == "" {
		return Config{}, gatewayconfig.Listener{}, errors.New("节点 ID 不能为空")
	}
	if listenerName == "" && listenAddress == "" {
		return Config{}, gatewayconfig.Listener{}, errors.New("必须指定 SOCKS5 入口")
	}

	selectedIndex := -1
	for idx, listener := range config.SocksListeners {
		if !listenerSelectorMatches(listener, listenerName, listenAddress) {
			continue
		}
		if selectedIndex >= 0 {
			return Config{}, gatewayconfig.Listener{}, errors.New("SOCKS5 入口选择不唯一")
		}
		selectedIndex = idx
	}
	if selectedIndex < 0 {
		return Config{}, gatewayconfig.Listener{}, errors.New("SOCKS5 入口不存在")
	}

	listener := config.SocksListeners[selectedIndex]
	if !listener.IsEnabled() {
		return Config{}, gatewayconfig.Listener{}, fmt.Errorf("SOCKS5 入口未启用: %s", listener.ListenAddress())
	}
	enabled := true
	listener.BackendPolicyEnabled = &enabled
	listener.FixedNodeID = nodeID

	next := config
	next.SocksListeners = append([]gatewayconfig.Listener(nil), config.SocksListeners...)
	next.SocksListeners[selectedIndex] = listener
	normalizeConfig(&next)
	return next, next.SocksListeners[selectedIndex], nil
}

func listenerSelectorMatches(listener gatewayconfig.Listener, listenerName string, listenAddress string) bool {
	nameMatches := listenerName != "" && strings.TrimSpace(listener.Name) == listenerName
	addressMatches := listenAddress != "" && listener.ListenAddress() == listenAddress
	if listenerName != "" && listenAddress != "" {
		return nameMatches && addressMatches
	}
	return nameMatches || addressMatches
}

func (s *Server) testNode(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		NodeID string `json:"node_id"`
		ID     string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
		s.sendError(w, http.StatusBadRequest, "请求 JSON 无效")
		return
	}
	nodeID := payload.NodeID
	if nodeID == "" {
		nodeID = payload.ID
	}
	if nodeID == "" {
		s.sendError(w, http.StatusBadRequest, "节点 ID 不能为空")
		return
	}
	s.mu.Lock()
	_, ok := s.findNodeLocked(nodeID)
	s.mu.Unlock()
	if !ok {
		s.sendError(w, http.StatusNotFound, "节点不存在，请先刷新节点列表")
		return
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), gatewayconfig.DefaultHandshakeTimeout+batchProbeGraceTime)
	defer cancel()
	resultCh := make(chan nodeTestResult, 1)
	go func() {
		resultCh <- s.probeNodeTestJob(probeCtx, nodeTestJob{NodeID: nodeID}, s.probeNode)
	}()

	select {
	case result := <-resultCh:
		node, _ := s.normalizeNodeTestResult(result)
		if result.Err != nil && node.ID == "" {
			s.sendError(w, http.StatusInternalServerError, result.Err.Error())
			return
		}
		s.sendJSON(w, map[string]any{"ok": true, "node": node})
	case <-probeCtx.Done():
		node := s.markInterruptedNodeProbe(nodeID, probeCtx.Err())
		s.sendJSON(w, map[string]any{"ok": true, "timeout": true, "node": node})
	}
}

func (s *Server) testNodes(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		NodeIDs []string `json:"node_ids"`
		IDs     []string `json:"ids"`
		Limit   int      `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
		s.sendError(w, http.StatusBadRequest, "请求 JSON 无效")
		return
	}
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

	testCtx, batch, ok := s.startBatchNodeTest()
	if !ok {
		s.sendError(w, http.StatusConflict, "已有批量测试正在运行")
		return
	}
	defer s.finishBatchNodeTest(batch)

	s.markBatchNodesProbeTesting(nodeIDs)
	results, cancelled := s.probeNodesConcurrently(testCtx, nodeIDs)
	s.sendJSON(w, map[string]any{"ok": true, "cancelled": cancelled, "nodes": results})
}

func (s *Server) cancelTestNodes(w http.ResponseWriter) {
	if s.cancelBatchNodeTest() {
		s.sendJSON(w, map[string]any{"ok": true, "cancelled": true, "message": "已请求取消批量测试"})
		return
	}
	s.sendJSON(w, map[string]any{"ok": true, "cancelled": false, "message": "当前没有正在运行的批量测试"})
}

func (s *Server) startBatchNodeTest() (context.Context, *batchNodeTest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batchTest != nil {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	batch := &batchNodeTest{cancel: cancel}
	s.batchTest = batch
	return ctx, batch, true
}

func (s *Server) finishBatchNodeTest(batch *batchNodeTest) {
	batch.cancel()
	s.mu.Lock()
	if s.batchTest == batch {
		s.batchTest = nil
	}
	s.mu.Unlock()
}

func (s *Server) cancelBatchNodeTest() bool {
	s.mu.Lock()
	batch := s.batchTest
	s.mu.Unlock()
	if batch == nil {
		return false
	}
	batch.cancel()
	return true
}

func (s *Server) probeNodesConcurrently(ctx context.Context, nodeIDs []string) ([]vpngate.Node, bool) {
	if len(nodeIDs) == 0 {
		return []vpngate.Node{}, false
	}
	workerCount := batchProbeWorkerCount(len(nodeIDs))
	watchdogCtx, cancel := context.WithTimeout(ctx, batchProbeWatchdogTimeout(len(nodeIDs), workerCount))
	defer cancel()
	return s.probeNodesConcurrentlyWith(watchdogCtx, nodeIDs, workerCount, s.probeBatchNode)
}

func batchProbeWorkerCount(nodeCount int) int {
	if nodeCount <= 0 {
		return 0
	}
	workerCount := maxBatchTestWorkers
	if workerCount > nodeCount {
		workerCount = nodeCount
	}
	return workerCount
}

func batchProbeWatchdogTimeout(nodeCount int, workerCount int) time.Duration {
	if nodeCount <= 0 || workerCount <= 0 {
		return batchProbeTimeout + batchProbeGraceTime
	}
	batches := (nodeCount + workerCount - 1) / workerCount
	return time.Duration(batches) * (batchProbeTimeout + batchProbeGraceTime)
}

func (s *Server) probeNodesConcurrentlyWith(ctx context.Context, nodeIDs []string, workerCount int, probe nodeProbeFunc) ([]vpngate.Node, bool) {
	if len(nodeIDs) == 0 {
		return []vpngate.Node{}, false
	}
	if probe == nil {
		probe = s.probeBatchNode
	}
	if workerCount <= 0 || workerCount > len(nodeIDs) {
		workerCount = batchProbeWorkerCount(len(nodeIDs))
	}
	jobs := make(chan nodeTestJob)
	resultCh := make(chan nodeTestResult, len(nodeIDs))
	queuedCh := make(chan int, 1)

	for worker := 0; worker < workerCount; worker++ {
		go func() {
			for job := range jobs {
				resultCh <- s.probeNodeTestJob(ctx, job, probe)
			}
		}()
	}

	go func() {
		queued := 0
		defer func() {
			close(jobs)
			queuedCh <- queued
		}()
		for idx, nodeID := range nodeIDs {
			select {
			case <-ctx.Done():
				return
			case jobs <- nodeTestJob{Index: idx, NodeID: nodeID}:
				queued++
			}
		}
	}()

	results := make([]vpngate.Node, len(nodeIDs))
	completedNodes := make([]bool, len(nodeIDs))
	expected := len(nodeIDs)
	completed := 0
	cancelled := false
	for completed < expected {
		select {
		case queued := <-queuedCh:
			expected = queued
		case <-ctx.Done():
			cancelled = true
			completed += s.drainReadyNodeTestResults(resultCh, results, completedNodes)
			for idx, nodeID := range nodeIDs {
				if !completedNodes[idx] {
					results[idx] = s.markInterruptedNodeProbe(nodeID, ctx.Err())
				}
			}
			return compactNodeTestResults(results), true
		case result := <-resultCh:
			completed++
			node, interrupted := s.normalizeNodeTestResult(result)
			if interrupted {
				cancelled = true
			}
			if result.Index >= 0 && result.Index < len(results) {
				results[result.Index] = node
				completedNodes[result.Index] = true
			}
		}
	}
	if ctx.Err() != nil || cancelled {
		for idx, nodeID := range nodeIDs {
			if !completedNodes[idx] {
				results[idx] = s.markInterruptedNodeProbe(nodeID, ctx.Err())
			}
		}
		return compactNodeTestResults(results), true
	}
	return compactNodeTestResults(results), false
}

func (s *Server) probeNodeTestJob(ctx context.Context, job nodeTestJob, probe nodeProbeFunc) (result nodeTestResult) {
	result = nodeTestResult{Index: job.Index, NodeID: job.NodeID}
	defer func() {
		if recovered := recover(); recovered != nil {
			message := fmt.Sprintf("节点测试异常: %v", recovered)
			s.logger.Error("节点测试发生 panic", "node", job.NodeID, "panic", recovered)
			result.Node = s.markNodeProbeFailed(job.NodeID, message)
			result.Err = errors.New(message)
		}
	}()
	result.Node, result.Err = probe(ctx, job.NodeID)
	return result
}

func (s *Server) drainReadyNodeTestResults(resultCh <-chan nodeTestResult, results []vpngate.Node, completedNodes []bool) int {
	completed := 0
	for {
		select {
		case result := <-resultCh:
			node, _ := s.normalizeNodeTestResult(result)
			if result.Index >= 0 && result.Index < len(results) {
				results[result.Index] = node
				completedNodes[result.Index] = true
				completed++
			}
		default:
			return completed
		}
	}
}

func (s *Server) normalizeNodeTestResult(result nodeTestResult) (vpngate.Node, bool) {
	if result.Err != nil {
		if isContextDoneError(result.Err) {
			return s.markInterruptedNodeProbe(result.NodeID, result.Err), true
		}
		s.logger.Warn("节点测试失败", "node", result.NodeID, "error", result.Err)
		return s.markNodeProbeFailed(result.NodeID, result.Err.Error()), false
	}
	if result.Node.ID == "" {
		return s.markNodeProbeFailed(result.NodeID, "节点测试未返回结果"), false
	}
	return result.Node, false
}

func isContextDoneError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (s *Server) markInterruptedNodeProbe(nodeID string, err error) vpngate.Node {
	if errors.Is(err, context.DeadlineExceeded) {
		return s.markNodeProbeFailed(nodeID, "节点测试超时")
	}
	return s.markNodeProbeCancelled(nodeID)
}

func compactNodeTestResults(results []vpngate.Node) []vpngate.Node {
	compacted := make([]vpngate.Node, 0, len(results))
	for _, node := range results {
		if node.ID != "" {
			compacted = append(compacted, node)
		}
	}
	return compacted
}

func (s *Server) probeNode(ctx context.Context, nodeID string) (vpngate.Node, error) {
	return s.probeNodeWithTimeout(ctx, nodeID, gatewayconfig.DefaultHandshakeTimeout)
}

func (s *Server) probeBatchNode(ctx context.Context, nodeID string) (vpngate.Node, error) {
	return s.probeNodeWithTimeout(ctx, nodeID, batchProbeTimeout)
}

func (s *Server) probeNodeWithTimeout(ctx context.Context, nodeID string, handshakeTimeout time.Duration) (vpngate.Node, error) {
	if handshakeTimeout <= 0 {
		handshakeTimeout = gatewayconfig.DefaultHandshakeTimeout
	}
	if err := ctx.Err(); err != nil {
		return vpngate.Node{}, err
	}
	node, config, ok := s.markNodeProbeTesting(nodeID)
	if !ok {
		return vpngate.Node{}, errors.New("节点不存在")
	}
	if err := ctx.Err(); err != nil {
		return s.markInterruptedNodeProbe(nodeID, err), err
	}
	path, err := s.writeNodeConfig(node)
	if err != nil {
		s.markNodeProbeFailed(nodeID, err.Error())
		return vpngate.Node{}, err
	}
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	tunnel, err := vpn.Start(probeCtx, vpn.StartOptions{
		ConfigPath:       path,
		AuthFilePath:     config.OpenVPNAuth,
		HandshakeTimeout: handshakeTimeout,
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
	if ctx.Err() != nil {
		return s.markInterruptedNodeProbe(nodeID, ctx.Err()), ctx.Err()
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

func (s *Server) markNodeProbeTesting(nodeID string) (vpngate.Node, Config, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.nodes {
		if s.nodes[idx].ID == nodeID {
			s.nodes[idx].ProbeStatus = probeStatusTesting
			s.nodes[idx].ProbeMessage = "正在测试节点真实出口"
			s.nodes[idx].ProbeLatency = 0
			s.nodes[idx].ExitIPInfo = nil
			delete(s.failed, nodeID)
			return s.nodes[idx], s.config, true
		}
	}
	return vpngate.Node{}, s.config, false
}

func (s *Server) markBatchNodesProbeTesting(nodeIDs []string) {
	if len(nodeIDs) == 0 {
		return
	}
	selected := make(map[string]struct{}, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if nodeID != "" {
			selected[nodeID] = struct{}{}
		}
	}
	if len(selected) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.nodes {
		if _, ok := selected[s.nodes[idx].ID]; ok {
			s.nodes[idx].ProbeStatus = probeStatusTesting
			s.nodes[idx].ProbeMessage = "正在测试节点真实出口"
			s.nodes[idx].ProbeLatency = 0
			s.nodes[idx].ExitIPInfo = nil
			delete(s.failed, s.nodes[idx].ID)
		}
	}
}

func (s *Server) markNodeProbeCancelled(nodeID string) vpngate.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.nodes {
		if s.nodes[idx].ID == nodeID {
			s.nodes[idx].ProbeStatus = "cancelled"
			s.nodes[idx].ProbeMessage = "批量测试已取消"
			s.nodes[idx].ProbeLatency = 0
			s.nodes[idx].ExitIPInfo = nil
			delete(s.failed, nodeID)
			return s.nodes[idx]
		}
	}
	return vpngate.Node{
		ID:           nodeID,
		ProbeStatus:  "cancelled",
		ProbeMessage: "批量测试已取消",
	}
}

func (s *Server) markNodeProbeFailed(nodeID string, message string) vpngate.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.nodes {
		if s.nodes[idx].ID == nodeID {
			s.nodes[idx].ProbeStatus = "unavailable"
			s.nodes[idx].ProbeMessage = message
			s.nodes[idx].ProbeLatency = 0
			s.nodes[idx].ExitIPInfo = nil
			s.failed[nodeID] = message
			return s.nodes[idx]
		}
	}
	s.failed[nodeID] = message
	return vpngate.Node{
		ID:           nodeID,
		ProbeStatus:  "unavailable",
		ProbeMessage: message,
	}
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
	listeners := make([]gatewayconfig.Listener, 0, len(config.SocksListeners))
	for _, listener := range config.SocksListeners {
		if !listener.IsEnabled() {
			continue
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		s.finishSession(session, "error", "没有启用任何 SOCKS5 监听端口")
		return
	}

	s.updateSessionSocksURLs(session, localProxyURLs(listeners))
	s.updateSession(session, "starting", "正在为每个 SOCKS5 入口启动独立 OpenVPN 后端")

	resultCh := make(chan listenerWorkerResult, len(listeners))
	for _, listener := range listeners {
		listener := listener
		s.updateListenerBackendState(session, listener, ListenerBackendState{
			Status:  "starting",
			Message: "等待选择 OpenVPN 后端",
		})
		go s.runListenerWorker(ctx, session, listener, resultCh)
	}

	s.consumeListenerResults(ctx, session, resultCh)
}

func (s *Server) consumeListenerResults(ctx context.Context, session *Session, resultCh <-chan listenerWorkerResult) {
	for {
		select {
		case <-ctx.Done():
			s.finishSession(session, "stopped", "已断开")
			return
		case result := <-resultCh:
			if result.Err != nil && ctx.Err() == nil {
				session.cancel()
				s.finishSession(session, "error", fmt.Sprintf("SOCKS5 入口 %s 异常退出: %v", result.Listener.Name, result.Err))
				return
			}
		}
	}
}

func (s *Server) runListenerWorker(ctx context.Context, session *Session, listener gatewayconfig.Listener, resultCh chan<- listenerWorkerResult) {
	forceVPNGate := listenerHasBackendPolicy(listener) || session.config.OpenVPNConfig == ""
	retry := 0
	for {
		if ctx.Err() != nil {
			resultCh <- listenerWorkerResult{Listener: listener, Err: nil}
			return
		}

		s.updateListenerBackendState(session, listener, ListenerBackendState{
			Status:  "switching",
			Message: "正在选择并测试 OpenVPN 后端",
		})
		plan, err := s.resolveListenerBackend(ctx, session.config, listener, forceVPNGate)
		if err != nil {
			s.updateListenerBackendState(session, listener, ListenerBackendState{
				Status:  "error",
				Message: "OpenVPN 后端选择失败",
				Error:   err.Error(),
			})
			if !sleepWithContext(ctx, failoverBackoff(retry)) {
				resultCh <- listenerWorkerResult{Listener: listener, Err: nil}
				return
			}
			retry++
			continue
		}

		err = s.serveListenerBackend(ctx, session, listener, plan)
		if err == nil || ctx.Err() != nil {
			resultCh <- listenerWorkerResult{Listener: listener, Err: nil}
			return
		}
		if isSocksListenFailure(err) {
			resultCh <- listenerWorkerResult{Listener: listener, Err: err}
			return
		}
		if plan.NodeID != "" {
			s.markNodeProbeFailed(plan.NodeID, err.Error())
		}
		s.updateListenerBackendState(session, listener, ListenerBackendState{
			Status:      "switching",
			Message:     "当前 OpenVPN 后端不可用，正在刷新 VPNGate 节点并切换",
			NodeID:      plan.NodeID,
			CountryCode: plan.CountryCode,
			EntryCIDRs:  plan.EntryCIDRs,
			EntryIP:     plan.EntryIP,
			Error:       err.Error(),
		})
		s.refreshNodesInBackground()
		forceVPNGate = true
		if !sleepWithContext(ctx, failoverBackoff(retry)) {
			resultCh <- listenerWorkerResult{Listener: listener, Err: nil}
			return
		}
		retry++
	}
}

func (s *Server) resolveListenerBackend(ctx context.Context, config Config, listener gatewayconfig.Listener, forceVPNGate bool) (listenerBackendPlan, error) {
	if !forceVPNGate && !listenerHasBackendPolicy(listener) && config.OpenVPNConfig != "" {
		if _, err := os.Stat(config.OpenVPNConfig); err != nil {
			return listenerBackendPlan{}, fmt.Errorf("OpenVPN 配置不可读: %w", err)
		}
		return listenerBackendPlan{
			ConfigPath:   config.OpenVPNConfig,
			StaticConfig: true,
		}, nil
	}

	plan, err := s.selectAndProbeListenerNode(ctx, config, listener)
	if err == nil {
		return plan, nil
	}
	if forceVPNGate || listenerHasBackendPolicy(listener) || config.OpenVPNConfig == "" {
		return listenerBackendPlan{}, err
	}
	if _, statErr := os.Stat(config.OpenVPNConfig); statErr != nil {
		return listenerBackendPlan{}, fmt.Errorf("%v；OpenVPN 配置也不可读: %w", err, statErr)
	}
	return listenerBackendPlan{
		ConfigPath:   config.OpenVPNConfig,
		StaticConfig: true,
	}, nil
}

func (s *Server) selectAndProbeListenerNode(ctx context.Context, config Config, listener gatewayconfig.Listener) (listenerBackendPlan, error) {
	candidateIDs, err := s.listenerNodeCandidates(config, listener, maxBatchNodeTests)
	if err != nil {
		return listenerBackendPlan{}, err
	}
	if len(candidateIDs) == 0 {
		s.refreshNodesInBackground()
		candidateIDs, err = s.listenerNodeCandidates(config, listener, maxBatchNodeTests)
		if err != nil {
			return listenerBackendPlan{}, err
		}
	}
	if len(candidateIDs) == 0 {
		return listenerBackendPlan{}, errors.New("没有匹配 SOCKS5 绑定策略的可用 VPNGate 节点")
	}

	var lastError string
	for _, nodeID := range candidateIDs {
		node, err := s.probeNode(ctx, nodeID)
		if err != nil {
			lastError = err.Error()
			continue
		}
		if node.ProbeStatus != "available" {
			lastError = node.ProbeMessage
			continue
		}
		path, err := s.writeNodeConfig(node)
		if err != nil {
			lastError = err.Error()
			s.markNodeProbeFailed(nodeID, err.Error())
			continue
		}
		return listenerBackendPlan{
			ConfigPath:  path,
			NodeID:      node.ID,
			CountryCode: strings.ToUpper(strings.TrimSpace(node.CountryShort)),
			EntryIP:     listenerNodeEntryIP(node),
			EntryCIDRs:  append([]string(nil), listener.EntryCIDRs...),
		}, nil
	}
	if lastError == "" {
		lastError = "候选节点测试未通过"
	}
	return listenerBackendPlan{}, fmt.Errorf("没有通过可用性测试的 VPNGate 节点: %s", lastError)
}

func (s *Server) serveListenerBackend(ctx context.Context, session *Session, listener gatewayconfig.Listener, plan listenerBackendPlan) error {
	logger := s.logger.With("listener", listener.Name, "listen", listener.ListenAddress())
	if plan.NodeID != "" {
		logger = logger.With("node", plan.NodeID)
	}
	backendCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tunnel, err := vpn.Start(backendCtx, vpn.StartOptions{
		ConfigPath:       plan.ConfigPath,
		AuthFilePath:     session.config.OpenVPNAuth,
		HandshakeTimeout: gatewayconfig.DefaultHandshakeTimeout,
		Logger:           logger,
	})
	if err != nil {
		return fmt.Errorf("启动用户态 OpenVPN 失败: %w", err)
	}

	dialer, err := vpn.NewDialer(backendCtx, tunnel, logger)
	if err != nil {
		_ = tunnel.Close()
		return fmt.Errorf("初始化用户态 TCP/IP 栈失败: %w", err)
	}
	// Dialer.Close 会关闭底层 tunnel，避免重复关闭。
	defer dialer.Close()

	server := socks.NewServer(
		listener.ListenAddress(),
		dialer,
		gatewayconfig.DefaultConnectTimeout,
		logger,
		socks.AuthConfig{Username: listener.Username, Password: listener.Password},
	)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(backendCtx)
	}()
	proxyAddress, err := waitSocksAddress(backendCtx, server, errCh)
	if err != nil {
		_ = server.Close()
		return err
	}
	defer func() {
		cancel()
		_ = server.Close()
	}()

	proxyURL := proxyURLForListener(listener, proxyAddress)
	if result := checkProxy(proxyURL); !result.OK {
		return fmt.Errorf("OpenVPN 后端首次健康检查失败: %s", result.Error)
	}
	s.updateListenerBackendState(session, listener, ListenerBackendState{
		Status:      "running",
		Message:     "SOCKS5 入口已绑定独立 OpenVPN 后端",
		NodeID:      plan.NodeID,
		CountryCode: plan.CountryCode,
		EntryCIDRs:  plan.EntryCIDRs,
		EntryIP:     plan.EntryIP,
		ProxyURL:    proxyURL,
	})

	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err != nil && backendCtx.Err() == nil {
				return fmt.Errorf("SOCKS5 网关异常退出: %w", err)
			}
			return nil
		case <-ticker.C:
			result := checkProxy(proxyURL)
			if !result.OK {
				return fmt.Errorf("OpenVPN 后端健康检查失败: %s", result.Error)
			}
			s.updateListenerBackendState(session, listener, ListenerBackendState{
				Status:      "running",
				Message:     "SOCKS5 入口已绑定独立 OpenVPN 后端",
				NodeID:      plan.NodeID,
				CountryCode: plan.CountryCode,
				EntryCIDRs:  plan.EntryCIDRs,
				EntryIP:     plan.EntryIP,
				ExitIP:      result.IP,
				ProxyURL:    proxyURL,
			})
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

func (s *Server) updateListenerBackendState(session *Session, listener gatewayconfig.Listener, update ListenerBackendState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session != session {
		return
	}
	key := listenerBackendKey(listener)
	if session.listenerBackends == nil {
		session.listenerBackends = map[string]ListenerBackendState{}
	}
	previous := session.listenerBackends[key]
	state := previous
	state.ListenerName = listener.Name
	state.ListenAddress = listener.ListenAddress()
	if state.ProxyURL == "" {
		state.ProxyURL = listenerProxyURL(listener, listener.ListenAddress())
	}
	if update.ProxyURL != "" {
		state.ProxyURL = update.ProxyURL
	}
	if update.Status != "" {
		state.Status = update.Status
	}
	if update.Message != "" {
		state.Message = update.Message
	}
	state.NodeID = update.NodeID
	state.CountryCode = update.CountryCode
	state.EntryCIDRs = append([]string(nil), update.EntryCIDRs...)
	state.EntryIP = update.EntryIP
	state.ExitIP = update.ExitIP
	state.Error = update.Error
	session.listenerBackends[key] = state
	s.recomputeActiveNodesLocked(session)
	backends := listenerBackendStates(session.listenerBackends)
	session.status = aggregateBackendStatus(backends)
	session.message = aggregateBackendMessage(backends)
}

func (s *Server) recomputeActiveNodesLocked(session *Session) {
	active := map[string]struct{}{}
	if session != nil {
		for _, backend := range session.listenerBackends {
			if backend.Status == "running" && backend.NodeID != "" {
				active[backend.NodeID] = struct{}{}
			}
		}
	}
	for idx := range s.nodes {
		_, ok := active[s.nodes[idx].ID]
		s.nodes[idx].Active = ok
	}
}

func (s *Server) activeNodeIDsLocked() map[string]struct{} {
	active := map[string]struct{}{}
	if s.session != nil {
		for _, backend := range s.session.listenerBackends {
			if backend.Status == "running" && backend.NodeID != "" {
				active[backend.NodeID] = struct{}{}
			}
		}
	}
	for _, node := range s.nodes {
		if node.Active {
			active[node.ID] = struct{}{}
		}
	}
	return active
}

func (s *Server) finishSession(session *Session, status string, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == session {
		session.status = status
		session.message = message
		s.session = nil
	}
	s.recomputeActiveNodesLocked(nil)
	s.logger.Info("用户态会话结束", "status", status, "message", message)
	if status == "error" {
		if session.nodeID != "" {
			s.failed[session.nodeID] = message
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
	activeIDs := s.activeNodeIDsLocked()
	for idx := range nodes {
		_, active := activeIDs[nodes[idx].ID]
		nodes[idx].Active = active
	}
	s.nodes = nodes
	s.mu.Unlock()
	s.logger.Info("VPNGate 节点已刷新", "count", len(nodes))
}

func (s *Server) tryAutoConnect() {
	s.mu.Lock()
	if !s.config.AutoConnect || s.session != nil {
		s.mu.Unlock()
		return
	}
	config := s.config
	nodesCount := len(s.nodes)
	s.mu.Unlock()

	if config.OpenVPNConfig == "" {
		if nodesCount == 0 || !hasListenerBackendPolicy(config.SocksListeners) {
			s.logger.Warn("自动连接已跳过，未配置 OpenVPN 配置文件或 SOCKS5 入口绑定策略")
			return
		}
	} else if _, err := os.Stat(config.OpenVPNConfig); err != nil {
		s.logger.Warn("自动连接已跳过，OpenVPN 配置不可读", "path", config.OpenVPNConfig, "error", err)
		return
	}

	if err := s.startConfiguredSession(config); err != nil {
		s.logger.Warn("自动连接 OpenVPN 配置失败", "path", config.OpenVPNConfig, "error", err)
	}
}

func (s *Server) startConfiguredSession(config Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session != nil {
		return errors.New("当前已有活动连接")
	}
	for idx := range s.nodes {
		s.nodes[idx].Active = false
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	session := &Session{
		startedAt:        time.Now(),
		config:           config,
		cancel:           cancel,
		status:           "starting",
		message:          "正在自动连接 OpenVPN 配置",
		listenerBackends: map[string]ListenerBackendState{},
	}
	s.session = session
	go s.runSession(sessionCtx, session)
	return nil
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

func (s *Server) listenerNodeCandidates(config Config, listener gatewayconfig.Listener, limit int) ([]string, error) {
	s.mu.Lock()
	nodes := make([]vpngate.Node, len(s.nodes))
	copy(nodes, s.nodes)
	failed := make(map[string]string, len(s.failed))
	for key, value := range s.failed {
		failed[key] = value
	}
	s.mu.Unlock()
	return selectListenerNodeIDs(config, listener, nodes, failed, limit)
}

func selectListenerNodeIDs(config Config, listener gatewayconfig.Listener, nodes []vpngate.Node, failed map[string]string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = len(nodes)
	}
	fixedNodeID := ""
	if listener.BackendPolicyIsEnabled() {
		fixedNodeID = strings.TrimSpace(listener.FixedNodeID)
	}
	if fixedNodeID == "" && config.RoutingMode == "fixed_ip" {
		fixedNodeID = strings.TrimSpace(config.FixedNodeID)
	}
	if fixedNodeID != "" {
		for _, node := range nodes {
			if node.ID == fixedNodeID && !nodeFailed(node.ID, failed) {
				return []string{node.ID}, nil
			}
		}
		return []string{}, nil
	}
	countryCode := ""
	if listener.BackendPolicyIsEnabled() {
		countryCode = strings.ToUpper(strings.TrimSpace(listener.CountryCode))
	}
	if countryCode == "" && config.RoutingMode == "fixed_region" {
		countryCode = strings.ToUpper(strings.TrimSpace(config.ForceCountry))
	}
	var entryCIDRs []string
	if listener.BackendPolicyIsEnabled() {
		entryCIDRs = listener.EntryCIDRs
	}
	cidrs, err := parseCIDRs(entryCIDRs)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, node := range nodes {
		if node.ID == "" || nodeFailed(node.ID, failed) {
			continue
		}
		if countryCode != "" && !strings.EqualFold(node.CountryShort, countryCode) {
			continue
		}
		if len(cidrs) > 0 && !nodeEntryMatchesCIDRs(node, cidrs) {
			continue
		}
		ids = append(ids, node.ID)
		if len(ids) >= limit {
			break
		}
	}
	return ids, nil
}

func nodeFailed(nodeID string, failed map[string]string) bool {
	if len(failed) == 0 {
		return false
	}
	_, ok := failed[nodeID]
	return ok
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	if len(values) == 0 {
		return nil, nil
	}
	cidrs := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		cidr := strings.TrimSpace(value)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("入口网段 CIDR 无效: %s", cidr)
		}
		cidrs = append(cidrs, network)
	}
	return cidrs, nil
}

func nodeEntryMatchesCIDRs(node vpngate.Node, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(listenerNodeEntryIP(node))
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func listenerNodeEntryIP(node vpngate.Node) string {
	for _, value := range []string{node.RemoteHost, node.IP} {
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func listenerHasBackendPolicy(listener gatewayconfig.Listener) bool {
	return listener.BackendPolicyIsEnabled() && listener.HasBackendPolicyValues()
}

func failoverBackoff(retry int) time.Duration {
	if retry < 0 {
		retry = 0
	}
	if retry > 5 {
		retry = 5
	}
	return time.Duration(1<<retry) * time.Second
}

func sleepWithContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func isSocksListenFailure(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "监听 SOCKS5 地址失败") ||
		strings.Contains(text, "address already in use") ||
		strings.Contains(text, "permission denied")
}

func listenerBackendKey(listener gatewayconfig.Listener) string {
	return listener.ListenAddress()
}

func localProxyURLs(listeners []gatewayconfig.Listener) []string {
	var values []string
	for _, listener := range listeners {
		if !listener.IsEnabled() {
			continue
		}
		values = append(values, listenerProxyURL(listener, listener.ListenAddress()))
	}
	return values
}

func proxyURLForListener(listener gatewayconfig.Listener, proxyAddress string) string {
	if proxyAddress == "" {
		proxyAddress = listener.ListenAddress()
	}
	if host, port, err := net.SplitHostPort(proxyAddress); err == nil {
		ip := net.ParseIP(host)
		if ip != nil && ip.IsUnspecified() {
			if ip.To4() != nil {
				host = "127.0.0.1"
			} else {
				host = "::1"
			}
			proxyAddress = net.JoinHostPort(host, port)
		}
	}
	return listenerProxyURL(listener, proxyAddress)
}

func listenerProxyURL(listener gatewayconfig.Listener, hostPort string) string {
	proxyURL := url.URL{
		Scheme: "socks5h",
		Host:   hostPort,
	}
	if listener.HasAuth() {
		proxyURL.User = url.UserPassword(listener.Username, listener.Password)
	}
	return proxyURL.String()
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
	defer transport.CloseIdleConnections()
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

func testListenerProxies(backends []ListenerBackendState) ProxyTestResponse {
	if len(backends) == 0 {
		result := checkProxy("")
		return proxyTestResponseFromResult(result, nil)
	}
	results := make([]ProxyTestResult, 0, len(backends))
	allOK := true
	for _, backend := range backends {
		result := ProxyTestResult{
			Listener: backend.ListenerName,
			Listen:   backend.ListenAddress,
			ProxyURL: backend.ProxyURL,
		}
		if backend.Status != "running" {
			result.OK = false
			result.Error = fmt.Sprintf("SOCKS5 入口未运行: %s", backend.Status)
		} else {
			proxyResult := checkProxy(backend.ProxyURL)
			result.OK = proxyResult.OK
			result.IP = proxyResult.IP
			result.LatencyMS = proxyResult.LatencyMS
			result.Error = proxyResult.Error
			result.Info = proxyResult.Info
			if result.ProxyURL == "" {
				result.ProxyURL = proxyResult.ProxyURL
			}
		}
		if !result.OK {
			allOK = false
		}
		results = append(results, result)
	}
	response := proxyTestResponseFromResult(results[0], results)
	response.OK = allOK
	if !allOK {
		response.Error = proxyTestSummaryError(results)
	}
	return response
}

func proxyTestResponseFromResult(result ProxyTestResult, results []ProxyTestResult) ProxyTestResponse {
	return ProxyTestResponse{
		OK:        result.OK,
		IP:        result.IP,
		LatencyMS: result.LatencyMS,
		Error:     result.Error,
		ProxyURL:  result.ProxyURL,
		Info:      result.Info,
		Results:   results,
	}
}

func proxyTestSummaryError(results []ProxyTestResult) string {
	if len(results) == 0 {
		return "SOCKS5 网关未启动"
	}
	failed := 0
	for _, result := range results {
		if !result.OK {
			failed++
		}
	}
	return fmt.Sprintf("%d/%d 个 SOCKS5 入口出口检测失败", failed, len(results))
}

func (s *Server) checkTunnelExit(ctx context.Context, tunnel *vpn.Tunnel, nodeID string) (*vpngate.IPInfo, error) {
	dialer, err := vpn.NewDialer(ctx, tunnel, s.logger.With("probe_node", nodeID))
	if err != nil {
		_ = tunnel.Close()
		return nil, fmt.Errorf("初始化用户态 TCP/IP 栈失败: %w", err)
	}
	// Dialer.Close 会关闭底层 tunnel，避免重复关闭。
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
	req.Header.Set("User-Agent", "AkiraGate-Go/1.0")
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
