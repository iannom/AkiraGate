package manager

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	gatewayconfig "akiragate/userspace-gateway/internal/config"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	WebHost           string                   `json:"web_host"`
	WebPort           int                      `json:"web_port"`
	SecretPath        string                   `json:"secret_path"`
	AdminUsername     string                   `json:"admin_username"`
	AdminPassword     string                   `json:"admin_password,omitempty"`
	AdminPasswordHash string                   `json:"admin_password_hash"`
	OpenVPNConfig     string                   `json:"openvpn_config"`
	OpenVPNAuth       string                   `json:"openvpn_auth"`
	AutoConnect       bool                     `json:"auto_connect"`
	RefreshSeconds    int                      `json:"refresh_seconds"`
	RoutingMode       string                   `json:"routing_mode"`
	ForceCountry      string                   `json:"force_country"`
	FixedNodeID       string                   `json:"fixed_node_id"`
	SocksListeners    []gatewayconfig.Listener `json:"socks5_listeners"`
}

func DefaultConfig() Config {
	proxyPassword := randomHex(9)
	adminPasswordHash, err := HashPassword(randomHex(9))
	if err != nil {
		adminPasswordHash = ""
	}
	return Config{
		WebHost:           "::",
		WebPort:           8787,
		SecretPath:        randomHex(6),
		AdminUsername:     "admin",
		AdminPasswordHash: adminPasswordHash,
		AutoConnect:       false,
		RefreshSeconds:    960,
		RoutingMode:       "auto",
		SocksListeners: []gatewayconfig.Listener{
			withListenerAuth(gatewayconfig.NewListener("local", "127.0.0.1", 7928, true), "proxy", proxyPassword),
		},
	}
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			config := DefaultConfig()
			if err := SaveConfig(path, config); err != nil {
				return Config{}, err
			}
			return config, nil
		}
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	needsMigration := strings.TrimSpace(config.AdminPassword) != "" ||
		strings.TrimSpace(config.AdminPasswordHash) == "" ||
		(config.AutoConnect && strings.TrimSpace(config.OpenVPNConfig) == "" && !hasListenerBackendPolicy(config.SocksListeners))
	normalizeConfig(&config)
	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}
	if needsMigration {
		if err := SaveConfig(path, config); err != nil {
			return Config{}, err
		}
	}
	return config, nil
}

func SaveConfig(path string, config Config) error {
	normalizeConfig(&config)
	if err := ValidateConfig(config); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ValidateConfig(config Config) error {
	if config.WebHost == "" {
		return errors.New("Web 监听地址不能为空")
	}
	if config.WebPort < 1 || config.WebPort > 65535 {
		return fmt.Errorf("Web 监听端口超出范围: %d", config.WebPort)
	}
	if config.SecretPath == "" {
		return errors.New("登录安全后缀不能为空")
	}
	if !validSecretPath(config.SecretPath) {
		return errors.New("登录安全后缀只能包含字母、数字、下划线和短横线")
	}
	if config.AdminUsername == "" || config.AdminPasswordHash == "" {
		return errors.New("管理账号和密码哈希不能为空")
	}
	if !validPasswordHash(config.AdminPasswordHash) {
		return errors.New("管理密码哈希无效")
	}
	if err := validateRouting(config); err != nil {
		return err
	}
	if err := gatewayconfig.ValidateListeners(config.SocksListeners); err != nil {
		return err
	}
	webAddress := net.JoinHostPort(config.WebHost, fmt.Sprintf("%d", config.WebPort))
	for _, listener := range config.SocksListeners {
		if listener.IsEnabled() && listener.ListenAddress() == webAddress {
			return fmt.Errorf("SOCKS5 监听地址不能与 Web 管理地址相同: %s", webAddress)
		}
	}
	return nil
}

func validateRouting(config Config) error {
	switch config.RoutingMode {
	case "auto":
		return nil
	case "fixed_region":
		if config.ForceCountry == "" {
			return errors.New("固定国家地区模式必须选择国家代码")
		}
		return nil
	case "fixed_ip":
		if config.FixedNodeID == "" {
			return errors.New("固定节点模式必须选择节点 ID")
		}
		return nil
	default:
		return errors.New("路由模式必须是 auto、fixed_region 或 fixed_ip")
	}
}

func withListenerAuth(listener gatewayconfig.Listener, username string, password string) gatewayconfig.Listener {
	listener.Username = username
	listener.Password = password
	return listener
}

func validSecretPath(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			continue
		}
		if ch >= '0' && ch <= '9' {
			continue
		}
		if ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func normalizeConfig(config *Config) {
	config.WebHost = strings.TrimSpace(config.WebHost)
	config.SecretPath = strings.TrimSpace(config.SecretPath)
	config.AdminUsername = strings.TrimSpace(config.AdminUsername)
	config.AdminPassword = strings.TrimSpace(config.AdminPassword)
	config.AdminPasswordHash = strings.TrimSpace(config.AdminPasswordHash)
	config.OpenVPNConfig = strings.TrimSpace(config.OpenVPNConfig)
	config.OpenVPNAuth = strings.TrimSpace(config.OpenVPNAuth)
	config.RoutingMode = strings.TrimSpace(config.RoutingMode)
	config.ForceCountry = strings.ToUpper(strings.TrimSpace(config.ForceCountry))
	config.FixedNodeID = strings.TrimSpace(config.FixedNodeID)
	if config.WebHost == "" {
		config.WebHost = "::"
	}
	if config.WebPort == 0 {
		config.WebPort = 8787
	}
	if config.SecretPath == "" {
		config.SecretPath = randomHex(6)
	}
	if config.AdminUsername == "" {
		config.AdminUsername = "admin"
	}
	if config.AdminPasswordHash == "" && config.AdminPassword != "" {
		hash, err := HashPassword(config.AdminPassword)
		if err == nil {
			config.AdminPasswordHash = hash
		}
	}
	config.AdminPassword = ""
	if config.AdminPasswordHash == "" {
		hash, err := HashPassword(randomHex(9))
		if err == nil {
			config.AdminPasswordHash = hash
		}
	}
	if config.RefreshSeconds <= 0 {
		config.RefreshSeconds = 960
	}
	if config.RoutingMode == "" {
		config.RoutingMode = "auto"
	}
	if len(config.SocksListeners) == 0 {
		config.SocksListeners = DefaultConfig().SocksListeners
	}
	for idx := range config.SocksListeners {
		listener := &config.SocksListeners[idx]
		if listener.Name == "" {
			listener.Name = fmt.Sprintf("socks%d", idx+1)
		}
		if listener.Host == "" {
			listener.Host = "127.0.0.1"
		}
		if listener.Port == 0 {
			listener.Port = 7928 + idx
		}
		listener.Username = strings.TrimSpace(listener.Username)
		listener.Password = strings.TrimSpace(listener.Password)
		listener.CountryCode = strings.ToUpper(strings.TrimSpace(listener.CountryCode))
		listener.FixedNodeID = strings.TrimSpace(listener.FixedNodeID)
		listener.EntryCIDRs = normalizeCIDRs(listener.EntryCIDRs)
		if listener.BackendPolicyEnabled == nil && listener.HasBackendPolicyValues() {
			enabled := true
			listener.BackendPolicyEnabled = &enabled
		}
	}
	if config.OpenVPNConfig == "" && !hasListenerBackendPolicy(config.SocksListeners) {
		config.AutoConnect = false
	}
}

func hasListenerBackendPolicy(listeners []gatewayconfig.Listener) bool {
	for _, listener := range listeners {
		if listener.BackendPolicyIsEnabled() && listener.HasBackendPolicyValues() {
			return true
		}
	}
	return false
}

func normalizeCIDRs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		cidr := strings.TrimSpace(value)
		if cidr == "" {
			continue
		}
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		normalized = append(normalized, cidr)
	}
	return normalized
}

func HashPassword(password string) (string, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return "", errors.New("管理密码不能为空")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func validPasswordHash(hash string) bool {
	if hash == "" {
		return false
	}
	_, err := bcrypt.Cost([]byte(hash))
	return err == nil
}

func verifyPassword(hash string, password string) bool {
	if hash == "" || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func randomHex(size int) string {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "akiragate"
	}
	return hex.EncodeToString(buffer)
}
