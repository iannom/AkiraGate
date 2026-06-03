package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultConnectTimeout   = 20 * time.Second
	DefaultHandshakeTimeout = 150 * time.Second
)

type Config struct {
	Listeners         []Listener
	OpenVPNConfigPath string
	AuthFilePath      string
	ConnectTimeout    time.Duration
	HandshakeTimeout  time.Duration
}

type Listener struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Username    string   `json:"username,omitempty"`
	Password    string   `json:"password,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	EntryCIDRs  []string `json:"entry_cidrs,omitempty"`
	FixedNodeID string   `json:"fixed_node_id,omitempty"`
}

func DefaultListener() Listener {
	enabled := true
	return Listener{
		Name:    "default",
		Host:    "127.0.0.1",
		Port:    7928,
		Enabled: &enabled,
	}
}

func NewListener(name string, host string, port int, enabled bool) Listener {
	return Listener{Name: name, Host: host, Port: port, Enabled: boolPtr(enabled)}
}

func boolPtr(value bool) *bool {
	return &value
}

func (l Listener) ListenAddress() string {
	return net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
}

func (l Listener) HasAuth() bool {
	return l.Username != "" || l.Password != ""
}

func (l Listener) IsEnabled() bool {
	return l.Enabled == nil || *l.Enabled
}

func (c Config) Validate() error {
	if err := ValidateListeners(c.Listeners); err != nil {
		return err
	}
	if c.OpenVPNConfigPath == "" {
		return errors.New("必须通过 --ovpn 或 AKIRAGATE_GATEWAY_OVPN 指定 OpenVPN 配置")
	}
	if _, err := os.Stat(c.OpenVPNConfigPath); err != nil {
		return fmt.Errorf("OpenVPN 配置不可读: %w", err)
	}
	if c.AuthFilePath != "" {
		if _, err := os.Stat(c.AuthFilePath); err != nil {
			return fmt.Errorf("认证文件不可读: %w", err)
		}
	}
	if c.ConnectTimeout <= 0 {
		return errors.New("连接超时时间必须大于 0")
	}
	if c.HandshakeTimeout <= 0 {
		return errors.New("握手超时时间必须大于 0")
	}
	return nil
}

func ValidateListeners(listeners []Listener) error {
	enabledListeners := map[string]struct{}{}
	for _, listener := range listeners {
		if !listener.IsEnabled() {
			continue
		}
		if listener.Host == "" {
			return errors.New("SOCKS5 监听地址不能为空")
		}
		if listener.Port < 1024 || listener.Port > 65535 {
			return fmt.Errorf("SOCKS5 监听端口超出范围: %d", listener.Port)
		}
		if isUnspecifiedHost(listener.Host) {
			if !listener.HasAuth() {
				return fmt.Errorf("公网 SOCKS5 监听 %s 必须启用用户名密码鉴权", listener.ListenAddress())
			}
		}
		if listener.HasAuth() && (listener.Username == "" || listener.Password == "") {
			return fmt.Errorf("SOCKS5 监听 %s 的用户名和密码必须同时填写", listener.ListenAddress())
		}
		if err := validateListenerBackendPolicy(listener); err != nil {
			return err
		}
		key := listener.ListenAddress()
		if _, ok := enabledListeners[key]; ok {
			return fmt.Errorf("SOCKS5 监听地址重复: %s", key)
		}
		enabledListeners[key] = struct{}{}
	}
	if len(enabledListeners) == 0 {
		return errors.New("至少需要启用一个 SOCKS5 监听端口")
	}
	return nil
}

func validateListenerBackendPolicy(listener Listener) error {
	if listener.CountryCode != "" && !validCountryCode(listener.CountryCode) {
		return fmt.Errorf("SOCKS5 监听 %s 的绑定国家代码无效: %s", listener.ListenAddress(), listener.CountryCode)
	}
	for _, value := range listener.EntryCIDRs {
		cidr := strings.TrimSpace(value)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("SOCKS5 监听 %s 的入口网段 CIDR 无效: %s", listener.ListenAddress(), cidr)
		}
	}
	return nil
}

func validCountryCode(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 2 {
		return false
	}
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			continue
		}
		return false
	}
	return true
}

func isUnspecifiedHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
