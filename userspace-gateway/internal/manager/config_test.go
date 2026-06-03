package manager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateConfigRejectsInvalidSecretPath(t *testing.T) {
	config := testConfig()
	config.SecretPath = "../admin"

	if err := ValidateConfig(config); err == nil {
		t.Fatal("包含路径分隔符的登录安全后缀应被拒绝")
	}
}

func TestDefaultConfigUsesAuthenticatedSocksListener(t *testing.T) {
	config := DefaultConfig()

	if len(config.SocksListeners) != 1 {
		t.Fatalf("默认配置应包含一个 SOCKS5 监听，实际: %d", len(config.SocksListeners))
	}
	listener := config.SocksListeners[0]
	if !listener.HasAuth() {
		t.Fatal("默认 SOCKS5 监听必须启用用户名密码鉴权")
	}
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("默认配置应通过校验: %v", err)
	}
}

func TestLoadConfigRejectsInvalidPublicSocksListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{
  "web_host": "127.0.0.1",
  "web_port": 8787,
  "secret_path": "secret",
  "admin_username": "admin",
  "admin_password": "password",
  "refresh_seconds": 960,
  "socks5_listeners": [
    {"name": "public", "host": "::", "port": 7929, "enabled": true}
  ]
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("读取公网无鉴权 SOCKS5 配置时应失败")
	}
}

func TestValidateConfigRejectsIncompleteRoutingPolicy(t *testing.T) {
	config := testConfig()
	config.RoutingMode = "fixed_region"
	config.ForceCountry = ""

	if err := ValidateConfig(config); err == nil {
		t.Fatal("固定国家地区模式缺少国家代码时应被拒绝")
	}

	config.RoutingMode = "fixed_ip"
	config.FixedNodeID = ""
	if err := ValidateConfig(config); err == nil {
		t.Fatal("固定节点模式缺少节点 ID 时应被拒绝")
	}
}
