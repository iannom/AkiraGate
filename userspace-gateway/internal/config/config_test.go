package config

import "testing"

func TestValidateListenersAllowsMultipleAuthenticatedPublicListeners(t *testing.T) {
	listeners := []Listener{
		NewListener("local", "127.0.0.1", 7928, true),
		{Name: "public", Host: "::", Port: 7929, Username: "user", Password: "pass", Enabled: boolPtr(true)},
	}
	if err := ValidateListeners(listeners); err != nil {
		t.Fatalf("多监听配置应通过校验: %v", err)
	}
}

func TestValidateListenersRejectsPublicListenerWithoutAuth(t *testing.T) {
	listeners := []Listener{
		NewListener("public", "[::]", 7929, true),
	}
	if err := ValidateListeners(listeners); err == nil {
		t.Fatal("公网监听未启用鉴权时应被拒绝")
	}
}

func TestValidateListenersRejectsDuplicateAddress(t *testing.T) {
	listeners := []Listener{
		NewListener("a", "127.0.0.1", 7928, true),
		NewListener("b", "127.0.0.1", 7928, true),
	}
	if err := ValidateListeners(listeners); err == nil {
		t.Fatal("重复监听地址应被拒绝")
	}
}

func TestValidateListenersTreatsMissingEnabledAsEnabled(t *testing.T) {
	listeners := []Listener{
		{Name: "public", Host: "::", Port: 7929},
	}
	if err := ValidateListeners(listeners); err == nil {
		t.Fatal("省略 enabled 的公网监听仍应按启用处理并要求鉴权")
	}
}

func TestValidateListenersRejectsInvalidBackendPolicy(t *testing.T) {
	listener := NewListener("local", "127.0.0.1", 7928, true)
	listener.CountryCode = "JPN"
	if err := ValidateListeners([]Listener{listener}); err == nil {
		t.Fatal("无效国家代码应被拒绝")
	}

	listener.CountryCode = "JP"
	listener.EntryCIDRs = []string{"not-cidr"}
	if err := ValidateListeners([]Listener{listener}); err == nil {
		t.Fatal("无效入口 CIDR 应被拒绝")
	}
}

func TestValidateListenersAllowsBackendPolicy(t *testing.T) {
	listener := NewListener("local", "127.0.0.1", 7928, true)
	listener.CountryCode = "JP"
	listener.EntryCIDRs = []string{"203.0.113.0/24", "2001:db8::/32"}
	listener.FixedNodeID = "jp-1"

	if err := ValidateListeners([]Listener{listener}); err != nil {
		t.Fatalf("有效 SOCKS5 后端绑定策略应通过校验: %v", err)
	}
}
