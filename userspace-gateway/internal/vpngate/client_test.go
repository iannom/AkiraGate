package vpngate

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseNodes(t *testing.T) {
	config := "client\nremote 203.0.113.10 443 tcp\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(config))
	csvText := "# header\n*HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n" +
		"vpn.example,203.0.113.10,100,20,1000,Japan,JP,3," + encoded + "\n" +
		"*"

	nodes, err := ParseNodes(strings.NewReader(csvText))
	if err != nil {
		t.Fatalf("解析节点失败: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("节点数量错误: %d", len(nodes))
	}
	node := nodes[0]
	if node.RemoteHost != "203.0.113.10" || node.RemotePort != 443 || node.Proto != "tcp" {
		t.Fatalf("remote 解析错误: %#v", node)
	}
	if node.ConfigText != config {
		t.Fatalf("配置文本不匹配: %q", node.ConfigText)
	}
	if node.ID == "" {
		t.Fatal("节点 ID 不应为空")
	}
}

func TestParseNodesWithCurrentVPNGateFormat(t *testing.T) {
	config := "client\nremote 203.0.113.10 443 tcp\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(config))
	csvText := "*vpn_servers\n" +
		"#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" +
		"vpn.example,203.0.113.10,100,20,1000,Japan,JP,3,1,1,1,2weeks,op,," + encoded + "\n" +
		"*"

	nodes, err := ParseNodes(strings.NewReader(csvText))
	if err != nil {
		t.Fatalf("解析当前 VPNGate 格式失败: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("节点数量错误: %d", len(nodes))
	}
	node := nodes[0]
	if node.Hostname != "vpn.example" || node.RemoteHost != "203.0.113.10" || node.RemotePort != 443 {
		t.Fatalf("节点字段解析错误: %#v", node)
	}
}

func TestParseNodesReturnsErrorWhenNoUsableNodes(t *testing.T) {
	csvText := "*vpn_servers\n" +
		"#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n" +
		"vpn.example,203.0.113.10,100,20,1000,Japan,JP,3,invalid-base64\n" +
		"*"

	_, err := ParseNodes(strings.NewReader(csvText))
	if err == nil {
		t.Fatal("没有可用节点时应返回错误")
	}
	if !strings.Contains(err.Error(), "未解析到可用节点") {
		t.Fatalf("错误信息不符合预期: %v", err)
	}
}
