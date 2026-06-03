package socks

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

type testDialer struct {
	host string
	port uint16
	conn net.Conn
}

func (d *testDialer) DialContext(_ context.Context, host string, port uint16, _ time.Duration) (net.Conn, error) {
	d.host = host
	d.port = port
	return d.conn, nil
}

func TestSOCKS5ConnectRelaysTraffic(t *testing.T) {
	client, serverSide := net.Pipe()
	defer client.Close()

	dialerSide, upstream := net.Pipe()
	defer upstream.Close()

	dialer := &testDialer{conn: dialerSide}
	server := NewServer("127.0.0.1:0", dialer, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		server.handleClient(context.Background(), serverSide)
		close(done)
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("写入认证协商失败: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("读取认证响应失败: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("认证响应不符合预期: %x", reply)
	}

	request := []byte{0x05, 0x01, 0x00, 0x03, 0x0b}
	request = append(request, []byte("example.com")...)
	request = append(request, 0x01, 0xbb)
	if _, err := client.Write(request); err != nil {
		t.Fatalf("写入 CONNECT 请求失败: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(client, connectReply); err != nil {
		t.Fatalf("读取 CONNECT 响应失败: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("CONNECT 响应失败: %x", connectReply)
	}
	if dialer.host != "example.com" || dialer.port != 443 {
		t.Fatalf("目标解析错误: %s:%d", dialer.host, dialer.port)
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("写入客户端数据失败: %v", err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(upstream, payload); err != nil {
		t.Fatalf("读取上游数据失败: %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("上游收到数据错误: %q", payload)
	}

	if _, err := upstream.Write([]byte("pong")); err != nil {
		t.Fatalf("写入上游响应失败: %v", err)
	}
	if _, err := io.ReadFull(client, payload); err != nil {
		t.Fatalf("读取客户端响应失败: %v", err)
	}
	if string(payload) != "pong" {
		t.Fatalf("客户端收到数据错误: %q", payload)
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 客户端处理未及时退出")
	}
}

func TestSOCKS5ServerListensAndRelaysTraffic(t *testing.T) {
	dialerSide, upstream := net.Pipe()
	defer upstream.Close()

	dialer := &testDialer{conn: dialerSide}
	server := NewServer("127.0.0.1:0", dialer, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	defer func() {
		cancel()
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("SOCKS5 服务未及时退出")
		}
	}()

	var address string
	for range 20 {
		address = server.Address()
		if address != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if address == "" {
		t.Fatal("SOCKS5 服务未开始监听")
	}

	client, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("连接 SOCKS5 服务失败: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("写入认证协商失败: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("读取认证响应失败: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("认证响应不符合预期: %x", reply)
	}

	request := []byte{0x05, 0x01, 0x00, 0x01, 203, 0, 113, 1, 0x00, 0x50}
	if _, err := client.Write(request); err != nil {
		t.Fatalf("写入 CONNECT 请求失败: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(client, connectReply); err != nil {
		t.Fatalf("读取 CONNECT 响应失败: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("CONNECT 响应失败: %x", connectReply)
	}
	if dialer.host != "203.0.113.1" || dialer.port != 80 {
		t.Fatalf("目标解析错误: %s:%d", dialer.host, dialer.port)
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("写入客户端数据失败: %v", err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(upstream, payload); err != nil {
		t.Fatalf("读取上游数据失败: %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("上游收到数据错误: %q", payload)
	}
}

func TestSOCKS5RejectsUnsupportedAuthMethod(t *testing.T) {
	client, serverSide := net.Pipe()
	defer client.Close()

	dialer := &testDialer{}
	server := NewServer("127.0.0.1:0", dialer, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		server.handleClient(context.Background(), serverSide)
		close(done)
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("写入认证协商失败: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("读取认证拒绝响应失败: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0xff {
		t.Fatalf("认证拒绝响应不符合预期: %x", reply)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 客户端处理未及时退出")
	}
}

func TestSOCKS5UsernamePasswordAuthConnects(t *testing.T) {
	client, serverSide := net.Pipe()
	defer client.Close()

	dialerSide, upstream := net.Pipe()
	defer upstream.Close()

	dialer := &testDialer{conn: dialerSide}
	server := NewServer(
		"127.0.0.1:0",
		dialer,
		time.Second,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthConfig{Username: "user", Password: "pass"},
	)
	done := make(chan struct{})
	go func() {
		server.handleClient(context.Background(), serverSide)
		close(done)
	}()

	if _, err := client.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		t.Fatalf("写入认证方法失败: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("读取认证方法响应失败: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("认证方法响应不符合预期: %x", reply)
	}

	if _, err := client.Write(usernamePasswordRequest("user", "pass")); err != nil {
		t.Fatalf("写入用户名密码失败: %v", err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(client, authReply); err != nil {
		t.Fatalf("读取用户名密码响应失败: %v", err)
	}
	if authReply[0] != 0x01 || authReply[1] != 0x00 {
		t.Fatalf("用户名密码响应不符合预期: %x", authReply)
	}

	request := []byte{0x05, 0x01, 0x00, 0x03, 0x0b}
	request = append(request, []byte("example.com")...)
	request = append(request, 0x01, 0xbb)
	if _, err := client.Write(request); err != nil {
		t.Fatalf("写入 CONNECT 请求失败: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(client, connectReply); err != nil {
		t.Fatalf("读取 CONNECT 响应失败: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("CONNECT 响应失败: %x", connectReply)
	}
	if dialer.host != "example.com" || dialer.port != 443 {
		t.Fatalf("目标解析错误: %s:%d", dialer.host, dialer.port)
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 客户端处理未及时退出")
	}
}

func TestSOCKS5UsernamePasswordAuthRejectsBadPassword(t *testing.T) {
	client, serverSide := net.Pipe()
	defer client.Close()

	server := NewServer(
		"127.0.0.1:0",
		&testDialer{},
		time.Second,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthConfig{Username: "user", Password: "pass"},
	)
	done := make(chan struct{})
	go func() {
		server.handleClient(context.Background(), serverSide)
		close(done)
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("写入认证方法失败: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("读取认证方法响应失败: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("认证方法响应不符合预期: %x", reply)
	}

	if _, err := client.Write(usernamePasswordRequest("user", "wrong")); err != nil {
		t.Fatalf("写入用户名密码失败: %v", err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(client, authReply); err != nil {
		t.Fatalf("读取用户名密码响应失败: %v", err)
	}
	if authReply[0] != 0x01 || authReply[1] != 0x01 {
		t.Fatalf("用户名密码拒绝响应不符合预期: %x", authReply)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 客户端处理未及时退出")
	}
}

func TestSOCKS5UsernamePasswordAuthRejectsNoAuthOnlyClient(t *testing.T) {
	client, serverSide := net.Pipe()
	defer client.Close()

	server := NewServer(
		"127.0.0.1:0",
		&testDialer{},
		time.Second,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthConfig{Username: "user", Password: "pass"},
	)
	done := make(chan struct{})
	go func() {
		server.handleClient(context.Background(), serverSide)
		close(done)
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("写入认证方法失败: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("读取认证方法响应失败: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0xff {
		t.Fatalf("认证方法拒绝响应不符合预期: %x", reply)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 客户端处理未及时退出")
	}
}

func usernamePasswordRequest(username string, password string) []byte {
	request := []byte{0x01, byte(len(username))}
	request = append(request, []byte(username)...)
	request = append(request, byte(len(password)))
	request = append(request, []byte(password)...)
	return request
}

func appendPort(buffer []byte, port uint16) []byte {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(buffer, portBytes...)
}
