package socks

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, host string, port uint16, timeout time.Duration) (net.Conn, error)
}

type Server struct {
	listenAddress  string
	dialer         Dialer
	connectTimeout time.Duration
	logger         *slog.Logger
	listener       net.Listener
	auth           AuthConfig
	mu             sync.Mutex
}

type AuthConfig struct {
	Username string
	Password string
}

func (a AuthConfig) Enabled() bool {
	return a.Username != "" || a.Password != ""
}

func NewServer(listenAddress string, dialer Dialer, connectTimeout time.Duration, logger *slog.Logger, auth ...AuthConfig) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	authConfig := AuthConfig{}
	if len(auth) > 0 {
		authConfig = auth[0]
	}
	return &Server{
		listenAddress:  listenAddress,
		dialer:         dialer,
		connectTimeout: connectTimeout,
		logger:         logger,
		auth:           authConfig,
	}
}

func (s *Server) Serve(ctx context.Context) error {
	if s.dialer == nil {
		return errors.New("SOCKS5 dialer 不能为空")
	}
	listener, err := net.Listen("tcp", s.listenAddress)
	if err != nil {
		return fmt.Errorf("监听 SOCKS5 地址失败: %w", err)
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	s.logger.Info("SOCKS5 网关已启动", "listen", listener.Addr().String(), "auth", s.auth.Enabled())
	fmt.Printf("AIMILI_GATEWAY_READY listen=%s auth=%t\n", listener.Addr().String(), s.auth.Enabled())

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("接受 SOCKS5 客户端失败: %w", err)
		}
		go s.handleClient(ctx, client)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *Server) Address() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) handleClient(ctx context.Context, client net.Conn) {
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		s.logger.Warn("设置客户端超时失败", "error", err)
	}

	target, err := s.handshake(client)
	if err != nil {
		s.logger.Warn("SOCKS5 握手失败", "client", client.RemoteAddr().String(), "error", err)
		return
	}

	upstream, err := s.dialer.DialContext(ctx, target.Host, target.Port, s.connectTimeout)
	if err != nil {
		s.logger.Warn("SOCKS5 目标连接失败", "target", target.String(), "error", err)
		_ = sendReply(client, 0x04)
		return
	}
	defer upstream.Close()

	if err := sendReply(client, 0x00); err != nil {
		s.logger.Warn("SOCKS5 响应失败", "target", target.String(), "error", err)
		return
	}
	_ = client.SetDeadline(time.Time{})
	relay(client, upstream)
}

type Target struct {
	Host string
	Port uint16
}

func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

func (s *Server) handshake(client net.Conn) (Target, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return Target{}, err
	}
	if header[0] != 0x05 {
		return Target{}, fmt.Errorf("不支持的 SOCKS 版本: %d", header[0])
	}
	methodCount := int(header[1])
	if methodCount == 0 {
		return Target{}, errors.New("客户端未提供认证方法")
	}
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(client, methods); err != nil {
		return Target{}, err
	}
	if s.auth.Enabled() {
		if !supportsUsernamePassword(methods) {
			_, _ = client.Write([]byte{0x05, 0xff})
			return Target{}, errors.New("客户端不支持 SOCKS5 用户名密码认证")
		}
		if _, err := client.Write([]byte{0x05, 0x02}); err != nil {
			return Target{}, err
		}
		if err := s.authenticateUsernamePassword(client); err != nil {
			return Target{}, err
		}
	} else if supportsNoAuthentication(methods) {
		if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
			return Target{}, err
		}
	} else {
		_, _ = client.Write([]byte{0x05, 0xff})
		return Target{}, errors.New("客户端不支持 SOCKS5 无认证模式")
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(client, request); err != nil {
		return Target{}, err
	}
	if request[0] != 0x05 {
		return Target{}, fmt.Errorf("不支持的请求版本: %d", request[0])
	}
	if request[1] != 0x01 {
		_ = sendReply(client, 0x07)
		return Target{}, fmt.Errorf("暂不支持 SOCKS5 命令: %d", request[1])
	}

	host, err := readAddress(client, request[3])
	if err != nil {
		_ = sendReply(client, 0x08)
		return Target{}, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(client, portBytes); err != nil {
		return Target{}, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	if port == 0 {
		return Target{}, errors.New("目标端口不能为空")
	}
	return Target{Host: host, Port: port}, nil
}

func (s *Server) authenticateUsernamePassword(conn net.Conn) error {
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	if version[0] != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("不支持的 SOCKS5 用户名密码认证版本: %d", version[0])
	}

	username, err := readCredentialField(conn, "用户名")
	if err != nil {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return err
	}
	password, err := readCredentialField(conn, "密码")
	if err != nil {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return err
	}

	if constantTimeStringEqual(username, s.auth.Username) && constantTimeStringEqual(password, s.auth.Password) {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}

	_, _ = conn.Write([]byte{0x01, 0x01})
	return errors.New("SOCKS5 用户名或密码不正确")
}

func readCredentialField(reader io.Reader, fieldName string) (string, error) {
	length := make([]byte, 1)
	if _, err := io.ReadFull(reader, length); err != nil {
		return "", err
	}
	if length[0] == 0 {
		return "", fmt.Errorf("SOCKS5 %s不能为空", fieldName)
	}
	value := make([]byte, int(length[0]))
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	return string(value), nil
}

func constantTimeStringEqual(left string, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func readAddress(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", err
		}
		return net.IP(raw).String(), nil
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return "", err
		}
		if length[0] == 0 {
			return "", errors.New("目标域名不能为空")
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", err
		}
		return string(raw), nil
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", err
		}
		return net.IP(raw).String(), nil
	default:
		return "", fmt.Errorf("不支持的地址类型: %d", addressType)
	}
}

func supportsNoAuthentication(methods []byte) bool {
	for _, method := range methods {
		if method == 0x00 {
			return true
		}
	}
	return false
}

func supportsUsernamePassword(methods []byte) bool {
	for _, method := range methods {
		if method == 0x02 {
			return true
		}
	}
	return false
}

func sendReply(writer io.Writer, code byte) error {
	_, err := writer.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func relay(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go copyAndClose(&wg, left, right)
	go copyAndClose(&wg, right, left)
	wg.Wait()
}

func copyAndClose(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	_ = closeWrite(dst)
	_ = closeRead(src)
}

func closeWrite(conn net.Conn) error {
	if tcpConn, ok := conn.(interface{ CloseWrite() error }); ok {
		return tcpConn.CloseWrite()
	}
	return conn.Close()
}

func closeRead(conn net.Conn) error {
	if tcpConn, ok := conn.(interface{ CloseRead() error }); ok {
		return tcpConn.CloseRead()
	}
	return nil
}
