package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"aimilivpn/userspace-gateway/internal/app"
	"aimilivpn/userspace-gateway/internal/config"
)

func main() {
	var cfg config.Config
	var listenerFlags listenerFlag
	flag.Var(&listenerFlags, "socks5", "SOCKS5 listener: host:port or host:port,username,password. Repeatable.")
	listenHost := flag.String("listen-host", "", "deprecated: SOCKS5 listen host")
	listenPort := flag.Int("listen-port", 0, "deprecated: SOCKS5 listen port")
	flag.StringVar(&cfg.OpenVPNConfigPath, "ovpn", os.Getenv("AIMILI_GATEWAY_OVPN"), "OpenVPN client configuration path")
	flag.StringVar(&cfg.AuthFilePath, "auth-file", os.Getenv("AIMILI_GATEWAY_AUTH_FILE"), "OpenVPN auth-user-pass file")
	flag.DurationVar(&cfg.ConnectTimeout, "connect-timeout", config.DefaultConnectTimeout, "OpenVPN and outbound TCP connect timeout")
	flag.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", config.DefaultHandshakeTimeout, "OpenVPN userspace tunnel startup timeout")
	flag.Parse()
	cfg.Listeners = listenerFlags.listeners
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = listenersFromEnv()
	}
	if len(cfg.Listeners) == 0 && *listenHost != "" && *listenPort > 0 {
		cfg.Listeners = []config.Listener{config.NewListener("default", *listenHost, *listenPort, true)}
	}
	if len(cfg.Listeners) == 0 {
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		logger.Error("必须通过 --socks5 或 AIMILI_SOCKS5_LISTENERS 显式指定 SOCKS5 监听；公网监听必须包含用户名和密码")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := cfg.Validate(); err != nil {
		logger.Error("配置无效", "error", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	gateway := app.New(cfg, logger)
	if err := gateway.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("用户态网关退出", "error", err)
		os.Exit(1)
	}
}

func getenv(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

type listenerFlag struct {
	listeners []config.Listener
}

func (f *listenerFlag) String() string {
	values := make([]string, 0, len(f.listeners))
	for _, listener := range f.listeners {
		values = append(values, listener.ListenAddress())
	}
	return strings.Join(values, ";")
}

func (f *listenerFlag) Set(value string) error {
	listener, err := parseListener(value, len(f.listeners)+1)
	if err != nil {
		return err
	}
	f.listeners = append(f.listeners, listener)
	return nil
}

func listenersFromEnv() []config.Listener {
	raw := os.Getenv("AIMILI_SOCKS5_LISTENERS")
	if raw == "" {
		host := getenv("AIMILI_GATEWAY_HOST", "")
		portValue := os.Getenv("AIMILI_GATEWAY_PORT")
		if host == "" || portValue == "" {
			return nil
		}
		port, err := strconv.Atoi(portValue)
		if err != nil {
			return nil
		}
		listener := config.NewListener("default", host, port, true)
		listener.Username = os.Getenv("AIMILI_SOCKS5_USERNAME")
		listener.Password = os.Getenv("AIMILI_SOCKS5_PASSWORD")
		return []config.Listener{listener}
	}

	var listeners []config.Listener
	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		listener, err := parseListener(item, len(listeners)+1)
		if err != nil {
			continue
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

func parseListener(value string, index int) (config.Listener, error) {
	parts := strings.Split(value, ",")
	address := strings.TrimSpace(parts[0])
	host, portValue, err := net.SplitHostPort(address)
	if err != nil {
		return config.Listener{}, fmt.Errorf("SOCKS5 监听地址格式应为 host:port: %w", err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		return config.Listener{}, fmt.Errorf("SOCKS5 监听端口无效: %w", err)
	}

	listener := config.NewListener(fmt.Sprintf("socks%d", index), host, port, true)
	if len(parts) > 1 {
		listener.Username = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		listener.Password = strings.TrimSpace(parts[2])
	}
	if len(parts) > 3 {
		return config.Listener{}, errors.New("SOCKS5 监听配置最多包含 host:port,username,password")
	}
	return listener, nil
}
