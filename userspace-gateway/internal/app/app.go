package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"aimilivpn/userspace-gateway/internal/config"
	"aimilivpn/userspace-gateway/internal/socks"
	"aimilivpn/userspace-gateway/internal/vpn"
)

type App struct {
	config config.Config
	logger *slog.Logger
}

func New(config config.Config, logger *slog.Logger) *App {
	if logger == nil {
		logger = slog.Default()
	}
	return &App{config: config, logger: logger}
}

func (a *App) Run(ctx context.Context) error {
	a.logger.Info("启动用户态 OpenVPN 后端", "ovpn", a.config.OpenVPNConfigPath)
	tunnel, err := vpn.Start(ctx, vpn.StartOptions{
		ConfigPath:       a.config.OpenVPNConfigPath,
		AuthFilePath:     a.config.AuthFilePath,
		HandshakeTimeout: a.config.HandshakeTimeout,
		Logger:           a.logger,
	})
	if err != nil {
		return err
	}
	defer tunnel.Close()

	info := tunnel.Info()
	a.logger.Info("用户态 OpenVPN 隧道已连接", "ipv4", info.IPv4, "gateway", info.Gateway, "mtu", info.MTU, "ipv6", info.IPv6)

	dialer, err := vpn.NewDialer(ctx, tunnel, a.logger)
	if err != nil {
		return fmt.Errorf("初始化用户态 TCP/IP 栈失败: %w", err)
	}
	defer dialer.Close()

	var servers []*socks.Server
	for _, listener := range a.config.Listeners {
		if !listener.IsEnabled() {
			continue
		}
		server := socks.NewServer(
			listener.ListenAddress(),
			dialer,
			a.config.ConnectTimeout,
			a.logger.With("listener", listener.Name),
			socks.AuthConfig{Username: listener.Username, Password: listener.Password},
		)
		servers = append(servers, server)
	}
	defer func() {
		for _, server := range servers {
			_ = server.Close()
		}
	}()

	errCh := make(chan error, len(servers))
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(s *socks.Server) {
			defer wg.Done()
			errCh <- s.Serve(ctx)
		}(server)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		if err != nil && ctx.Err() == nil {
			return err
		}
	}
	return ctx.Err()
}
