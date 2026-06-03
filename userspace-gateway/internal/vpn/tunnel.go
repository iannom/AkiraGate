package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	ovpnconfig "github.com/galang-rs/ovpn/pkg/config"
	"github.com/galang-rs/ovpn/pkg/tunnel"
)

type Tunnel struct {
	tun    *tunnel.TUN
	logger *slog.Logger
}

type StartOptions struct {
	ConfigPath       string
	AuthFilePath     string
	HandshakeTimeout time.Duration
	Logger           *slog.Logger
}

type Info struct {
	IPv4    string
	Gateway string
	MTU     int
	IPv6    string
}

func Start(ctx context.Context, options StartOptions) (result *Tunnel, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if options.Logger == nil {
				options.Logger = slog.Default()
			}
			options.Logger.Error("OpenVPN 配置解析发生 panic", "panic", recovered)
			err = fmt.Errorf("解析 OpenVPN 配置失败: %v", recovered)
		}
	}()
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.ConfigPath == "" {
		return nil, fmt.Errorf("OpenVPN 配置路径不能为空")
	}

	cfgOptions := []ovpnconfig.Option{
		ovpnconfig.WithLogger(newOvpnLogger(options.Logger)),
		ovpnconfig.WithConfigFile(options.ConfigPath),
	}
	if options.AuthFilePath != "" {
		cfgOptions = append(cfgOptions, ovpnconfig.WithAuthFile(options.AuthFilePath))
	}
	cfg := ovpnconfig.NewConfig(cfgOptions...)

	startCtx := ctx
	cancel := func() {}
	if options.HandshakeTimeout > 0 {
		startCtx, cancel = context.WithTimeout(ctx, options.HandshakeTimeout)
	}
	defer cancel()

	tun, err := tunnel.Start(startCtx, &net.Dialer{}, cfg)
	if err != nil {
		return nil, fmt.Errorf("启动用户态 OpenVPN 隧道失败: %w", err)
	}
	return &Tunnel{tun: tun, logger: options.Logger}, nil
}

func (t *Tunnel) Read(packet []byte) (int, error) {
	return t.tun.Read(packet)
}

func (t *Tunnel) Write(packet []byte) (int, error) {
	return t.tun.Write(packet)
}

func (t *Tunnel) Close() error {
	return t.tun.Close()
}

func (t *Tunnel) Info() Info {
	info := t.tun.TunnelInfo()
	return Info{
		IPv4:    info.IP,
		Gateway: info.GW,
		MTU:     info.MTU,
		IPv6:    info.IPv6,
	}
}
