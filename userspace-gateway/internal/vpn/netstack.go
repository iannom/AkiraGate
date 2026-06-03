package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

type Dialer struct {
	stack   *stack.Stack
	linkEP  *iobased.Endpoint
	tunnel  *Tunnel
	logger  *slog.Logger
	closeCh chan struct{}
	once    sync.Once
}

func NewDialer(ctx context.Context, tunnel *Tunnel, logger *slog.Logger) (*Dialer, error) {
	if tunnel == nil {
		return nil, errors.New("隧道不能为空")
	}
	if logger == nil {
		logger = slog.Default()
	}

	info := tunnel.Info()
	mtu := uint32(info.MTU)
	if mtu == 0 {
		mtu = 1500
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	linkEP, err := iobased.New(tunnel, mtu, 0)
	if err != nil {
		return nil, fmt.Errorf("创建用户态链路端点失败: %w", err)
	}
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("创建用户态 NIC 失败: %s", err)
	}

	ipv4Addr := net.ParseIP(info.IPv4).To4()
	if ipv4Addr == nil {
		return nil, fmt.Errorf("OpenVPN 未下发有效 IPv4 地址: %q", info.IPv4)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4Slice(ipv4Addr).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("配置用户态 IPv4 地址失败: %s", err)
	}

	if info.IPv6 != "" {
		ipv6Addr := net.ParseIP(info.IPv6).To16()
		if ipv6Addr != nil {
			if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
				Protocol:          ipv6.ProtocolNumber,
				AddressWithPrefix: tcpip.AddrFrom16Slice(ipv6Addr).WithPrefix(),
			}, stack.AddressProperties{}); err != nil {
				logger.Warn("配置用户态 IPv6 地址失败", "error", err)
			}
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	d := &Dialer{
		stack:   s,
		linkEP:  linkEP,
		tunnel:  tunnel,
		logger:  logger,
		closeCh: make(chan struct{}),
	}
	go d.closeWhenContextDone(ctx)
	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	if host == "" {
		return nil, errors.New("目标主机不能为空")
	}
	if port == 0 {
		return nil, errors.New("目标端口不能为空")
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	ip, networkProtocol, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	addr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: ip,
		Port: port,
	}

	conn, err := gonet.DialContextTCP(ctx, d.stack, addr, networkProtocol)
	if err != nil {
		return nil, fmt.Errorf("用户态 TCP 连接失败 %s:%d: %w", host, port, err)
	}
	return conn, nil
}

func (d *Dialer) Close() error {
	d.once.Do(func() {
		close(d.closeCh)
		_ = d.tunnel.Close()
		d.linkEP.Close()
		d.linkEP.Wait()
		d.stack.Close()
		d.stack.Wait()
	})
	return nil
}

func (d *Dialer) resolve(ctx context.Context, host string) (tcpip.Address, tcpip.NetworkProtocolNumber, error) {
	if parsed := net.ParseIP(host); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return tcpip.AddrFrom4Slice(v4), ipv4.ProtocolNumber, nil
		}
		if v6 := parsed.To16(); v6 != nil {
			return tcpip.AddrFrom16Slice(v6), ipv6.ProtocolNumber, nil
		}
	}

	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return tcpip.Address{}, 0, fmt.Errorf("解析目标域名失败 %s: %w", host, err)
	}
	for _, addr := range addrs {
		if v4 := addr.IP.To4(); v4 != nil {
			return tcpip.AddrFrom4Slice(v4), ipv4.ProtocolNumber, nil
		}
	}
	for _, addr := range addrs {
		if v6 := addr.IP.To16(); v6 != nil {
			return tcpip.AddrFrom16Slice(v6), ipv6.ProtocolNumber, nil
		}
	}
	return tcpip.Address{}, 0, fmt.Errorf("域名没有可用 IP: %s", host)
}

func (d *Dialer) closeWhenContextDone(ctx context.Context) {
	select {
	case <-ctx.Done():
		_ = d.Close()
	case <-d.closeCh:
	}
}
