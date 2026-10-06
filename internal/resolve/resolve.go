// Package resolve provides per-connection DNS configuration without global state.
package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

type Config struct {
	Server string
	TCP    bool
}

func (c Config) endpoint() (string, error) {
	if c.Server == "" {
		return "", nil
	}
	if ip, err := netip.ParseAddr(c.Server); err == nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(c.Server)
	if err != nil {
		return "", errors.New("--dns-server must be an IP address or IP:PORT (IPv6 with port: [IP]:PORT)")
	}
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if ipErr != nil || portErr != nil || number < 1 || number > 65535 {
		return "", errors.New("--dns-server requires a literal IP and port 1-65535")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(number)), nil
}

func (c Config) Validate() error { _, err := c.endpoint(); return err }

// New uses system DNS addresses unless Server is explicit. A custom resolver
// never falls back to system DNS; TCP changes only DNS, not NFS or KDC transport.
// Owner cancellation closes active DNS sockets as well as stopping the lookup.
func New(owner context.Context, cfg Config) (*net.Resolver, error) {
	return newResolver(owner, cfg, (&net.Dialer{}).DialContext)
}

func newResolver(owner context.Context, cfg Config, dial func(context.Context, string, string) (net.Conn, error)) (*net.Resolver, error) {
	endpoint, err := cfg.endpoint()
	if err != nil {
		return nil, err
	}
	return &net.Resolver{PreferGo: true, Dial: func(queryCtx context.Context, network, address string) (net.Conn, error) {
		if err := owner.Err(); err != nil {
			return nil, err
		}
		if endpoint != "" {
			address = endpoint
		}
		if cfg.TCP {
			network = "tcp"
		}
		ctx, cancel := context.WithCancel(queryCtx)
		stopOwner := context.AfterFunc(owner, cancel)
		defer func() { stopOwner(); cancel() }()
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		wrapped := &cancelConn{Conn: conn, stop: context.AfterFunc(owner, func() { conn.Close() })}
		if _, ok := conn.(net.PacketConn); ok {
			return &cancelPacketConn{wrapped}, nil
		}
		return wrapped, nil
	}}, nil
}

type cancelConn struct {
	net.Conn
	stop func() bool
}

func (c *cancelConn) Close() error { c.stop(); return c.Conn.Close() }

// Go's resolver selects datagram versus stream framing from this interface.
type cancelPacketConn struct{ *cancelConn }

func (c *cancelPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.Conn.(net.PacketConn).ReadFrom(b)
}
func (c *cancelPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.Conn.(net.PacketConn).WriteTo(b, a)
}
