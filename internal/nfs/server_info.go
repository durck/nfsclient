package nfs

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"nfsclient/internal/resolve"
)

// ServerInfo returns a display name and the connected NFS peer's IP address.
// Reverse DNS is best-effort, bounded by ctx, and never changes authentication,
// routing or the configured server identity. Callers should cache display data.
func (c *Client) ServerInfo(ctx context.Context) (name, ip string) {
	if c == nil {
		return "", ""
	}
	var dns resolve.Config
	if c.config != nil {
		name = strings.TrimSuffix(c.config.Host, ".")
		dns = c.config.DNS
	}
	if c.nfs != nil && c.nfs.conn != nil {
		if host, _, err := net.SplitHostPort(c.nfs.conn.RemoteAddr().String()); err == nil {
			if addr, err := netip.ParseAddr(host); err == nil {
				ip = addr.Unmap().String()
			}
		}
	}
	if _, err := netip.ParseAddr(name); err != nil && name != "" {
		return name, ip
	}
	// Literal targets are addresses, not hostnames. Do not label an unconnected
	// target as a connected peer or resolve a different address for the display.
	name = ""
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return name, ip
	}
	resolver, err := resolve.New(ctx, dns)
	if err != nil {
		return name, ip
	}
	if names, err := resolver.LookupAddr(ctx, addr.WithZone("").String()); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	return name, ip
}
