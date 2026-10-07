package nfs

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/resolve"
	"nfsclient/internal/testutil/dnsfixture"
)

type serverInfoConn struct {
	net.Conn
	peer net.Addr
}

func (c serverInfoConn) RemoteAddr() net.Addr { return c.peer }

func TestServerInfoConnectedPeer(t *testing.T) {
	for _, tt := range []struct{ target, peer, zone, name, ip string }{
		{"nas.example.test.", "192.0.2.9", "", "nas.example.test", "192.0.2.9"},
		{"nas.example.test", "2001:db8::9", "", "nas.example.test", "2001:db8::9"},
		{"192.0.2.1", "192.0.2.9", "", "", "192.0.2.9"},
		{"::ffff:192.0.2.9", "::ffff:192.0.2.9", "", "", "192.0.2.9"},
		{"fe80::9%eth0", "fe80::9", "eth0", "", "fe80::9%eth0"},
	} {
		t.Run(tt.target+tt.peer, func(t *testing.T) {
			c := &Client{config: &Config{Host: tt.target, DNS: resolve.Config{Server: "invalid"}},
				nfs: &rpcClient{conn: serverInfoConn{peer: &net.TCPAddr{IP: net.ParseIP(tt.peer), Zone: tt.zone, Port: 2049}}}}
			name, ip := c.ServerInfo(context.Background())
			if name != tt.name || ip != tt.ip {
				t.Fatalf("got (%q, %q), want (%q, %q)", name, ip, tt.name, tt.ip)
			}
		})
	}
	for _, c := range []*Client{nil, {}, {config: &Config{Host: "192.0.2.9"}}} {
		if name, ip := c.ServerInfo(context.Background()); name != "" || ip != "" {
			t.Fatalf("unconnected peer reported: %q %q", name, ip)
		}
	}
}

func TestServerInfoReverseDNS(t *testing.T) {
	for _, mode := range []string{"udp", "tcp", "missing", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			dns := dnsfixture.Start(t, func(network string, q dnsmessage.Message) *dnsmessage.Message {
				if mode == "timeout" {
					return nil
				}
				if len(q.Questions) != 1 || q.Questions[0].Type != dnsmessage.TypePTR || q.Questions[0].Name.String() != "9.2.0.192.in-addr.arpa." {
					t.Error("unexpected reverse question", q.Questions)
				}
				q.Response, q.RecursionAvailable = true, true
				if mode == "missing" {
					q.RCode = dnsmessage.RCodeNameError
				} else {
					name, _ := dnsmessage.NewName("nas.example.test.")
					q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}, Body: &dnsmessage.PTRResource{PTR: name}}}
				}
				return &q
			})
			c := &Client{config: &Config{Host: "192.0.2.9", DNS: resolve.Config{Server: dns.Address, TCP: mode == "tcp"}},
				nfs: &rpcClient{conn: serverInfoConn{peer: &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 2049}}}}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			name, ip := c.ServerInfo(ctx)
			want := "nas.example.test"
			if mode == "missing" || mode == "timeout" {
				want = ""
			}
			if name != want || ip != "192.0.2.9" || time.Since(start) > time.Second {
				t.Fatalf("reverse DNS result: %q %q (%s)", name, ip, time.Since(start))
			}
			if mode == "tcp" && (dns.TCP.Load() == 0 || dns.UDP.Load() != 0) {
				t.Fatal("custom TCP DNS was not respected")
			}
		})
	}
}
