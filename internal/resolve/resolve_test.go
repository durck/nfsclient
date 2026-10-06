package resolve

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/testutil/dnsfixture"
)

func TestDNSServerValidation(t *testing.T) {
	for input, want := range map[string]string{"": "", "192.0.2.53": "192.0.2.53:53", "127.0.0.1:5353": "127.0.0.1:5353", "2001:db8::53": "[2001:db8::53]:53", "[::1]:5353": "[::1]:5353"} {
		if got, err := (Config{Server: input}).endpoint(); err != nil || got != want {
			t.Fatalf("%q: %q %v", input, got, err)
		}
	}
	for _, input := range []string{"dns.example", "https://127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:domain", ":53", "dns.example:53", "127.0.0.1:53/path"} {
		if err := (Config{Server: input}).Validate(); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestDNSUDPAndTCP(t *testing.T) {
	for _, mode := range []string{"udp", "tcp", "truncated", "nxdomain"} {
		t.Run(mode, func(t *testing.T) {
			s := dnsfixture.Start(t, func(network string, q dnsmessage.Message) *dnsmessage.Message {
				r := dnsfixture.Loopback(q)
				if mode == "truncated" && network == "udp" {
					r.Truncated, r.Answers = true, nil
				}
				if mode == "nxdomain" {
					r.RCode, r.Answers = dnsmessage.RCodeNameError, nil
				}
				return r
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, err := New(ctx, Config{Server: s.Address, TCP: mode == "tcp"})
			if err != nil {
				t.Fatal(err)
			}
			ips, err := r.LookupIP(ctx, "ip", "nfs.synthetic.invalid.")
			if mode == "nxdomain" {
				if err == nil || len(ips) != 0 {
					t.Fatal("negative custom DNS answer was ignored")
				}
			} else if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
				t.Fatalf("lookup: %v %v", ips, err)
			}
			if mode == "tcp" && (s.UDP.Load() != 0 || s.TCP.Load() < 2) {
				t.Fatal("forced TCP used UDP or skipped A/AAAA queries")
			}
			if mode == "udp" && (s.TCP.Load() != 0 || s.UDP.Load() < 2) {
				t.Fatal("default DNS did not use UDP")
			}
			if mode == "truncated" && (s.UDP.Load() == 0 || s.TCP.Load() == 0) {
				t.Fatal("missing standard truncated-UDP fallback")
			}
		})
	}
}

func TestSystemDNSTCPSelection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	r, err := newResolver(ctx, Config{TCP: true}, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "192.0.2.53:53" {
			t.Fatalf("changed system DNS address or wrong transport: %s %s", network, address)
		}
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Dial(ctx, "udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestDNSCancellation(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			seen := make(chan struct{}, 1)
			s := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message {
				select {
				case seen <- struct{}{}:
				default:
				}
				return nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, err := New(ctx, Config{Server: s.Address, TCP: tcp})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := r.LookupIP(ctx, "ip4", "nfs.synthetic.invalid."); done <- err }()
			select {
			case <-seen:
			case <-time.After(time.Second):
				t.Fatal("no DNS request")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "canceled") {
					t.Fatalf("cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("DNS cancellation stalled")
			}
		})
	}
}
