package cli

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/nfs"
	"nfsclient/internal/resolve"
	"nfsclient/internal/session"
	"nfsclient/internal/testutil/dnsfixture"
)

func TestPromptServerChangesWithClient(t *testing.T) {
	_, port := testServer(t)
	dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message { return dnsfixture.Loopback(q) })
	connect := func(host string) *nfs.Client {
		c, err := nfs.Connect(context.Background(), nfs.Config{Host: host, MountPort: port, NFSPort: port, Timeout: time.Second, DNS: resolve.Config{Server: dns.Address}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	s := &Shell{Session: session.New(connect("first.synthetic.invalid"), "stale-session-label", false, false, io.Discard)}
	ctx := context.Background()
	if got := s.prompt(ctx); got != "nfs first.synthetic.invalid (127.0.0.1) / > " {
		t.Fatal(got)
	}
	queries := dns.UDP.Load() + dns.TCP.Load()
	s.Session.CWD = "/documents"
	if got := s.prompt(ctx); !strings.HasSuffix(got, " /documents > ") {
		t.Fatal(got)
	}
	if dns.UDP.Load()+dns.TCP.Load() != queries {
		t.Fatal("prompt redraw performed a DNS query")
	}
	s.Session.Client = connect("second.synthetic.invalid")
	if got := s.prompt(ctx); got != "nfs second.synthetic.invalid (127.0.0.1) /documents > " {
		t.Fatal("stale server after client replacement:", got)
	}
}

func TestPromptEscapesServerAndPath(t *testing.T) {
	s := &Shell{Session: &session.Session{Host: "nas\x1b[31m\n", CWD: "/data\n"}}
	got := s.prompt(context.Background())
	if strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, `nas\x1b[31m\n`) || !strings.Contains(got, `/data\n`) {
		t.Fatalf("unsafe prompt: %q", got)
	}
	s.Session.Host = "192.0.2.9"
	s.Session.CWD = "/"
	if got := s.prompt(context.Background()); got != "nfs 192.0.2.9 / > " {
		t.Fatal(got)
	}
}
