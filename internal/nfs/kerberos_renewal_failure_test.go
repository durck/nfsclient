package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKerberosRenewalFailure(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires local MIT fixture")
	}
	for _, mode := range []string{"keytab-removed", "cache-corrupt", "cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			credential := "keytab"
			if mode == "cache-corrupt" {
				credential = "ccache"
			}
			cfg := renewalFixtureConfig(t, "3", "krb5p", credential)
			original := cfg
			dir := t.TempDir()
			copyLocal := func(source, name string) string {
				b, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(b)
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			cfg.Kerberos.ConfigFile = copyLocal(cfg.Kerberos.ConfigFile, "krb5.conf")
			if credential == "keytab" {
				cfg.Kerberos.Keytab = copyLocal(cfg.Kerberos.Keytab, "client.keytab")
			} else {
				cfg.Kerberos.CCache = copyLocal(cfg.Kerberos.CCache, "client.ccache")
			}
			ctx := context.Background()
			c, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			root, err := c.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			file, err := c.Create(ctx, root.Handle, fmt.Sprintf("renew-failure-%s-%d", mode, time.Now().UnixNano()), 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			var seen, done chan struct{}
			if mode == "keytab-removed" {
				if err := os.Remove(cfg.Kerberos.Keytab); err != nil {
					t.Fatal(err)
				}
			} else if mode == "cache-corrupt" {
				if err := os.WriteFile(cfg.Kerberos.CCache, []byte("not a cache"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				seen, done = make(chan struct{}), make(chan struct{})
				t.Cleanup(func() { l.Close(); <-done })
				go func() {
					defer close(done)
					peer, err := l.Accept()
					if err != nil {
						return
					}
					defer peer.Close()
					peer.SetDeadline(time.Now().Add(2 * time.Second))
					var p [4]byte
					if _, err := io.ReadFull(peer, p[:]); err != nil {
						return
					}
					close(seen)
					io.Copy(io.Discard, peer)
				}()
				conf := fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n udp_preference_limit = 1\n[realms]\n NFS.TEST = {\n kdc = %s\n }\n", l.Addr())
				if err := os.WriteFile(cfg.Kerberos.ConfigFile, []byte(conf), 0600); err != nil {
					t.Fatal(err)
				}
			}
			c.nfs.mu.Lock()
			c.nfs.gss.renewAt = time.Now()
			c.nfs.mu.Unlock()
			requestCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := c.WriteFrom(requestCtx, file.Handle, bytes.NewReader([]byte("must not arrive")))
				result <- err
			}()
			if mode == "cancel" {
				select {
				case <-seen:
					cancel()
				case <-time.After(time.Second):
					t.Fatal("renewal did not reach KDC")
				}
			}
			select {
			case err = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("renewal exceeded deadline")
			}
			if err == nil || !strings.Contains(err.Error(), "pending NFS request not sent") {
				t.Fatalf("renewal failure: %v", err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) || mode == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("wrong cancellation: %v", err)
			}
			if done != nil {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("KDC connection leaked")
				}
			}
			if _, err = c.GetAttr(ctx, file.Handle); err == nil || !strings.Contains(err.Error(), "session closed") {
				t.Fatalf("failed session revived: %v", err)
			}
			if c.KerberosRenewals() != 0 || c.Identity() != "root@NFS.TEST (krb5p)" {
				t.Fatal("identity changed on failure")
			}
			observer, err := Connect(ctx, original)
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close()
			attr, err := observer.GetAttr(ctx, file.Handle)
			if err != nil || attr.Size != 0 {
				t.Fatalf("pending mutation reached server: size=%d err=%v", attr.Size, err)
			}
		})
	}
}

func TestKerberosRenewalRelativePaths(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires local MIT fixture")
	}
	cfg := renewalFixtureConfig(t, "3", "krb5p", "ccache")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*string{&cfg.Kerberos.ConfigFile, &cfg.Kerberos.CCache} {
		*p, err = filepath.Rel(cwd, *p)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg.Kerberos.CCache = "FILE:" + cfg.Kerberos.CCache
	c, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Chdir(t.TempDir())
	c.nfs.mu.Lock()
	c.nfs.gss.seq = 0x7ffffffe
	c.nfs.mu.Unlock()
	if _, err := c.Mount(context.Background(), "/data"); err != nil {
		t.Fatal(err)
	}
	if c.KerberosRenewals() != 1 {
		t.Fatal("sequence exhaustion did not renew via pinned paths")
	}
}

// These require no realm. Expiry during an RPC still closes permanently;
// installing a renewal configuration cannot turn the failed call into a replay.
func TestKerberosFailedRPCNeverRenews(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &rpcClient{conn: a, timeout: time.Second, gss: &rpcGSS{context: testMIC{}, established: true, expiry: time.Now().Add(50 * time.Millisecond), renewAt: time.Now().Add(time.Hour)}, kerberos: &kerberosSession{}}
	seen := make(chan error, 1)
	go func() { _, err := readRecord(b); seen <- err }()
	if _, err := c.call(context.Background(), nfsProgram, 3, 7, nil, nil); err == nil {
		t.Fatal("expired in-flight WRITE succeeded")
	}
	if err := <-seen; err != nil {
		t.Fatal(err)
	}
	if !c.closed {
		t.Fatal("failed RPC left renewable session")
	}
	if _, err := c.call(context.Background(), nfsProgram, 3, 7, nil, nil); err == nil || !strings.Contains(err.Error(), "session closed") {
		t.Fatalf("request replayed: %v", err)
	}
	if c.gss.seq != 1 {
		t.Fatal("failed WRITE was sent again")
	}
}

func TestKerberosCloseCancelsLeaseRenewal(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires MIT fixture")
	}
	cfg := renewalFixtureConfig(t, "4.2", "krb5p", "keytab")
	conf, err := os.ReadFile(cfg.Kerberos.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Kerberos.ConfigFile = filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(cfg.Kerberos.ConfigFile, conf, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { l.Close(); <-done })
	go func() {
		defer close(done)
		peer, err := l.Accept()
		if err != nil {
			return
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(5 * time.Second))
		var prefix [4]byte
		if _, err := io.ReadFull(peer, prefix[:]); err != nil {
			return
		}
		close(seen)
		io.Copy(io.Discard, peer)
	}()
	conf = []byte(fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n udp_preference_limit = 1\n[realms]\n NFS.TEST = {\n kdc = %s\n }\n", l.Addr()))
	if err := os.WriteFile(cfg.Kerberos.ConfigFile, conf, 0600); err != nil {
		t.Fatal(err)
	}
	c.nfs.mu.Lock()
	c.nfs.gss.renewAt = time.Now()
	c.nfs.mu.Unlock()
	select {
	case <-seen:
	case <-time.After(4 * time.Second):
		t.Fatal("lease renewal did not reach KDC")
	}
	start := time.Now()
	c.Close()
	if time.Since(start) > time.Second {
		t.Fatal("Close waited for KDC timeout instead of canceling lease renewal")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("KDC socket survived Close")
	}
}
