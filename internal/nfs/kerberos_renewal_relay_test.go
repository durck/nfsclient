package nfs

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestKerberosRenewalRejectsTampering(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires MIT fixture")
	}
	for _, mode := range []string{"mutual-token", "window-signature", "destroy-reply-lost"} {
		t.Run(mode, func(t *testing.T) {
			cfg := renewalFixtureConfig(t, "3", "krb5p", "keytab")
			observerConfig := cfg
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var injected atomic.Bool
			var dataAfter atomic.Int32
			t.Cleanup(func() { l.Close(); <-done })
			go func() {
				defer close(done)
				down, err := l.Accept()
				if err != nil {
					return
				}
				defer down.Close()
				up, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(observerConfig.NFSPort)), time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				defer up.Close()
				down.SetDeadline(time.Now().Add(10 * time.Second))
				up.SetDeadline(time.Now().Add(10 * time.Second))
				inits := 0
				for {
					req, err := readRecord(down)
					if err != nil {
						return
					}
					d := &decoder{b: req}
					d.take(24)
					if d.u32() != 6 {
						t.Error("renewal downgraded RPC authentication")
						return
					}
					cred := &decoder{b: d.opaque(400)}
					cred.u32()
					control := cred.u32()
					if d.err != nil || cred.err != nil {
						t.Error("bad renewal credential")
						return
					}
					if control == 1 {
						inits++
					}
					if control == 0 && injected.Load() {
						dataAfter.Add(1)
					}
					if _, err = up.Write(record(req, true)); err != nil {
						return
					}
					reply, err := readRecord(up)
					if err != nil {
						return
					}
					if control == 1 && inits == 2 && mode != "destroy-reply-lost" {
						d = &decoder{b: reply}
						d.take(12)
						d.u32()
						mic := d.opaque(400)
						if mode == "window-signature" {
							if len(mic) == 0 {
								t.Error("missing INIT verifier")
								return
							}
							mic[len(mic)-1] ^= 1
						} else {
							d.u32()
							d.opaque(380)
							d.take(12)
							token := d.opaque(1 << 20)
							if d.err != nil || len(token) == 0 {
								t.Error("missing AP_REP")
								return
							}
							token[len(token)-1] ^= 1
						}
						injected.Store(true)
					}
					if control == 3 && inits == 2 && mode == "destroy-reply-lost" {
						injected.Store(true)
						continue
					}
					if _, err = down.Write(record(reply, true)); err != nil {
						return
					}
				}
			}()
			cfg.NFSPort = l.Addr().(*net.TCPAddr).Port
			c, err := Connect(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			root, err := c.Mount(context.Background(), "/data")
			if err != nil {
				t.Fatal(err)
			}
			file, err := c.Create(context.Background(), root.Handle, fmt.Sprintf("renew-relay-%s-%d", mode, time.Now().UnixNano()), 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			c.nfs.mu.Lock()
			c.nfs.gss.renewAt = time.Now()
			c.nfs.mu.Unlock()
			_, err = c.WriteFrom(context.Background(), file.Handle, bytes.NewReader([]byte("must not arrive")))
			if err == nil || !strings.Contains(err.Error(), "pending NFS request not sent") || !injected.Load() {
				t.Fatalf("tampering not rejected: %v", err)
			}
			if mode == "mutual-token" && !strings.Contains(err.Error(), "server authentication") || mode == "window-signature" && !strings.Contains(err.Error(), "signature verification failed") {
				t.Fatalf("wrong verification error: %v", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("renewal connection not closed")
			}
			if dataAfter.Load() != 0 {
				t.Fatal("NFS request followed failed renewal")
			}
			observer, err := Connect(context.Background(), observerConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close()
			attr, err := observer.GetAttr(context.Background(), file.Handle)
			if err != nil || attr.Size != 0 {
				t.Fatalf("mutation changed data: %v size=%d", err, attr.Size)
			}
		})
	}
}
