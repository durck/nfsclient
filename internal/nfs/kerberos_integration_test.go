package nfs

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Corrupt real MIT/Ganesha tokens through a local RPC relay. This verifies that
// the client rejects cryptographic failures, not only synthetic MIC failures.
func TestKerberosTamperedServer(t *testing.T) {
	testKerberosTamperedServer(t, "auto")
}

func TestKerberosV4TamperedServer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_V4") != "1" {
		t.Skip("requires v4 Kerberos fixture")
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) { testKerberosTamperedServer(t, version) })
	}
}

func testKerberosTamperedServer(t *testing.T, version string) {
	port := os.Getenv("NFS_VIEWER_KRB5_PORT")
	if port == "" {
		t.Skip("requires tests/kerberos fixture")
	}
	mountPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"))
	if err != nil && (version == "auto" || version == "3") {
		t.Fatal(err)
	}
	for _, mode := range []string{"mutual-token", "window-signature", "data-signature"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				downstream, err := listener.Accept()
				if err != nil {
					return
				}
				defer downstream.Close()
				upstream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				downstream.SetDeadline(time.Now().Add(10 * time.Second))
				upstream.SetDeadline(time.Now().Add(10 * time.Second))
				for call := 0; call < 2; call++ {
					request, err := readRecord(downstream)
					if err != nil {
						return
					}
					if _, err = upstream.Write(record(request, true)); err != nil {
						return
					}
					reply, err := readRecord(upstream)
					if err != nil {
						return
					}
					if call == 0 && mode == "mutual-token" {
						d := &decoder{b: reply}
						d.take(12)
						d.u32()
						d.opaque(400)
						d.u32()
						d.opaque(380)
						d.take(12)
						token := d.opaque(1 << 20)
						if d.err != nil || len(token) == 0 {
							return
						}
						token[len(token)-1] ^= 1
					}
					if call == 0 && mode == "window-signature" || call == 1 && mode == "data-signature" {
						d := &decoder{b: reply}
						d.take(12)
						d.u32()
						mic := d.opaque(400)
						if d.err != nil || len(mic) == 0 {
							return
						}
						mic[len(mic)-1] ^= 1
					}
					if _, err = downstream.Write(record(reply, true)); err != nil {
						return
					}
				}
			}()
			cfg := Config{Host: "127.0.0.1", Version: version, Security: "krb5", Transport: "tcp", Timeout: 3 * time.Second,
				NFSPort: listener.Addr().(*net.TCPAddr).Port, MountPort: mountPort,
				Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			c, err := Connect(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("tampered authentication accepted")
			}
			want := "signature verification failed"
			if mode == "mutual-token" {
				want = "server authentication"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("did not reach cryptographic validation: %v", err)
			}
			listener.Close()
			<-done
		})
	}
}
