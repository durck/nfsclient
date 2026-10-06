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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// A separate opt-in realm fixture limits service tickets to four seconds while
// the client configuration requests its normal lifetime. No wall-clock changes.
func TestKerberosShortLifetime(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires short-life MIT fixture")
	}
	nfsPort, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_PORT"))
	mountPort, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"))
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) {
			cfg := Config{Host: "127.0.0.1", Version: "3", Transport: "tcp", Security: security, Timeout: 3 * time.Second, NFSPort: nfsPort, MountPort: mountPort, Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			ctx := context.Background()
			c, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			remaining := time.Until(c.KerberosExpiry())
			if remaining <= 0 || remaining > 5*time.Second {
				t.Fatalf("not KDC-limited expiry: %s", remaining)
			}
			root, err := c.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			file, err := c.Create(ctx, root.Handle, fmt.Sprintf("expiry-%d", time.Now().UnixNano()), 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			timer := time.NewTimer(time.Until(c.KerberosExpiry()) + 20*time.Millisecond)
			<-timer.C
			payload := []byte("written once after context refresh")
			_, err = c.WriteFrom(ctx, file.Handle, bytes.NewReader(payload))
			if err != nil || c.KerberosRenewals() != 1 {
				t.Fatalf("refresh before expired operation: %v", err)
			}
			fresh, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			attr, err := fresh.GetAttr(ctx, file.Handle)
			if err != nil || attr.Size != uint64(len(payload)) {
				t.Fatalf("renewed write size=%d err=%v", attr.Size, err)
			}
		})
	}
}

func TestKerberosExpiryBeforeRequest(t *testing.T) {
	for _, service := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			c := &rpcClient{conn: a, timeout: time.Second, gss: &rpcGSS{context: testMIC{}, service: service, established: true, expiry: time.Now().Add(-time.Second)}}
			_, err := c.call(context.Background(), nfsProgram, 3, 7, nil, encoder{0, 0, 0, 0})
			if err == nil || !strings.Contains(err.Error(), "context expired") || c.gss.seq != 0 {
				t.Fatalf("expired WRITE: %v seq=%d", err, c.gss.seq)
			}
			b.SetReadDeadline(time.Now().Add(time.Second))
			var buf [1]byte
			n, err := b.Read(buf[:])
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("expired request reached server: n=%d err=%v", n, err)
			}
		})
	}
}

func TestKerberosExpiryBoundsInflightRequest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &rpcClient{conn: a, timeout: 10 * time.Second, gss: &rpcGSS{context: testMIC{}, established: true, expiry: time.Now().Add(100 * time.Millisecond)}}
	done := make(chan error, 1)
	go func() { b.SetDeadline(time.Now().Add(time.Second)); _, err := readRecord(b); done <- err }()
	start := time.Now()
	_, err := c.call(context.Background(), nfsProgram, 3, 7, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "context expired") || !strings.Contains(err.Error(), "outcome may be unknown") || time.Since(start) > time.Second {
		t.Fatalf("expiry did not bound RPC: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c.gss.verify(&decoder{}, c.gss.seq) == nil {
		t.Fatal("expired reply accepted")
	}
}

func TestKerberosSetupCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			seen := make(chan struct{})
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				conn, err := l.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				close(seen)
				io.Copy(io.Discard, conn)
			}()
			dir := t.TempDir()
			kt := keytab.New()
			if err := kt.AddEntry("root", "NFS.TEST", "synthetic-test-password", time.Now(), 1, 18); err != nil {
				t.Fatal(err)
			}
			kb, err := kt.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			k := KerberosConfig{ConfigFile: filepath.Join(dir, "krb5.conf"), Keytab: filepath.Join(dir, "client.keytab"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}
			conf := fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n dns_lookup_kdc = false\n udp_preference_limit = 1\n[realms]\n NFS.TEST = {\n kdc = %s\n }\n", l.Addr())
			if err := os.WriteFile(k.Keytab, kb, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(k.ConfigFile, []byte(conf), 0600); err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			c := &rpcClient{conn: a, timeout: 150 * time.Millisecond}
			if mode == "cancel" {
				c.timeout = 10 * time.Second
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := c.establishKerberos(ctx, k, "krb5p", 3); result <- err }()
			select {
			case <-seen:
			case <-time.After(time.Second):
				t.Fatal("login did not reach fake KDC")
			}
			want := context.DeadlineExceeded
			if mode == "cancel" {
				cancel()
				want = context.Canceled
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("want %v, got %v", want, err)
				}
			case <-time.After(time.Second):
				t.Fatal("Kerberos setup ignored cancellation/timeout")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("KDC socket leaked after setup failure")
			}
		})
	}
}
