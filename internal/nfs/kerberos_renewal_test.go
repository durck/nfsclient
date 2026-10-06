package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"
)

// Keep a file open across the actual MIT service-ticket expiry, including
// NFSv4 OPEN state and background lease traffic. No wall-clock changes.
func TestKerberosRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires four-second MIT service tickets")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			if version == "3-udp" && security != "krb5" {
				continue
			}
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					t.Parallel()
					cfg := renewalFixtureConfig(t, version, security, credential)
					testKerberosRenewalTransfer(t, cfg)
				})
			}
		}
	}
}

func renewalFixtureConfig(t *testing.T, version, security, credential string) Config {
	t.Helper()
	p, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_PORT"))
	m, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"))
	cfg := Config{Host: "127.0.0.1", Version: version, Transport: "tcp", Security: security, Timeout: 3 * time.Second, NFSPort: p, MountPort: m,
		Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
	if version == "3-udp" {
		cfg.Version, cfg.Transport = "3", "udp"
		cfg.NFSPort, _ = strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"))
		cfg.MountPort, _ = strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
		if cfg.NFSPort == 0 || cfg.MountPort == 0 {
			t.Skip("requires UDP ports")
		}
	}
	if credential == "ccache" {
		cfg.Kerberos.Keytab, cfg.Kerberos.CCache = "", os.Getenv("NFS_VIEWER_KRB5_CCACHE")
		if cfg.Kerberos.CCache == "" {
			t.Skip("requires root FILE cache")
		}
	}
	return cfg
}

type expiryPauseReader struct {
	*bytes.Reader
	ctx   context.Context
	until time.Time
	reads int
}

func (r *expiryPauseReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 1 {
		p = p[:min(len(p), 4096)]
	}
	if r.reads == 2 {
		timer := time.NewTimer(max(0, time.Until(r.until)))
		defer timer.Stop()
		select {
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		case <-timer.C:
		}
	}
	return r.Reader.Read(p)
}

var _ io.Reader = (*expiryPauseReader)(nil)

func testKerberosRenewalTransfer(t *testing.T, cfg Config) {
	t.Helper()
	testKerberosRenewalTransferWithLifetime(t, cfg, 5*time.Second)
}

func testKerberosRenewalTransferWithLifetime(t *testing.T, cfg Config, maxLife time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), maxLife+13*time.Second)
	defer cancel()
	c, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	oldExpiry := c.KerberosExpiry()
	if left := time.Until(oldExpiry); left <= 0 || left > maxLife {
		t.Fatalf("wrong actual lifetime: %s", left)
	}
	root, err := c.Mount(ctx, "/data")
	if err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	file, err := c.Create(ctx, root.Handle, fmt.Sprintf("renew-%x", nonce), 0600, false)
	if err != nil {
		t.Fatal(err)
	}
	connection := c.nfs.conn
	var session []byte
	var clientID uint64
	if c.v4 != nil {
		c.v4.mu.Lock()
		session, clientID = bytes.Clone(c.v4.session), c.v4.clientID
		c.v4.mu.Unlock()
	}
	payload := bytes.Repeat([]byte{0, 255, 27, 'R'}, 10000)
	r := &expiryPauseReader{Reader: bytes.NewReader(payload), ctx: ctx, until: oldExpiry.Add(50 * time.Millisecond)}
	n, err := c.WriteFrom(ctx, file.Handle, r)
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("transfer across ticket expiry: %d %v", n, err)
	}
	var got bytes.Buffer
	if _, err := c.ReadTo(ctx, file.Handle, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("renewed content: %v", err)
	}
	if !c.KerberosExpiry().After(oldExpiry) || c.nfs.conn != connection || c.Identity() != cfg.Kerberos.Principal+" ("+cfg.Security+")" {
		t.Fatal("expiry, connection or identity not preserved")
	}
	if c.v4 != nil {
		c.v4.mu.Lock()
		unchanged := bytes.Equal(session, c.v4.session) && clientID == c.v4.clientID
		c.v4.mu.Unlock()
		if !unchanged {
			t.Fatal("renewal replaced NFSv4 state")
		}
	}
}
