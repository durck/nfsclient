package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func mtlsFixture(t *testing.T) (string, string, string) {
	t.Helper()
	if os.Getenv("NFS_VIEWER_KERNEL_MTLS") != "1" {
		t.Skip("requires isolated --mtls kernel fixture")
	}
	host, ca := kernelTLSFixture(t)
	credentials := os.Getenv("NFS_VIEWER_MTLS_CREDENTIALS")
	if credentials == "" {
		t.Fatal("explicit private fixture credential directory required")
	}
	return host, ca, credentials
}

func TestKernelMutualTLS(t *testing.T) {
	host, ca, credentials := mtlsFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			base := nfs.Config{Host: host, Version: version, Timeout: 5 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}}
			for _, denial := range []string{"absent", "absent-insecure", "expired", "plaintext"} {
				cfg := base
				if denial == "absent-insecure" {
					cfg.TLS.CAFile = ""
					cfg.TLS.InsecureSkipVerify = true
				}
				if denial == "expired" {
					cfg.TLS.CertFile = filepath.Join(credentials, "expired.crt")
					cfg.TLS.KeyFile = filepath.Join(credentials, "expired.key")
				}
				if denial == "plaintext" {
					cfg.TLS = nfs.TLSConfig{}
				}
				c, err := nfs.Connect(ctx, cfg)
				if err == nil {
					s := session.New(c, host, false, false, nil)
					err = s.Use(ctx, "/data")
					c.Close()
				}
				if err == nil {
					t.Fatal("mTLS export accepted", denial)
				}
				t.Logf("MUTUAL_TLS_DENIAL platform=%s version=%s case=%s", runtime.GOOS, version, denial)
			}
			for _, insecure := range []bool{false, true} {
				cfg := base
				cfg.TLS.CertFile = filepath.Join(credentials, "client.crt")
				cfg.TLS.KeyFile = filepath.Join(credentials, "client.key")
				if insecure {
					cfg.TLS.CAFile = ""
					cfg.TLS.ServerName = "wrong.test"
					cfg.TLS.InsecureSkipVerify = true
				}
				c, err := nfs.Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(c, host, false, false, nil)
				t.Cleanup(func() { s.Client.Close() })
				if err := s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("mtls-api-%s-%s-%t-%d", runtime.GOOS, version, insecure, time.Now().UnixNano())
				local := filepath.Join(t.TempDir(), "source")
				payload := bytes.Repeat([]byte("mutual TLS fixture\x00"), 4096)
				if err := os.WriteFile(local, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Put(ctx, local, name); err != nil {
					t.Fatal(err)
				}
				if err := s.Reconnect(ctx); err != nil {
					t.Fatal(err)
				}
				if !s.Client.TLSActive() || s.Client.TLSCertificateVerified() == insecure {
					t.Fatal("reconnect changed TLS policy")
				}
				id, err := s.Lock(ctx, name, false)
				if err != nil {
					t.Fatal(err)
				}
				var got bytes.Buffer
				if _, err := s.Cat(ctx, name, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
					t.Fatal("mTLS readback", err)
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				t.Logf("MUTUAL_TLS platform=%s version=%s insecure=%t bytes=%d reconnect lock bytes_verified", runtime.GOOS, version, insecure, len(payload))
			}
		})
	}
}

func TestKernelMutualTLSCLI(t *testing.T) {
	host, ca, credentials := mtlsFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			base := []string{host, "--nfs-version", version, "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--no-banner", "--progress", "never", "--color", "never", "--timeout", "5s", "--tls", "--tls-ca", ca}
			for _, denial := range []string{"absent", "expired", "absent-insecure"} {
				a := append([]string(nil), base...)
				if denial == "expired" {
					a = append(a, "--tls-cert", filepath.Join(credentials, "expired.crt"), "--tls-key", filepath.Join(credentials, "expired.key"))
				}
				if denial == "absent-insecure" {
					a = append(a, "--tls-insecure")
				}
				if out, err := runKerberosCLI(t, append(a, "-c", "ls")); err == nil {
					t.Fatal("CLI mTLS denial missing", denial, out)
				}
			}
			name := fmt.Sprintf("mtls-cli-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			dir := t.TempDir()
			source, destination := filepath.Join(dir, "source"), filepath.Join(dir, "result")
			payload := bytes.Repeat([]byte("mutual TLS fixture\x00"), 4096)
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			a := append(base, "--tls-cert", filepath.Join(credentials, "client.crt"), "--tls-key", filepath.Join(credentials, "client.key"))
			for _, cmd := range []string{"put " + strconv.Quote(source) + " " + name, "reconnect", "get " + name + " " + strconv.Quote(destination)} {
				a = append(a, "-c", cmd)
			}
			if out, err := runKerberosCLI(t, a); err != nil {
				t.Fatal(err, out)
			}
			if b, err := os.ReadFile(destination); err != nil || !bytes.Equal(b, payload) {
				t.Fatal("CLI mTLS bytes", err)
			}
			t.Logf("MUTUAL_TLS_CLI platform=%s version=%s bytes=%d credential_denials reconnect bytes_verified", runtime.GOOS, version, len(payload))
		})
	}
}
