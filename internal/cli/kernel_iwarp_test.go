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

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func iwarpPayload() []byte {
	p := make([]byte, 1<<20+17)
	for i := range p {
		p[i] = byte((i*17 + i/251) % 256)
	}
	return p
}

func TestKernelIWARP(t *testing.T) {
	host := os.Getenv("NFS_IWARP_HOST")
	if host == "" {
		t.Skip("requires isolated software-iWARP NFS fixture")
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: version, Transport: "iwarp", Timeout: 10 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.Transport() != "iwarp" || c.ReadSize > 3044 || c.WriteSize > 3044 {
				t.Fatal("transport bounds", c.Transport(), c.ReadSize, c.WriteSize)
			}
			s := session.New(c, host, false, false, nil)
			if err := s.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			var seed bytes.Buffer
			if _, err := s.Cat(ctx, "seed", &seed); err != nil || seed.String() != "real software-iWARP NFS fixture\n" {
				t.Fatal(seed.String(), err)
			}
			name := fmt.Sprintf("iwarp-api-%s-%s", runtime.GOOS, version)
			local := filepath.Join(t.TempDir(), "source")
			payload := iwarpPayload()
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, local, name); err != nil {
				t.Fatal(err)
			}
			id, err := s.Lock(ctx, name, true)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if _, err := s.Cat(ctx, name, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
				t.Fatal("locked roundtrip", err, got.Len())
			}
			if _, err := c.Reconnect(ctx); err != nfs.ErrLocksHeld {
				t.Fatal("held-lock reconnect", err)
			}
			if err := c.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			fresh, err := c.Reconnect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			s = session.New(fresh, host, false, false, nil)
			if err := s.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			got.Reset()
			if _, err := s.Cat(ctx, name, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
				t.Fatal("reconnect roundtrip", err)
			}
			t.Logf("IWARP_API version=%s os=%s bytes=%d crc32c inline locked reconnect", version, runtime.GOOS, len(payload))
		})
	}
}

func TestKernelIWARPCLI(t *testing.T) {
	host := os.Getenv("NFS_IWARP_HOST")
	if host == "" {
		t.Skip("requires isolated software-iWARP NFS fixture")
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			source, target := filepath.Join(dir, "source"), filepath.Join(dir, "download")
			payload := iwarpPayload()
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("iwarp-cli-%s-%s", runtime.GOOS, version)
			args := []string{host, "--transport", "iwarp", "--nfs-version", version, "--export", "/data", "--uid", "25001", "--gid", "25000", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never", "--timeout", "10s"}
			for _, cmd := range []string{"put " + strconv.Quote(source) + " " + name, "lock " + name + " write", "get " + name + " " + strconv.Quote(target), "unlock 1", "reconnect", "stat " + name} {
				args = append(args, "-c", cmd)
			}
			out, err := runKerberosCLI(t, args)
			if err != nil {
				t.Fatal(err, out)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("CLI bytes", err, len(got))
			}
			t.Logf("IWARP_CLI version=%s os=%s bytes=%d locked reconnect", version, runtime.GOOS, len(payload))
		})
	}
}
