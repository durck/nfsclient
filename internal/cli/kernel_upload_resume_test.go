package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func uploadResumePayload() []byte {
	return append(bytes.Repeat(copySource(), 4), []byte("upload-resume-end!")...)
}

func TestKernelUploadResume(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			relay := newDownloadRelayTarget(t, net.JoinHostPort(host, "2049"))
			c, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", NFSPort: relay.port(), Version: version, Timeout: 15 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}})
			if err != nil {
				t.Fatal(err)
			}
			s := session.New(c, "127.0.0.1", false, false, nil)
			t.Cleanup(func() { s.Client.Close() })
			if err := s.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			c.ReadSize = 32768
			c.WriteSize = 32768
			dir := t.TempDir()
			full, part, bad := filepath.Join(dir, "full"), filepath.Join(dir, "part"), filepath.Join(dir, "bad")
			payload := uploadResumePayload()
			for _, p := range []struct {
				name string
				data []byte
			}{{full, payload}, {part, payload[:131072]}, {bad, bytes.Repeat([]byte{'!'}, len(payload))}} {
				if err := os.WriteFile(p.name, p.data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			name := fmt.Sprintf("reput-api-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			if _, err := s.Put(ctx, part, name); err != nil {
				t.Fatal(err)
			}
			if _, err := s.PutResume(ctx, full, name, nil); err == nil {
				t.Fatal("resume without lock accepted")
			}
			id, err := s.Lock(ctx, name, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.PutResume(ctx, full, name, nil); err == nil {
				t.Fatal("read lock accepted")
			}
			if err := c.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			id, err = s.Lock(ctx, name, true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.PutResume(ctx, bad, name, nil); !errors.Is(err, session.ErrUploadPrefix) {
				t.Fatal("prefix mismatch", err)
			}
			changed := false
			_, err = s.PutResume(ctx, full, name, func(done, total uint64) {
				if done > 0 && !changed {
					changed = true
					if err := os.Chtimes(full, time.Now(), time.Now().Add(time.Hour)); err != nil {
						t.Error(err)
					}
				}
			})
			if !changed || !errors.Is(err, session.ErrUploadSourceChanged) {
				t.Fatal("local change accepted", err)
			}
			before, _, err := s.Resolve(ctx, name, false)
			if err != nil || before.Attr.Size != 131072 {
				t.Fatal("failed verification appended bytes", before.Attr.Size, err)
			}
			interrupted, stop := context.WithCancel(ctx)
			cut := false
			n, err := s.PutResume(interrupted, full, name, func(done, total uint64) {
				if done >= 196608 && done < total && !cut {
					cut = true
					if version == "4.1" {
						relay.cut()
					} else {
						stop()
					}
				}
			})
			stop()
			if err == nil || !cut || n < 196608 || n >= int64(len(payload)) {
				t.Fatal("upload interruption", n, cut, err)
			}
			if version == "4.1" {
				var transport *net.OpError
				if !errors.Is(err, nfs.ErrConnectionLost) && !errors.As(err, &transport) {
					t.Fatal("real encrypted disconnect", err)
				}
				if len(c.Locks()) != 1 || !c.Locks()[0].Uncertain {
					t.Fatal("lost lock not retained uncertain")
				}
				if err := s.Reconnect(ctx); !errors.Is(err, nfs.ErrLocksHeld) {
					t.Fatal("silent lock discard", err)
				}
				c.DiscardLocks()
			} else {
				if err := c.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Reconnect(ctx); err != nil {
				t.Fatal(err)
			}
			if !s.Client.TLSActive() || !s.Client.TLSCertificateVerified() {
				t.Fatal("TLS policy lost")
			}
			// The old disconnected owner may retain its lock until lease expiry.
			deadline := time.Now().Add(75 * time.Second)
			for {
				id, err = s.Lock(ctx, name, true)
				if err == nil {
					break
				}
				if !errors.Is(err, nfs.Status(10010)) || time.Now().After(deadline) {
					t.Fatal("new lock acquisition", err)
				}
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if n, err := s.PutResume(ctx, full, name, nil); err != nil || n != int64(len(payload)) {
				t.Fatal("resumed upload", n, err)
			}
			if n, err := s.PutResume(ctx, full, name, nil); err != nil || n != int64(len(payload)) {
				t.Fatal("already complete", n, err)
			}
			var got bytes.Buffer
			if _, err := s.Cat(ctx, name, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
				t.Fatal("resumed bytes", err)
			}
			if err := s.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			t.Logf("UPLOAD_RESUME platform=%s version=%s bytes=%d prefix_change_refusals interruption explicit_reconnect_relock final_bytes_verified", runtime.GOOS, version, len(payload))
		})
	}
}

func TestKernelUploadResumeCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			full, part, out := filepath.Join(dir, "full"), filepath.Join(dir, "part"), filepath.Join(dir, "result")
			payload := uploadResumePayload()
			if err := os.WriteFile(full, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(part, payload[:131072], 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("reput-cli-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			args := []string{host, "--nfs-version", version, "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "15s"}
			for _, cmd := range []string{"put " + strconv.Quote(part) + " " + name, "lock " + name + " write", "reput " + strconv.Quote(full) + " " + name, "get " + name + " " + strconv.Quote(out), "unlock 1"} {
				args = append(args, "-c", cmd)
			}
			if output, err := runKerberosCLI(t, args); err != nil {
				t.Fatal(err, output)
			}
			if b, err := os.ReadFile(out); err != nil || !bytes.Equal(b, payload) {
				t.Fatal("CLI resumed bytes", err)
			}
			t.Logf("UPLOAD_RESUME_CLI platform=%s version=%s bytes=%d prefix_verified_append", runtime.GOOS, version, len(payload))
		})
	}
}
