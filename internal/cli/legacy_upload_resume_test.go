package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/session"
)

func TestLegacyUploadResume(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LEGACY_RESUME") != "1" {
		t.Skip("requires disposable FreeBSD NLM export")
	}
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(version+"/"+transport, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				cfg := retainedNLMConfig(t, version, transport, "resume-api-"+version+"-"+transport)
				s := retainedNLMSession(t, cfg)
				c := s.Client
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
				name := fmt.Sprintf("reput-api-%s-%s-%s-%d", runtime.GOOS, version, transport, time.Now().UnixNano())
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
						stop()
					}
				})
				stop()
				if err == nil || !cut || n < 196608 || n >= int64(len(payload)) {
					t.Fatal("upload interruption", n, cut, err)
				}
				if err := c.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				c.Close()
				s = retainedNLMSession(t, cfg)
				id, err = s.Lock(ctx, name, true)
				if err != nil {
					t.Fatal(err)
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
				t.Logf("LEGACY_RESUME platform=%s version=%s transport=%s file=%s bytes=%d prefix_change_refusals interruption explicit_reconnect_relock final_bytes_verified", runtime.GOOS, version, transport, name, len(payload))
				s.Client.Close()
				s = retainedNLMSession(t, cfg)
				empty := filepath.Join(dir, "empty")
				if err := os.WriteFile(empty, nil, 0600); err != nil {
					t.Fatal(err)
				}
				emptyName := name + "-empty"
				if _, err := s.Put(ctx, empty, emptyName); err != nil {
					t.Fatal(err)
				}
				id, err = s.Lock(ctx, emptyName, true)
				if err != nil {
					t.Fatal(err)
				}
				if n, err := s.PutResume(ctx, empty, emptyName, nil); err != nil || n != 0 {
					t.Fatal("empty complete", n, err)
				}
				if version == "2" {
					huge := filepath.Join(dir, "huge")
					f, err := os.Create(huge)
					if err != nil {
						t.Fatal(err)
					}
					err = f.Truncate(1 << 31)
					f.Close()
					if err != nil {
						t.Fatal(err)
					}
					if n, err := s.PutResume(ctx, huge, emptyName, nil); err == nil || n != 0 {
						t.Fatal("v2 local size limit", n, err)
					}
				}
				if n, err := s.PutResume(ctx, full, emptyName, nil); err != nil || n != int64(len(payload)) {
					t.Fatal("empty prefix", n, err)
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				s.Client.Close()

			})
		}
	}
}
func TestLegacyUploadResumeCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LEGACY_RESUME") != "1" {
		t.Skip("requires disposable FreeBSD NLM export")
	}
	if os.Getenv("NFS_VIEWER_TEST_BINARY") == "" {
		t.Fatal("standalone binary required")
	}
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(version+"/"+transport, func(t *testing.T) {
				dir := t.TempDir()
				full, part, out := filepath.Join(dir, "full"), filepath.Join(dir, "part"), filepath.Join(dir, "result")
				payload := uploadResumePayload()
				if err := os.WriteFile(full, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(part, payload[:131072], 0600); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("reput-cli-%s-%s-%s-%d", runtime.GOOS, version, transport, time.Now().UnixNano())
				cfg := retainedNLMConfig(t, version, transport, "resume-cli-"+version+"-"+transport)
				args := []string{cfg.Host, "--nfs-version", version, "--transport", transport, "--export", os.Getenv("NFS_VIEWER_NLM_EXPORT"), "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--no-banner", "--progress", "never", "--color", "never", "--nlm-client-ip", cfg.NLMClientIP, "--nlm-state-dir", cfg.NLMStateDir}
				if cfg.NLMListenIP != "" {
					args = append(args, "--nlm-listen-ip", cfg.NLMListenIP)
				}
				for _, cmd := range []string{"put " + strconv.Quote(part) + " " + name, "lock " + name + " write", "reput " + strconv.Quote(full) + " " + name, "get " + name + " " + strconv.Quote(out), "unlock 1"} {
					args = append(args, "-c", cmd)
				}
				if output, err := runKerberosCLI(t, args); err != nil {
					t.Fatal(err, output)
				}
				if b, err := os.ReadFile(out); err != nil || !bytes.Equal(b, payload) {
					t.Fatal("CLI resumed bytes", err)
				}
				t.Logf("LEGACY_RESUME_CLI platform=%s version=%s transport=%s file=%s bytes=%d prefix_verified_append", runtime.GOOS, version, transport, name, len(payload))
			})
		}
	}
}
