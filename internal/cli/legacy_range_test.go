package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"nfsclient/internal/nfs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func legacyRangeFiles(t *testing.T) (string, string, string, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	full, patch, out := filepath.Join(dir, "full"), filepath.Join(dir, "patch"), filepath.Join(dir, "out")
	payload := copySource()[:131072]
	change := bytes.Repeat([]byte{0xa5}, 65536)
	if err := os.WriteFile(full, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patch, change, 0600); err != nil {
		t.Fatal(err)
	}
	return full, patch, out, payload, change
}

func TestLegacyRange(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LEGACY_RANGE") != "1" {
		t.Skip("requires disposable FreeBSD retained NLM fixture")
	}
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(version+"/"+transport, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				cfg := retainedNLMConfig(t, version, transport, "range-api-"+version+"-"+transport)
				s := retainedNLMSession(t, cfg)
				full, patch, out, payload, change := legacyRangeFiles(t)
				name := fmt.Sprintf("range-api-%s-%s-%s-%d", runtime.GOOS, version, transport, time.Now().UnixNano())
				if _, err := s.Put(ctx, full, name); err != nil {
					t.Fatal(err)
				}
				if _, err := s.GetRange(ctx, name, out, 0, 16, nil); err == nil {
					t.Fatal("missing lock accepted")
				}
				readID, err := s.LockRange(ctx, name, false, 0, 16384)
				if err != nil {
					t.Fatal(err)
				}
				writeID, err := s.LockRange(ctx, name, true, 16384, 65536)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.GetRange(ctx, name, out, 0, 32768, nil); err == nil {
					t.Fatal("joined adjacent locks")
				}
				if _, err := s.PutRange(ctx, patch, name, 0, nil); err == nil {
					t.Fatal("wrote through read lock")
				}
				if _, err := s.Cat(ctx, name, io.Discard); !errors.Is(err, nfs.ErrPartialLockIO) {
					t.Fatal("ordinary read accepted", err)
				}
				if _, err := s.GetRange(ctx, name, out, 0, 16384, nil); err != nil {
					t.Fatal(err)
				}
				if data, err := os.ReadFile(out); err != nil || !bytes.Equal(data, payload[:16384]) {
					t.Fatal("read bytes", err)
				}
				cancelCtx, stop := context.WithCancel(ctx)
				_, err = s.GetRange(cancelCtx, name, out+"-cancel", 16384, 65536, func(done, total uint64) {
					if done > 0 {
						stop()
					}
				})
				stop()
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled download", err)
				}
				if _, err := os.Stat(out + "-cancel"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("published cancelled range", err)
				}
				if _, err := s.PutRange(ctx, patch, name, 16385, nil); err == nil {
					t.Fatal("crossed write boundary")
				}
				if n, err := s.PutRange(ctx, patch, name, 16384, nil); err != nil || n != 65536 {
					t.Fatal("range write", n, err)
				}
				if _, err := s.GetRange(ctx, name, out+"-patch", 16384, 65536, nil); err != nil {
					t.Fatal(err)
				}
				if data, err := os.ReadFile(out + "-patch"); err != nil || !bytes.Equal(data, change) {
					t.Fatal("patch bytes", err)
				}
				if err := s.Client.Unlock(ctx, readID); err != nil {
					t.Fatal(err)
				}
				if _, err := s.GetRange(ctx, name, out+"-released", 0, 16, nil); err == nil {
					t.Fatal("released lock reused")
				}
				if err := s.Client.Unlock(ctx, writeID); err != nil {
					t.Fatal(err)
				}
				copy(payload[16384:81920], change)
				var got bytes.Buffer
				if _, err := s.Cat(ctx, name, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
					t.Fatal("outside range changed", err)
				}
				t.Logf("LEGACY_RANGE platform=%s version=%s transport=%s file=%s bytes=%d", runtime.GOOS, version, transport, name, len(payload))
			})
		}
	}
}

func TestLegacyRangeCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LEGACY_RANGE") != "1" {
		t.Skip("requires disposable FreeBSD retained NLM fixture")
	}
	if os.Getenv("NFS_VIEWER_TEST_BINARY") == "" {
		t.Fatal("standalone binary required")
	}
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(version+"/"+transport, func(t *testing.T) {
				cfg := retainedNLMConfig(t, version, transport, "range-cli-"+version+"-"+transport)
				full, patch, out, payload, change := legacyRangeFiles(t)
				name := fmt.Sprintf("range-cli-%s-%s-%s-%d", runtime.GOOS, version, transport, time.Now().UnixNano())
				args := []string{cfg.Host, "--nfs-version", version, "--transport", transport, "--export", os.Getenv("NFS_VIEWER_NLM_EXPORT"), "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--no-banner", "--progress", "never", "--color", "never", "--nlm-client-ip", cfg.NLMClientIP, "--nlm-state-dir", cfg.NLMStateDir}
				if cfg.NLMListenIP != "" {
					args = append(args, "--nlm-listen-ip", cfg.NLMListenIP)
				}
				for _, cmd := range []string{"put " + strconv.Quote(full) + " " + name, "lock " + name + " read 0 16384", "lock " + name + " write 16384 65536", "getrange " + name + " " + strconv.Quote(out+"-prefix") + " 0 16384", "putrange " + strconv.Quote(patch) + " " + name + " 16384", "unlock 1", "unlock 2", "get " + name + " " + strconv.Quote(out)} {
					args = append(args, "-c", cmd)
				}
				if output, err := runKerberosCLI(t, args); err != nil {
					t.Fatal(err, output)
				}
				if data, err := os.ReadFile(out + "-prefix"); err != nil || !bytes.Equal(data, payload[:16384]) {
					t.Fatal("CLI prefix", err)
				}
				copy(payload[16384:81920], change)
				if data, err := os.ReadFile(out); err != nil || !bytes.Equal(data, payload) {
					t.Fatal("CLI bytes", err)
				}
				t.Logf("LEGACY_RANGE_CLI platform=%s version=%s transport=%s file=%s bytes=%d", runtime.GOOS, version, transport, name, len(payload))
			})
		}
	}
}

func TestLegacyRangeLoss(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LEGACY_RANGE_LOSS") != "1" {
		t.Skip("requires coordinated fixture statd restart")
	}
	cfg := retainedNLMConfig(t, "3", "tcp", "range-loss")
	s := retainedNLMSession(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	full, _, _, payload, _ := legacyRangeFiles(t)
	name := "range-loss-" + runtime.GOOS
	if _, err := s.Put(ctx, full, name); err != nil {
		t.Fatal(err)
	}
	id, err := s.LockRange(ctx, name, true, 16384, 65536)
	if err != nil {
		t.Fatal(err)
	}
	fh, err := s.Client.LockedFileHandle(id)
	if err != nil {
		t.Fatal(err)
	}
	marker := os.Getenv("NFS_VIEWER_NLM_MARKER")
	if marker == "" {
		t.Fatal("coordination marker required")
	}
	if err := os.WriteFile(marker, []byte("READY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for !s.Client.Locks()[0].Uncertain && ctx.Err() == nil {
		time.Sleep(25 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("statd restart not observed")
	}
	var out bytes.Buffer
	if n, err := s.Client.ReadRangeToProgress(ctx, fh, 16384, 16, &out, nil); !errors.Is(err, nfs.ErrLockUncertain) || n != 0 || out.Len() != 0 {
		t.Fatal("read after loss", n, err)
	}
	if n, err := s.Client.WriteRangeFromProgress(ctx, fh, 16384, 16, bytes.NewReader(bytes.Repeat([]byte{0xff}, 16)), nil); !errors.Is(err, nfs.ErrLockUncertain) || n != 0 {
		t.Fatal("write after loss", n, err)
	}
	s.Client.Close()
	fresh := retainedNLMSession(t, cfg)
	if n, err := fresh.Client.RecoverNLMLocks(ctx); err != nil || n != 1 {
		t.Fatal("saved owner cleanup", n, err)
	}
	id, err = fresh.LockRange(ctx, name, true, 16384, 65536)
	if err != nil {
		t.Fatal(err)
	}
	fh, err = fresh.Client.LockedFileHandle(id)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := fresh.Client.ReadRangeToProgress(ctx, fh, 16384, 16, &out, nil); err != nil || n != 16 || !bytes.Equal(out.Bytes(), payload[16384:16400]) {
		t.Fatal("fresh protected read", n, err)
	}
	if err := fresh.Client.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Logf("LEGACY_RANGE_LOSS platform=%s file=%s read_write_refused explicit_cleanup fresh_range_verified", runtime.GOOS, name)
}
