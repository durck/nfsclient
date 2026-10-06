package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func pnfsFixture(t *testing.T) (host string, port int, advertised, target string) {
	t.Helper()
	host = os.Getenv("NFS_VIEWER_PNFS_HOST")
	if host == "" {
		t.Skip("disposable pNFS fixture not selected")
	}
	var err error
	port, err = strconv.Atoi(os.Getenv("NFS_VIEWER_PNFS_PORT"))
	if err != nil || port < 1 || port > 65535 {
		t.Fatal("invalid fixture port")
	}
	advertised, target = os.Getenv("NFS_VIEWER_PNFS_ADVERTISED"), os.Getenv("NFS_VIEWER_PNFS_TARGET")
	if advertised == "" || target == "" {
		t.Fatal("explicit DS mapping required")
	}
	return
}

func pnfsPayload() []byte {
	b := make([]byte, (1<<20)+17)
	for i := range b {
		b[i] = byte((i*31 + i/251) % 256)
	}
	return b
}

func pnfsFixtureExport() string {
	if export := os.Getenv("NFS_VIEWER_PNFS_EXPORT"); export != "" {
		return export
	}
	return "/data"
}

func pnfsSession(t *testing.T, ctx context.Context, version string) *session.Session {
	t.Helper()
	host, port, _, _ := pnfsFixture(t)
	c, err := nfs.Connect(ctx, nfs.Config{Host: host, NFSPort: port, Version: version, PNFS: true, Timeout: 3 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}})
	if err != nil {
		t.Fatal(err)
	}
	s := session.New(c, host, false, false, nil)
	t.Cleanup(func() { s.Client.Close() })
	if err := s.Use(ctx, pnfsFixtureExport()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGlusterPNFS(t *testing.T) {
	_, _, advertised, target := pnfsFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			s := pnfsSession(t, ctx, version)
			other := pnfsSession(t, ctx, version)
			payload := pnfsPayload()
			local := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("pnfs-api-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			if _, err := s.Put(ctx, local, name); err != nil {
				t.Fatal(err)
			}
			o := nfs.PNFSOptions{DataServers: map[string]string{advertised: target}, Parallelism: 8}
			check := func(label string, options nfs.PNFSOptions, progress session.TransferProgress, wantError bool) {
				t.Helper()
				dir := t.TempDir()
				dest := filepath.Join(dir, "result")
				n, err := s.GetPNFS(ctx, name, dest, options, progress)
				if wantError {
					if err == nil {
						t.Fatal(label, "expected refusal")
					}
					if strings.HasPrefix(label, "changed-") && !errors.Is(err, session.ErrDownloadSourceChanged) {
						t.Fatal(label, "expected source-verification refusal", err)
					}
					if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
						t.Fatal(label, "published failed download", err)
					}
				} else {
					b, readErr := os.ReadFile(dest)
					if err != nil || readErr != nil || n != int64(len(payload)) || !bytes.Equal(b, payload) {
						t.Fatal(label, n, err, readErr)
					}
				}
				left, err := filepath.Glob(filepath.Join(dir, ".nfs-download-*"))
				if err != nil || len(left) != 0 {
					t.Fatal(label, "temporary leak", left, err)
				}
			}
			check("parallel-option", o, nil, false)
			sequential := o
			sequential.Parallelism = 1
			check("sequential", sequential, nil, false)
			id, err := s.Lock(ctx, name, false)
			if err != nil {
				t.Fatal(err)
			}
			check("held", o, nil, false)
			if len(s.Client.Locks()) != 1 || s.Client.Locks()[0].Uncertain {
				t.Fatal("DS teardown lost MDS lock")
			}
			if _, err := other.Lock(ctx, name, true); !errors.Is(err, nfs.Status(10010)) {
				t.Fatal("lock contention lost", err)
			}
			if err := s.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			id, err = s.LockRange(ctx, name, false, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			check("partial-lock", o, nil, true)
			if err := s.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			check("unapproved", nfs.PNFSOptions{DataServers: map[string]string{"192.0.2.254:1": target}}, nil, true)
			check("after-refusal", o, nil, false)
			collision := filepath.Join(t.TempDir(), "existing")
			if err := os.WriteFile(collision, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetPNFS(ctx, name, collision, o, nil); !errors.Is(err, session.ErrDestinationExists) {
				t.Fatal("collision", err)
			}
			if got, err := os.ReadFile(collision); err != nil || string(got) != "keep" {
				t.Fatal("collision changed destination", err)
			}
			// Cancel only after real DS bytes arrive, then verify session reuse.
			cctx, ccancel := context.WithCancel(ctx)
			cancelDest := filepath.Join(t.TempDir(), "cancelled")
			n, err := s.GetPNFS(cctx, name, cancelDest, o, func(done, total uint64) {
				if done > 0 {
					ccancel()
				}
			})
			ccancel()
			if err == nil || n == 0 || n >= int64(len(payload)) {
				t.Fatal("cancellation", n, err)
			}
			if _, err := os.Stat(cancelDest); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancelled publication", err)
			}
			check("after-cancel", o, nil, false)
			// Change observable metadata through an independent client mid-read.
			changed := false
			check("changed-source", o, func(done, total uint64) {
				if done > 0 && !changed {
					changed = true
					if err := other.Chmod(ctx, name, 0640); err != nil {
						t.Fatal(err)
					}
				}
			}, true)
			if !changed {
				t.Fatal("source-change hook not reached")
			}
			changed = false
			remoteNode, _, err := other.Resolve(ctx, name, true)
			if err != nil {
				t.Fatal(err)
			}
			check("changed-content", o, func(done, total uint64) {
				if done > 0 && !changed {
					changed = true
					modified := bytes.Repeat([]byte{0x5a}, len(payload))
					if n, err := other.Client.WriteFrom(ctx, remoteNode.Handle, bytes.NewReader(modified)); err != nil || n != int64(len(payload)) {
						t.Fatal("concurrent write", n, err)
					}
				}
			}, true)
			if !changed {
				t.Fatal("content-change hook not reached")
			}
			if n, err := other.Client.WriteFrom(ctx, remoteNode.Handle, bytes.NewReader(payload)); err != nil || n != int64(len(payload)) {
				t.Fatal("restore test source", n, err)
			}
			// A DS transport cut must not trigger another connection or MDS READ.
			relay, cut, connections := pnfsRelay(t, target)
			cutOnce := false
			check("DS-disconnect", nfs.PNFSOptions{DataServers: map[string]string{advertised: relay}, Parallelism: 8}, func(done, total uint64) {
				if done > 0 && !cutOnce {
					cutOnce = true
					cut()
				}
			}, true)
			if !cutOnce || connections() != 1 {
				t.Fatal("DS replay or unused relay", connections())
			}
			check("after-DS-disconnect", o, nil, false)
			if err := s.Reconnect(ctx); err != nil {
				t.Fatal(err)
			}
			check("reconnect", o, nil, false)
			empty := filepath.Join(t.TempDir(), "empty")
			if err := os.WriteFile(empty, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, empty, name+"-empty"); err != nil {
				t.Fatal(err)
			}
			if n, err := s.GetPNFS(ctx, name+"-empty", empty+"-out", o, nil); err != nil || n != 0 {
				t.Fatal("empty", n, err)
			}
			t.Logf("PNFS_API platform=%s version=%s remote=%s bytes=%d parallel=8 sequential held_lock collision cancellation source_change DS_cut no_replay reconnect empty verified", runtime.GOOS, version, name, len(payload))
		})
	}
}

func pnfsRelay(t *testing.T, target string) (string, func(), func() int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	count := 0
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			down, err := l.Accept()
			if err != nil {
				return
			}
			up, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				down.Close()
				return
			}
			mu.Lock()
			count++
			conns = append(conns, down, up)
			mu.Unlock()
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(up, down); up.Close() }()
			go func() { defer wg.Done(); io.Copy(down, up); down.Close() }()
		}
	}()
	cut := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	}
	t.Cleanup(func() { l.Close(); cut(); wg.Wait() })
	return l.Addr().String(), cut, func() int { mu.Lock(); defer mu.Unlock(); return count }
}

func TestGlusterPNFSCLI(t *testing.T) {
	host, port, advertised, target := pnfsFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			name := fmt.Sprintf("pnfs-cli-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			dest := filepath.Join(dir, "download")
			payload := pnfsPayload()
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{host, "--nfs-version", version, "--nfs-port", strconv.Itoa(port), "--pnfs", "--export", pnfsFixtureExport(), "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--no-banner", "--progress", "never", "--color", "never"}
			for _, cmd := range []string{"put " + strconv.Quote(source) + " " + name, "lock " + name + " read", "getpnfs " + name + " " + strconv.Quote(dest) + " --parallel 8 " + advertised + "=" + target, "unlock 1", "reconnect", "getpnfs " + name + " " + strconv.Quote(dest+"-again") + " " + advertised + "=" + target} {
				args = append(args, "-c", cmd)
			}
			out, err := runKerberosCLI(t, args)
			if err != nil {
				t.Fatal(err, out)
			}
			for _, p := range []string{dest, dest + "-again"} {
				b, err := os.ReadFile(p)
				if err != nil || !bytes.Equal(b, payload) {
					t.Fatal("CLI bytes", err)
				}
			}
			t.Logf("PNFS_CLI platform=%s version=%s remote=%s bytes=%d binary=%t verified", runtime.GOOS, version, name, len(payload), os.Getenv("NFS_VIEWER_TEST_BINARY") != "")
		})
	}
}

func TestPNFSCLIInvalidArguments(t *testing.T) {
	for _, command := range []string{
		"getpnfs a b x=y --layout",
		"getpnfs a b x=y --layout unknown",
		"getpnfs a b x=y --layout flex --layout file",
		"putpnfs a b x=y --layout flex --layout file",
		"putrangepnfs a b 0 x=y --layout unknown",
	} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil || !strings.Contains(err.Error(), "layout") {
			t.Fatal(command, err)
		}
	}
	for _, command := range []string{
		"getpnfs a b --read-failover --read-failover x=y",
		"putpnfs a b --read-failover x=y",
		"putrangepnfs a b 0 --read-failover x=y",
	} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil || !strings.Contains(err.Error(), "--read-failover") {
			t.Fatal(command, err)
		}
	}
	for _, command := range []string{"getpnfs a b --refresh-devices --refresh-devices x=y", "putpnfs a b --refresh-devices --refresh-devices x=y", "putrangepnfs a b 0 --refresh-devices --refresh-devices x=y"} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil || !strings.Contains(err.Error(), "--refresh-devices") {
			t.Fatal("device refresh option accepted", err)
		}
	}
	for _, command := range []string{"getpnfs a b --write-failover x=y", "putpnfs a b --write-failover --write-failover x=y", "putrangepnfs a b 0 --write-failover --write-failover x=y"} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil || !strings.Contains(err.Error(), "--write-failover") {
			t.Fatal("write failover option accepted", err)
		}
	}
	for _, command := range []string{"getpnfs a b --session-trunking --session-trunking x=y", "putpnfs a b --session-trunking x=y", "putrangepnfs a b 0 --session-trunking x=y"} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil || !strings.Contains(err.Error(), "--session-trunking") {
			t.Fatal("session trunking option accepted", err)
		}
	}
	for _, command := range []string{"getpnfs a b --mirror-failover --mirror-failover x=y", "putpnfs a b --mirror-failover x=y", "putrangepnfs a b 0 --mirror-failover x=y"} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil || !strings.Contains(err.Error(), "--mirror-failover") {
			t.Fatal(command, err)
		}
	}
	for _, command := range []string{"getpnfs a b", "putpnfs a b", "putrangepnfs a b 0"} {
		for _, args := range []string{"--ds-spn", "--ds-spn missing", "--ds-spn =nfs/ds", "--ds-spn target=", "--ds-spn target=nfs/a --ds-spn target=nfs/b"} {
			if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command+" x=y "+args); err == nil || !strings.Contains(err.Error(), "SPN") && !strings.Contains(err.Error(), "--ds-spn") {
				t.Fatal(command, args, err)
			}
		}
	}
	for _, cmd := range []string{"getpnfs", "getpnfs a b", "getpnfs a b missing", "getpnfs a b x=y x=z", "getpnfs a b --parallel", "getpnfs a b --parallel 0 x=y", "getpnfs a b --parallel 9 x=y", "getpnfs a b --parallel -1 x=y", "getpnfs a b --parallel text x=y", "getpnfs a b --parallel 2 --parallel 3 x=y", "getpnfs a b --parallel 2"} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), cmd); err == nil {
			t.Fatal(cmd)
		}
	}
	for _, version := range []string{"auto", "2", "3", "4.0"} {
		_, err := nfs.Connect(context.Background(), nfs.Config{PNFS: true, Version: version})
		if err == nil || !strings.Contains(err.Error(), "pNFS requires") {
			t.Fatal(version, err)
		}
	}
}
