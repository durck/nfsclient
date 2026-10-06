package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func retainedNLMConfig(t *testing.T, version, transport, suffix string) nfs.Config {
	t.Helper()
	if os.Getenv("NFS_VIEWER_NLM_RETAINED") != "1" {
		t.Skip("requires an exclusive NSM address and FreeBSD NLM fixture")
	}
	host, address, root := os.Getenv("NFS_VIEWER_NLM_HOST"), os.Getenv("NFS_VIEWER_NLM_CLIENT_IP"), os.Getenv("NFS_VIEWER_NLM_STATE_ROOT")
	if host == "" || address == "" || root == "" {
		t.Fatal("explicit NLM host, client IP and persistent state root are required")
	}
	return nfs.Config{Host: host, Version: version, Transport: transport, PortmapPort: 111, Timeout: 5 * time.Second, NLMClientIP: address, NLMListenIP: os.Getenv("NFS_VIEWER_NLM_LISTEN_IP"), NLMStateDir: filepath.Join(root, suffix), Auth: nfs.Auth{UID: 20001, GID: 20001}}
}

func TestNLMFreeBSDClientCrash(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NLM_CRASH") != "1" {
		t.Skip("requires a disposable server lock namespace")
	}
	testNLMClientCrash(t, "3", "tcp", false)
}

func TestNLMFreeBSDRecovery(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NLM_RECOVER") != "1" {
		t.Skip("requires disposable recovery fixture")
	}
	for _, v := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(v+"/"+transport, func(t *testing.T) { testNLMClientCrash(t, v, transport, true) })
		}
	}
}

func testNLMClientCrash(t *testing.T, version, transport string, recoverLocks bool) {
	cfg := retainedNLMConfig(t, version, transport, "client-crash-"+version+"-"+transport)
	binary := os.Getenv("NFS_VIEWER_TEST_BINARY")
	if binary == "" {
		t.Fatal("standalone binary required")
	}
	peerCfg := cfg
	peerCfg.NLMClientIP, peerCfg.NLMListenIP, peerCfg.NLMStateDir = "", "", ""
	peer := retainedNLMSession(t, peerCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if got, err := peer.TestLock(ctx, "file", true, 0, nfs.LockToEOF); err != nil || got != nil {
		t.Fatal("fixture is not free", got, err)
	}
	args := []string{cfg.Host, "--nfs-version", version, "--transport", transport, "--export", peer.Export, "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--batch", "--no-banner", "--color", "never", "--nlm-client-ip", cfg.NLMClientIP, "--nlm-state-dir", cfg.NLMStateDir}
	if cfg.NLMListenIP != "" {
		args = append(args, "--nlm-listen-ip", cfg.NLMListenIP)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stdin.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	if _, err := io.WriteString(stdin, "lock file write\n"); err != nil {
		t.Fatal(err)
	}
	confirmed := make(chan struct{}, 1)
	go func() {
		scan := bufio.NewScanner(stdout)
		for scan.Scan() {
			if strings.HasPrefix(scan.Text(), "Lock 1:") {
				confirmed <- struct{}{}
			}
		}
	}()
	select {
	case <-confirmed:
	case <-ctx.Done():
		t.Fatal("CLI did not confirm durable acquisition")
	}
	for {
		got, err := peer.TestLock(ctx, "file", true, 0, nfs.LockToEOF)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("CLI never acquired its lock")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed process exited cleanly")
	}
	if got, err := peer.TestLock(ctx, "file", true, 0, nfs.LockToEOF); err != nil || got == nil {
		t.Fatal("crash did not retain the server lock", got, err, output.String())
	}
	fresh := retainedNLMSession(t, cfg)
	if _, err := fresh.Lock(ctx, "file", true); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatal("crashed session was reused", err)
	}
	t.Log("forced standalone client termination retained server lock; persistent journal refused reuse")
	if !recoverLocks {
		return
	}
	// Recovery must use the saved credentials, even if the current identity differs.
	fresh.Client.Auth.UID = 20002
	var commandArgs []string
	for _, arg := range args {
		if arg != "--batch" {
			commandArgs = append(commandArgs, arg)
		}
	}
	if version == "2" {
		count, err := fresh.Client.RecoverNLMLocks(ctx)
		if err != nil || count != 1 {
			t.Fatal("recover saved owner", count, err)
		}
		fresh.Client.Close()
	} else {
		fresh.Client.Close()
		out, err := runKerberosCLI(t, append(append([]string{}, commandArgs...), "--uid", "20002", "-c", "nlmrecover"))
		if err != nil || !strings.Contains(out, "Released 1 recorded") {
			t.Fatal("CLI owner recovery", out, err)
		}
	}
	if got, err := peer.TestLock(ctx, "file", true, 0, nfs.LockToEOF); err != nil || got != nil {
		t.Fatal("recovered lock still held", got, err)
	}
	out, err := runKerberosCLI(t, append(commandArgs, "-c", "nlmrecover", "-c", "lock file write", "-c", "cat file", "-c", "unlock 1"))
	if err != nil || !strings.Contains(out, "Released 0 recorded") || !strings.Contains(out, "NLM fixture payload") {
		t.Fatal("post-recovery CLI", out, err)
	}
	t.Log("confirmed exact-owner recovery and subsequent fresh protected I/O")
}

func retainedNLMSession(t *testing.T, cfg nfs.Config) *session.Session {
	t.Helper()
	c, err := nfs.Connect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	s := session.New(c, cfg.Host, false, false, io.Discard)
	export := os.Getenv("NFS_VIEWER_NLM_EXPORT")
	if export == "" {
		t.Fatal("explicit fixture export required")
	}
	if err := s.Use(context.Background(), export); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNLMFreeBSDRetained(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(version+"/"+transport, func(t *testing.T) {
				cfg := retainedNLMConfig(t, version, transport, "clean-"+version+"-"+transport)
				s := retainedNLMSession(t, cfg)
				ctx := context.Background()
				peerCfg := cfg
				peerCfg.NLMClientIP = ""
				peerCfg.NLMListenIP = ""
				peerCfg.NLMStateDir = ""
				peer := retainedNLMSession(t, peerCfg)
				node, _, err := s.Resolve(ctx, "file", false)
				if err != nil {
					t.Fatal(err)
				}
				id, err := s.Lock(ctx, "file", true)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := peer.TestLock(ctx, "file", true, 0, nfs.LockToEOF); err != nil || got == nil || !got.Write {
					t.Fatal("peer did not see retained lock", got, err)
				}
				var data bytes.Buffer
				if _, err := s.Client.ReadTo(ctx, node.Handle, &data); err != nil || data.String() != "NLM fixture payload\n" {
					t.Fatal("protected read", data.String(), err)
				}
				if _, err := s.Client.WriteFrom(ctx, node.Handle, strings.NewReader(data.String())); err != nil {
					t.Fatal("protected write", err)
				}
				if _, err := s.LockRange(ctx, "file", true, 1, 1); err == nil {
					t.Fatal("overlap accepted")
				}
				if _, err := s.Client.Reconnect(ctx); !errors.Is(err, nfs.ErrLocksHeld) {
					t.Fatal("reconnect while held", err)
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				if got, err := peer.TestLock(ctx, "file", true, 0, nfs.LockToEOF); err != nil || got != nil {
					t.Fatal("lock not released", got, err)
				}
				read, err := s.Lock(ctx, "file", false)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := peer.TestLock(ctx, "file", false, 0, nfs.LockToEOF); err != nil || got != nil {
					t.Fatal("read/read conflict", got, err)
				}
				if _, err := s.Client.WriteFrom(ctx, node.Handle, strings.NewReader("bad")); err == nil {
					t.Fatal("write under read lock accepted")
				}
				if err := s.Client.Unlock(ctx, read); err != nil {
					t.Fatal(err)
				}
				a, err := s.LockRange(ctx, "file", true, 0, 4)
				if err != nil {
					t.Fatal(err)
				}
				b, err := s.LockRange(ctx, "file", true, 4, 4)
				if err != nil {
					t.Fatal(err)
				}
				data.Reset()
				if _, err := s.Client.ReadTo(ctx, node.Handle, &data); !errors.Is(err, nfs.ErrPartialLockIO) || data.Len() != 0 {
					t.Fatal("partial lock whole-file read", err)
				}
				if err := s.Client.Unlock(ctx, a); err != nil {
					t.Fatal(err)
				}
				if got, err := peer.TestLock(ctx, "file", true, 0, 4); err != nil || got != nil {
					t.Fatal("independent first unlock", got, err)
				}
				if got, err := peer.TestLock(ctx, "file", true, 4, 4); err != nil || got == nil {
					t.Fatal("second range lost", got, err)
				}
				if err := s.Client.Unlock(ctx, b); err != nil {
					t.Fatal(err)
				}
				s.Client.Close() // Release the exclusive port before the standalone process.
				args := []string{cfg.Host, "--nfs-version", version, "--transport", transport, "--export", s.Export, "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--no-banner", "--color", "never", "--nlm-client-ip", cfg.NLMClientIP, "--nlm-state-dir", cfg.NLMStateDir, "-c", "lock file write", "-c", "cat file", "-c", "locks", "-c", "unlock 1"}
				if cfg.NLMListenIP != "" {
					args = append(args, "--nlm-listen-ip", cfg.NLMListenIP)
				}
				out, err := runKerberosCLI(t, args)
				if err != nil || !strings.Contains(out, "NLM fixture payload") || !strings.Contains(out, "Lock 1") {
					t.Fatal("CLI", out, err)
				}
				t.Logf("confirmed lock/read/write/shared/ranges/unlock/clean restart: %s/%s", version, transport)
			})
		}
	}
}

// The driver waits for READY, changes a real server service, then allows the
// test to observe either a notification or a failed retained-control probe.
func TestNLMFreeBSDLoss(t *testing.T) {
	mode := os.Getenv("NFS_VIEWER_NLM_LOSS")
	if mode == "" {
		t.Skip("requires coordinated NSM/lockd restart")
	}
	cfg := retainedNLMConfig(t, "3", "tcp", "loss-"+mode)
	s := retainedNLMSession(t, cfg)
	ctx := context.Background()
	id, err := s.Lock(ctx, "file", true)
	if err != nil {
		t.Fatal(err)
	}
	marker := os.Getenv("NFS_VIEWER_NLM_MARKER")
	if marker == "" {
		t.Fatal("explicit coordination marker required")
	}
	if err := os.WriteFile(marker, []byte("READY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for !s.Client.Locks()[0].Uncertain && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if !s.Client.Locks()[0].Uncertain {
		t.Fatal("server change did not invalidate the lock")
	}
	if err := s.Client.Unlock(ctx, id); !errors.Is(err, nfs.ErrLockUncertain) {
		t.Fatal("lost lock unlock was replayed", err)
	}
	fh, err := s.Client.LockedFileHandle(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Client.WriteFrom(ctx, fh, strings.NewReader("corrupt")); err == nil {
		t.Fatal("write after loss accepted")
	}
	s.Client.Close()
	fresh := retainedNLMSession(t, cfg)
	// The restart driver can return before lockd has registered its RPC port.
	// Wait using the read-only TEST operation; never retry acquisition here.
	deadline = time.Now().Add(10 * time.Second)
	for {
		_, err := fresh.TestLock(ctx, "file", true, 0, nfs.LockToEOF)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restarted NLM did not become ready", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := fresh.Lock(ctx, "file", true); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatal("unclean state reused", err)
	}
	t.Log("uncertain lock retained; protected write/unlock/reuse refused for " + mode + " id=" + strconv.FormatUint(id, 10))
	if os.Getenv("NFS_VIEWER_NLM_RECOVER") == "1" {
		count, err := fresh.Client.RecoverNLMLocks(ctx)
		if err != nil || count != 1 {
			t.Fatal("service-loss recovery", count, err)
		}
		id, err := fresh.Lock(ctx, "file", true)
		if err != nil {
			t.Fatal("fresh lock after recovery", err)
		}
		if err := fresh.Client.Unlock(ctx, id); err != nil {
			t.Fatal(err)
		}
		t.Log("explicit cleanup after service loss permits a fresh acquisition")
	}
}
