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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// Forward bytes unchanged; cut only sockets belonging to this test's client.
// The actual server and its namespace survive the injected disconnect.
type downloadRelay struct {
	listener net.Listener
	mu       sync.Mutex
	pairs    map[net.Conn]net.Conn
	closed   bool
}

func newDownloadRelay(t *testing.T, upstream int) *downloadRelay {
	return newDownloadRelayTarget(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(upstream)))
}

func newDownloadRelayTarget(t *testing.T, upstream string) *downloadRelay {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &downloadRelay{listener: l, pairs: make(map[net.Conn]net.Conn)}
	done := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(done)
		for {
			client, err := l.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				server, err := net.DialTimeout("tcp", upstream, time.Second)
				if err != nil {
					return
				}
				defer server.Close()
				r.mu.Lock()
				if r.closed {
					r.mu.Unlock()
					return
				}
				r.pairs[client] = server
				r.mu.Unlock()
				defer func() { r.mu.Lock(); delete(r.pairs, client); r.mu.Unlock() }()
				copied := make(chan struct{})
				go func() { io.Copy(server, client); server.Close(); close(copied) }()
				io.Copy(client, server)
				client.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		l.Close()
		r.cut()
		<-done
		workers.Wait()
	})
	return r
}

func (r *downloadRelay) port() int { return r.listener.Addr().(*net.TCPAddr).Port }
func (r *downloadRelay) cut() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for client, server := range r.pairs {
		client.Close()
		server.Close()
	}
}

func recoverySession(t *testing.T, version string, port, mount int) *session.Session {
	t.Helper()
	c, err := nfs.Connect(context.Background(), nfs.Config{Host: "127.0.0.1", Version: version, NFSPort: port, MountPort: mount, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s := session.New(c, "127.0.0.1", false, false, nil)
	t.Cleanup(func() { s.Client.Close() })
	export := "/"
	if strings.HasPrefix(version, "4.") {
		export = "/data"
	}
	if err := s.Use(context.Background(), export); err != nil {
		t.Fatal(err)
	}
	return s
}

func assertRecoveryFile(t *testing.T, dest string, payload []byte) {
	t.Helper()
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("recovered content differs", err)
	}
	for _, suffix := range []string{".nfs-part", ".nfs-part.lock"} {
		if _, err := os.Lstat(dest + suffix); !os.IsNotExist(err) {
			t.Fatal("left recovery artifact", suffix, err)
		}
	}
}

func TestAutomaticResumeDisconnect(t *testing.T) {
	root, port := testServer(t)
	relay := newDownloadRelay(t, port)
	s := recoverySession(t, "3", relay.port(), relay.port())
	payload := bytes.Repeat([]byte("automatic-download\x00"), 32000)
	if err := os.WriteFile(filepath.Join(root, "source"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "download")
	old := s.Client
	cut, attempts := false, 0
	_, err := s.GetResumeRetry(context.Background(), "source", dest, 2, func(done, _ uint64) {
		if done == 0 {
			attempts++
		}
		if done >= 32768 && !cut {
			cut = true
			relay.cut()
		}
	})
	if err != nil || attempts != 2 || s.Client == old {
		t.Fatalf("recovery attempts=%d: %v", attempts, err)
	}
	assertRecoveryFile(t, dest, payload)
}

func TestAutomaticResumeBudget(t *testing.T) {
	root, port := testServer(t)
	relay := newDownloadRelay(t, port)
	s := recoverySession(t, "3", relay.port(), relay.port())
	payload := bytes.Repeat([]byte("budget"), 32000)
	if err := os.WriteFile(filepath.Join(root, "source"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "download")
	attempts := 0
	_, err := s.GetResumeRetry(context.Background(), "source", dest, 2, func(done, _ uint64) {
		if done == 0 {
			attempts++
		}
		if done >= 32768 {
			relay.cut()
		}
	})
	if err == nil || !strings.Contains(err.Error(), "budget exhausted") || attempts != 3 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
	part, err := os.ReadFile(dest + ".nfs-part")
	if err != nil || len(part) == 0 || !bytes.Equal(part, payload[:len(part)]) {
		t.Fatal("lost partial", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("published incomplete download")
	}
}

func TestAutomaticResumeFailedReconnectBudget(t *testing.T) {
	root, port := testServer(t)
	relay := newDownloadRelay(t, port)
	s := recoverySession(t, "3", relay.port(), relay.port())
	payload := bytes.Repeat([]byte("offline"), 32000)
	if err := os.WriteFile(filepath.Join(root, "source"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	var notices bytes.Buffer
	s.Notice = &notices
	old := s.Client
	attempts := 0
	dest := filepath.Join(t.TempDir(), "download")
	_, err := s.GetResumeRetry(context.Background(), "source", dest, 2, func(done, _ uint64) {
		if done == 0 {
			attempts++
		}
		if done >= 32768 {
			relay.listener.Close()
			relay.cut()
		}
	})
	if err == nil || !strings.Contains(err.Error(), "budget exhausted") || attempts != 1 || strings.Count(notices.String(), "Resume recovery") != 2 || s.Client != old {
		t.Fatalf("failed reconnects did not consume budget: attempts=%d err=%v notices=%s", attempts, err, notices.String())
	}
	if _, err := os.Stat(dest + ".nfs-part"); err != nil {
		t.Fatal("lost saved data", err)
	}
}

func TestAutomaticResumePermanentFailures(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "source"), []byte("current"), 0600); err != nil {
		t.Fatal(err)
	}
	var notices bytes.Buffer
	sh.Session.Notice = &notices
	old := sh.Session.Client
	for _, scenario := range []string{"prefix", "missing", "destination", "negative", "excessive"} {
		t.Run(scenario, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "download")
			remote, retries := "source", 2
			switch scenario {
			case "prefix":
				if err := os.WriteFile(dest+".nfs-part", []byte("old"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				remote = "absent"
			case "destination":
				if err := os.WriteFile(dest, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "negative":
				retries = -1
			case "excessive":
				retries = 31
			}
			if _, err := sh.Session.GetResumeRetry(context.Background(), remote, dest, retries, nil); err == nil {
				t.Fatal("permanent error accepted")
			}
			if notices.Len() != 0 || sh.Session.Client != old {
				t.Fatal("permanent error retried")
			}
			if scenario == "prefix" {
				b, err := os.ReadFile(dest + ".nfs-part")
				if err != nil || string(b) != "old" {
					t.Fatal("changed saved prefix", err)
				}
			}
		})
	}
}

type recoveryNotice func([]byte) (int, error)

func (f recoveryNotice) Write(p []byte) (int, error) { return f(p) }

func TestAutomaticResumeCancelAndExclusion(t *testing.T) {
	sh, root, _ := testShell(t)
	payload := bytes.Repeat([]byte("cancel"), 32000)
	if err := os.WriteFile(filepath.Join(root, "source"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "download")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := sh.Session.Client
	notices := 0
	sh.Session.Notice = recoveryNotice(func(p []byte) (int, error) {
		notices++
		if _, err := sh.Session.GetResume(context.Background(), "source", dest, nil); err == nil || !strings.Contains(err.Error(), "acquire resume lock") {
			t.Fatal("backoff released destination lock", err)
		}
		cancel()
		return len(p), nil
	})
	_, err := sh.Session.GetResumeRetry(ctx, "source", dest, 30, func(done, _ uint64) {
		if done >= 32768 {
			old.Close()
		}
	})
	if !errors.Is(err, context.Canceled) || notices != 1 || sh.Session.Client != old {
		t.Fatal("cancel retried", err, notices)
	}
	if _, err := os.Stat(dest + ".nfs-part.lock"); !os.IsNotExist(err) {
		t.Fatal("lock left after cancel")
	}
}

func TestAutomaticResumeRefusesReplacedSource(t *testing.T) {
	sh, root, _ := testShell(t)
	source := filepath.Join(root, "source")
	payload := bytes.Repeat([]byte("same-prefix"), 32000)
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "download")
	changed := false
	_, err := sh.Session.GetResumeRetry(context.Background(), "source", dest, 2, func(done, _ uint64) {
		if done >= 32768 && !changed {
			changed = true
			sh.Session.Client.Close()
			if err := os.Rename(source, source+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Cleanup(func() { sh.Session.Client.Close() })
	if !errors.Is(err, session.ErrDownloadSourceChanged) {
		t.Fatal("substituted inode accepted", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("published substituted source")
	}
	part, err := os.ReadFile(dest + ".nfs-part")
	if err != nil || len(part) == 0 || !bytes.Equal(part, payload[:len(part)]) {
		t.Fatal("partial lost", err)
	}
}

func TestRegetRetryShell(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "source"), []byte("shell"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"reget --retries", "reget --retries 1", "reget --retries -1 source", "reget --retries 31 source", "reget --retries nope source", "reget --retries 1 source out extra"} {
		if _, err := sh.Execute(context.Background(), line); err == nil {
			t.Fatal("invalid option accepted", line)
		}
	}
	sh.Session.Client.Close()
	if _, err := sh.Execute(context.Background(), "reget --retries 1 source out"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sh.Session.Client.Close() })
	assertRecoveryFile(t, filepath.Join(sh.LocalDir, "out"), []byte("shell"))
	for _, unsafe := range []string{"uid", "escape", "escaped"} {
		t.Run(unsafe, func(t *testing.T) {
			sh.Session.AutoUID, sh.Session.AutoEscape, sh.Session.Escaped = unsafe == "uid", unsafe == "escape", unsafe == "escaped"
			if _, err := sh.Session.GetResumeRetry(context.Background(), "source", filepath.Join(sh.LocalDir, unsafe), 1, nil); err == nil {
				t.Fatal("unsafe session accepted")
			}
		})
	}
}

func TestGaneshaAutomaticResume(t *testing.T) {
	portText := os.Getenv("NFS_VIEWER_TEST_PORT")
	if portText == "" {
		t.Skip("requires disposable Ganesha fixture")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			relay := newDownloadRelay(t, port)
			s := recoverySession(t, version, relay.port(), 0)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			payload := bytes.Repeat([]byte("ganesha-recovery\x00"), 32000)
			dir := t.TempDir()
			source, dest := filepath.Join(dir, "source"), filepath.Join(dir, "download")
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			remote := fmt.Sprintf("auto-resume-%d", time.Now().UnixNano())
			if _, err := s.Put(ctx, source, remote); err != nil {
				t.Fatal(err)
			}
			old := s.Client
			cut, attempts := false, 0
			_, err = s.GetResumeRetry(ctx, remote, dest, 2, func(done, _ uint64) {
				if done == 0 {
					attempts++
				}
				if done >= 32768 && !cut {
					cut = true
					relay.cut()
				}
			})
			if err != nil || attempts != 2 || old == s.Client {
				t.Fatalf("attempts=%d err=%v", attempts, err)
			}
			assertRecoveryFile(t, dest, payload)
			id, err := s.Lock(ctx, remote, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetResumeRetry(ctx, remote, dest+".locked", 1, nil); !errors.Is(err, nfs.ErrLocksHeld) {
				t.Fatal("held lock accepted", err)
			}
			if len(s.Client.Locks()) != 1 {
				t.Fatal("lock discarded")
			}
			if err := s.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			node, _, err := s.Resolve(ctx, remote, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Client.Remove(ctx, s.Root.Handle, remote); err != nil {
				t.Fatal(err)
			}
			t.Logf("AUTO_RESUME version=%s bytes=%d attempts=%d fileid=%d actual_tcp_cut prefix_verified locks_preserved", version, len(payload), attempts, node.Attr.FileID)
		})
	}
}
