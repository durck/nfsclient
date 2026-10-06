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
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestProtectedResumeRestart(t *testing.T) {
	host, control := os.Getenv("NFS_AUTO_RECLAIM_HOST"), os.Getenv("NFS_AUTO_RECLAIM_CONTROL")
	if host == "" || control == "" {
		t.Skip("requires owned restart fixture")
	}
	port, err := strconv.Atoi(os.Getenv("NFS_AUTO_RECLAIM_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			relay := newDownloadRelayTarget(t, net.JoinHostPort(host, strconv.Itoa(port)))
			cfg := nfs.Config{Host: "127.0.0.1", NFSPort: relay.port(), Version: version, Timeout: 5 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}}
			c, err := nfs.Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			var notice bytes.Buffer
			s := session.New(c, host, false, false, &notice)
			defer func() { s.Client.Close() }()
			if err := s.Use(ctx, "/"); err != nil {
				t.Fatal(err)
			}
			fixtureRequest(t, control, "grace", fmt.Sprintf("setup-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano()))
			payload := bytes.Repeat([]byte("protected resume\x00"), 32768)
			dir := t.TempDir()
			source, dest := filepath.Join(dir, "source"), filepath.Join(dir, "download")
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("resume-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			if _, err := s.Put(ctx, source, name); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetResumeReclaim(ctx, name, dest, nil); err == nil {
				t.Fatal("accepted no locks")
			}
			id, err := s.Lock(ctx, name, false)
			// Linux can extend the initial grace while previous clients reclaim.
			// A known GRACE refusal created no lock; only fixture setup retries it.
			for errors.Is(err, nfs.Status(10013)) && ctx.Err() == nil {
				time.Sleep(time.Second)
				id, err = s.Lock(ctx, name, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dest+".nfs-part", payload[:16384], 0600); err != nil {
				t.Fatal(err)
			}
			attempts := 0
			restarted := false
			old := s.Client
			count, err := s.GetResumeReclaim(ctx, name, dest, func(done, total uint64) {
				if done == 0 {
					attempts++
				}
				if done >= 32768 && !restarted {
					restarted = true
					token := name
					fixtureRequest(t, control, "restart", token)
				}
			})
			if err != nil || count != int64(len(payload)) || attempts != 2 || s.Client == old {
				t.Fatalf("count=%d attempts=%d err=%v notice=%s", count, attempts, err, notice.String())
			}
			assertRecoveryFile(t, dest, payload)
			locks := s.Client.Locks()
			if len(locks) != 1 || locks[0].ID != id || locks[0].Uncertain {
				t.Fatalf("lock lost: %+v", locks)
			}
			if strings.Count(notice.String(), "one server-restart lock reclaim") != 1 {
				t.Fatal(notice.String())
			}
			sh := &Shell{Session: s, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, LocalDir: dir, ProgressMode: "never"}
			if _, err := sh.Execute(ctx, "reget --reclaim-locks "+name+" shell-download"); err != nil {
				t.Fatal(err)
			}
			assertRecoveryFile(t, filepath.Join(dir, "shell-download"), payload)
			// Guard callback mutations before publication, including at EOF.
			changed := false
			_, err = s.GetResumeReclaim(ctx, name, dest+"-changed", func(done, total uint64) {
				if done == total && !changed {
					changed = true
					s.Client.Auth.GID++
				}
			})
			s.Client.Auth.GID--
			if !errors.Is(err, session.ErrResumeLockChanged) {
				t.Fatalf("callback mutation: %v", err)
			}
			if _, err := os.Stat(dest + "-changed"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published changed lock")
			}
			// A bad saved prefix is never a reason to reclaim or replace bytes.
			bad := dest + "-bad"
			if err := os.WriteFile(bad+".nfs-part", []byte("WRONG"), 0600); err != nil {
				t.Fatal(err)
			}
			_, err = s.GetResumeReclaim(ctx, name, bad, nil)
			if !errors.Is(err, session.ErrResumePrefix) {
				t.Fatalf("bad prefix: %v", err)
			}
			if strings.Count(notice.String(), "one server-restart lock reclaim") != 1 {
				t.Fatal("reclaimed for local failure")
			}
			// End only this test's recovery grace before fresh guard-test locks.
			fixtureRequest(t, control, "grace", name+"-guards")
			changed = false
			_, err = s.GetResumeReclaim(ctx, name, dest+"-relocked", func(done, total uint64) {
				if done == 0 && !changed {
					changed = true
					if err := s.Client.Unlock(ctx, id); err != nil {
						t.Fatal(err)
					}
					id, err = s.Lock(ctx, name, false)
					for errors.Is(err, nfs.Status(10013)) && ctx.Err() == nil {
						time.Sleep(time.Second)
						id, err = s.Lock(ctx, name, false)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			})
			if !errors.Is(err, session.ErrResumeLockChanged) {
				t.Fatalf("replacement lock accepted: %v", err)
			}
			cut := false
			_, err = s.GetResumeReclaim(ctx, name, dest+"-disconnect", func(done, total uint64) {
				if done >= 32768 && !cut {
					cut = true
					relay.cut()
				}
			})
			if err == nil || !strings.Contains(err.Error(), "changed server client ID") {
				t.Fatalf("unchanged server: %v", err)
			}
			if len(s.Client.Locks()) != 1 || !s.Client.Locks()[0].Uncertain {
				t.Fatal("uncertain inventory lost")
			}
			if _, err := os.Stat(dest + "-disconnect"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published after failed reclaim")
			}
			part, err := os.ReadFile(dest + "-disconnect.nfs-part")
			if err != nil || len(part) == 0 || !bytes.Equal(part, payload[:len(part)]) {
				t.Fatal("partial lost", err)
			}
			if strings.Count(notice.String(), "one server-restart lock reclaim") != 2 {
				t.Fatal("reclaim repeated", notice.String())
			}
			t.Logf("PROTECTED_RESUME os=%s version=%s bytes=%d attempts=%d restart=%t held_id=%d prefix_verified mutation_refused replacement_lock_refused unchanged_server_refused source=%s", runtime.GOOS, version, count, attempts, restarted, id, name)
		})
	}
}

func fixtureRequest(t *testing.T, control, operation, token string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(control, operation+"-request"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(control, operation+"-done"))
		if strings.TrimSpace(string(b)) == token {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(operation + " deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRegetReclaimOptions(t *testing.T) {
	sh := &Shell{}
	for _, line := range []string{"reget --reclaim-locks", "reget --reclaim-locks --retries 1 a", "reget --retries 1 --reclaim-locks a", "reget --reclaim-locks --reclaim-locks a", "reget --reclaim-locks a b c"} {
		if _, err := sh.Execute(context.Background(), line); err == nil {
			t.Fatalf("accepted %q", line)
		}
	}
}

func TestProtectedResumeRelease(t *testing.T) {
	host, port := os.Getenv("NFS_AUTO_RECLAIM_HOST"), os.Getenv("NFS_AUTO_RECLAIM_PORT")
	if host == "" || os.Getenv("NFS_VIEWER_TEST_BINARY") == "" {
		t.Skip("requires fixture and release binary")
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := nfs.Connect(ctx, nfs.Config{Host: host, NFSPort: p, Version: version, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			root, err := c.Mount(ctx, "/")
			if err != nil {
				t.Fatal(err)
			}
			entries, err := c.ReadDir(ctx, root.Handle)
			if err != nil {
				t.Fatal(err)
			}
			name := ""
			for _, e := range entries {
				if strings.HasPrefix(e.Name, "resume-"+runtime.GOOS+"-"+version+"-") {
					name = e.Name
				}
			}
			if name == "" {
				t.Fatal("native fixture source missing")
			}
			out := filepath.Join(t.TempDir(), "download")
			args := []string{host, "--nfs-port", port, "--nfs-version", version, "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never", "--uid", "25001", "--gid", "25000",
				"-c", "lock " + name + " read", "-c", "reget --reclaim-locks " + name + " " + strconv.Quote(out), "-c", "unlock 1"}
			if output, err := runKerberosCLI(t, args); err != nil {
				t.Fatal(err, output)
			}
			assertRecoveryFile(t, out, bytes.Repeat([]byte("protected resume\x00"), 32768))
			t.Logf("PROTECTED_RESUME_RELEASE os=%s version=%s bytes=557056", runtime.GOOS, version)
		})
	}
}
