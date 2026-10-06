package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func reclaimConfig(host, version string) nfs.Config {
	cfg := nfs.Config{Host: host, Version: version, Timeout: 5 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}}
	if creds := os.Getenv("NFS_RECLAIM_CREDENTIALS"); creds != "" {
		cfg.Auth = nfs.Auth{}
		cfg.Security = "krb5p"
		cfg.Kerberos = nfs.KerberosConfig{ConfigFile: filepath.Join(creds, "krb5.conf"), Keytab: filepath.Join(creds, "nv-alice.keytab"), Principal: "nv-alice@MSAD.NFS.TEST", SPN: "nfs/nfs-interop.msad.nfs.test"}
	}
	return cfg
}

func TestKernelReclaim(t *testing.T) {
	control, host := os.Getenv("NFS_RECLAIM_CONTROL"), os.Getenv("NFS_RECLAIM_HOST")
	if control == "" || host == "" {
		t.Skip("requires owned NFS restart supervisor")
	}
	for i, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cfg := reclaimConfig(host, version)
			c, err := nfs.Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s := session.New(c, host, false, false, nil)
			if err := s.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			local := filepath.Join(t.TempDir(), "source")
			payload := bytes.Repeat([]byte("reclaimed state\x00"), 4096)
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("reclaim-%s-%s", runtime.GOOS, version)
			for _, n := range []string{name, name + "-range"} {
				if _, err := s.Put(ctx, local, n); err != nil {
					t.Fatal(err)
				}
			}
			id, err := s.Lock(ctx, name, true)
			if err != nil {
				t.Fatal(err)
			}
			rangeID, err := s.LockRange(ctx, name+"-range", false, 13, 257)
			if err != nil {
				t.Fatal(err)
			}
			token := fmt.Sprint(i + 1)
			if err := os.WriteFile(filepath.Join(control, "restart-request"), []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(15 * time.Second)
			for {
				b, _ := os.ReadFile(filepath.Join(control, "restart-done"))
				if string(bytes.TrimSpace(b)) == token {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("restart deadline")
				}
				time.Sleep(50 * time.Millisecond)
			}
			sh := &Shell{Session: s, Out: io.Discard, Err: io.Discard}
			if _, err := sh.Execute(ctx, "reconnect --reclaim-locks"); err != nil {
				t.Fatal("protocol reclaim", err)
			}
			fresh := s.Client
			defer fresh.Close()
			locks := fresh.Locks()
			if len(locks) != 2 || locks[0].ID != id || locks[1].ID != rangeID || locks[0].Uncertain || locks[1].Uncertain || locks[1].Offset != 13 || locks[1].Length != 257 {
				t.Fatal("reclaimed inventory", locks)
			}
			if _, err := c.ReclaimLocks(ctx); err == nil {
				t.Fatal("old incarnation reclaimed twice")
			}
			c.Close()
			// Existing file handles remain valid; no replacement OPEN is needed.
			root, err := fresh.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			file, err := fresh.Lookup(ctx, root.Handle, name)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if _, err := fresh.ReadTo(ctx, file.Handle, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
				t.Fatal("reclaimed locked read", err)
			}
			// A new owner must still conflict once the server grace interval ends.
			other, err := nfs.Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			otherRoot, err := other.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			otherFile, err := other.Lookup(ctx, otherRoot.Handle, name)
			if err != nil {
				t.Fatal(err)
			}
			deadline = time.Now().Add(15 * time.Second)
			for {
				_, err = other.Lock(ctx, otherFile.Handle, true)
				if errors.Is(err, nfs.Status(10013)) && time.Now().Before(deadline) {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if err != nfs.Status(10010) {
					t.Fatal("reclaimed contention", err)
				}
				break
			}
			if err := fresh.Unlock(ctx, rangeID); err != nil {
				t.Fatal(err)
			}
			if err := fresh.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			newID, err := other.Lock(ctx, otherFile.Handle, true)
			if err != nil {
				t.Fatal("reclaimed release", err)
			}
			if err := other.Unlock(ctx, newID); err != nil {
				t.Fatal(err)
			}
			t.Logf("RECLAIM_API os=%s version=%s locks=2 whole_and_range real_restart previous_open reclaim_lock contention release", runtime.GOOS, version)
		})
	}
}

func TestKernelReclaimCLI(t *testing.T) {
	control, host, binary := os.Getenv("NFS_RECLAIM_CONTROL"), os.Getenv("NFS_RECLAIM_HOST"), os.Getenv("NFS_VIEWER_TEST_BINARY")
	if control == "" || host == "" || binary == "" {
		t.Skip("requires owned restart supervisor and release binary")
	}
	for i, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			dir := t.TempDir()
			source, target := filepath.Join(dir, "source"), filepath.Join(dir, "download")
			payload := bytes.Repeat([]byte("reclaimed state\x00"), 4096)
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("reclaim-cli-%s-%s", runtime.GOOS, version)
			args := []string{host, "--nfs-version", version, "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--batch", "--no-banner", "--color", "never", "--progress", "never", "--timeout", "5s"}
			cfg := reclaimConfig(host, version)
			if cfg.Security == "krb5p" {
				args = append(args, "--sec", "krb5p", "--krb5-config", cfg.Kerberos.ConfigFile, "--keytab", cfg.Kerberos.Keytab, "--principal", cfg.Kerberos.Principal, "--spn", cfg.Kerberos.SPN)
			} else {
				args = append(args, "--uid", "25001", "--gid", "25000")
			}
			cmd := exec.CommandContext(ctx, binary, args...)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			locked, recovered := make(chan struct{}, 1), make(chan struct{}, 1)
			output := make(chan string, 1)
			go func() {
				var lines []string
				scan := bufio.NewScanner(stdout)
				for scan.Scan() {
					line := scan.Text()
					lines = append(lines, line)
					if strings.HasPrefix(line, "Lock 1:") {
						select {
						case locked <- struct{}{}:
						default:
						}
					}
					if strings.Contains(line, "\theld\t") {
						select {
						case recovered <- struct{}{}:
						default:
						}
					}
				}
				output <- strings.Join(lines, "\n")
			}()
			fmt.Fprintf(stdin, "put %s %s\nlock %s write\n", strconv.Quote(source), name, name)
			select {
			case <-locked:
			case <-ctx.Done():
				t.Fatal("CLI lock deadline")
			}
			token := fmt.Sprint(i + 4)
			if err := os.WriteFile(filepath.Join(control, "restart-request"), []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(15 * time.Second)
			for {
				b, _ := os.ReadFile(filepath.Join(control, "restart-done"))
				if string(bytes.TrimSpace(b)) == token {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("restart deadline")
				}
				time.Sleep(50 * time.Millisecond)
			}
			fmt.Fprint(stdin, "reconnect --reclaim-locks\nlocks\n")
			select {
			case <-recovered:
			case <-ctx.Done():
				t.Fatal("CLI reclaim deadline")
			}
			// The fixture uses a ten-second grace interval. Retained state is
			// renewed while a v4.0 server finishes that interval for other clients.
			select {
			case <-time.After(12 * time.Second):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			fmt.Fprintf(stdin, "get %s %s\nunlock 1\nexit\n", name, strconv.Quote(target))
			stdin.Close()
			err = cmd.Wait()
			out := <-output
			if err != nil || !strings.Contains(stderr.String(), "Previous locks reclaimed") {
				t.Fatal("release reclaim", err, out, stderr.String())
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("reclaimed CLI bytes", err)
			}
			t.Logf("RECLAIM_CLI os=%s version=%s bytes=%d actual_release real_restart retained_lock", runtime.GOOS, version, len(payload))
		})
	}
}
