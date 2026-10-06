package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
)

func TestNLMFreeBSDNativeWait(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NLM_CALLBACK") != "1" {
		t.Skip("requires disposable native callback holder")
	}
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			for _, phase := range []string{"grant", "cancel"} {
				cli := os.Getenv("NFS_VIEWER_NLM_CALLBACK_CLI") == "1"
				if cli && phase == "cancel" {
					continue
				}
				t.Run(version+"/"+transport+"/"+phase, func(t *testing.T) {
					platform := os.Getenv("NFS_VIEWER_NLM_CALLBACK_PREFIX")
					if platform == "" {
						platform = runtime.GOOS
					}
					kind := "api"
					if cli {
						kind = "cli"
					}
					name := fmt.Sprintf("%s-%s-%s-%s-%s", platform, kind, version, transport, phase)
					cfg := retainedNLMConfig(t, version, transport, name)
					s := retainedNLMSession(t, cfg)
					peerCfg := cfg
					peerCfg.NLMClientIP, peerCfg.NLMStateDir, peerCfg.NLMListenIP = "", "", ""
					peer := retainedNLMSession(t, peerCfg)
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					local := filepath.Join(t.TempDir(), "marker")
					if err := os.WriteFile(local, []byte("1"), 0600); err != nil {
						t.Fatal(err)
					}
					mark := func(suffix string) error { _, err := peer.Put(ctx, local, name+"/"+suffix); return err }
					wait := func(suffix string) {
						for {
							_, _, err := peer.Resolve(ctx, name+"/"+suffix, false)
							if err == nil {
								return
							}
							if ctx.Err() != nil {
								t.Fatal("native oracle timeout", suffix, err)
							}
							time.Sleep(50 * time.Millisecond)
						}
					}
					if err := mark("start"); err != nil {
						t.Fatal(err)
					}
					wait("ready")
					conflict, err := peer.TestLock(ctx, name+"/file", true, 8, 8)
					if err != nil || conflict == nil {
						t.Fatal("native holder absent", conflict, err)
					}
					if phase == "grant" {
						released := make(chan error, 1)
						go func() { time.Sleep(5 * time.Second); released <- mark("release") }()
						var id uint64
						var releaseLock func() error
						if cli {
							releaseLock, err = nativeWaitCLI(t, ctx, cfg, s.Export, name+"/file")
							if err == nil {
								id = 1
							}
						} else {
							id, err = s.LockNativeWait(ctx, name+"/file", true, 8, 8, 10*time.Second)
							releaseLock = func() error { return s.Client.Unlock(ctx, id) }
						}
						if releaseErr := <-released; releaseErr != nil {
							t.Fatal(releaseErr)
						}
						if err != nil || id == 0 {
							t.Fatal("callback acquisition", id, err)
						}
						if err := mark("held"); err != nil {
							t.Fatal(err)
						}
						wait("probed")
						if err := releaseLock(); err != nil {
							t.Fatal(err)
						}
					} else {
						id, err := s.LockNativeWait(ctx, name+"/file", true, 8, 8, 3*time.Second)
						if id != 0 || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nfs.ErrLockUncertain) || len(s.Client.Locks()) != 0 {
							t.Fatal("unclean cancellation", id, err)
						}
						if err := mark("release"); err != nil {
							t.Fatal(err)
						}
					}
					if err := mark("done"); err != nil {
						t.Fatal(err)
					}
					wait("clean")
				})
			}
		}
	}
}

func nativeWaitCLI(t *testing.T, ctx context.Context, cfg nfs.Config, export, name string) (func() error, error) {
	args := []string{cfg.Host, "--nfs-version", cfg.Version, "--transport", cfg.Transport, "--export", export, "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--batch", "--no-banner", "--color", "never", "--nlm-client-ip", cfg.NLMClientIP, "--nlm-state-dir", cfg.NLMStateDir}
	if cfg.NLMListenIP != "" {
		args = append(args, "--nlm-listen-ip", cfg.NLMListenIP)
	}
	cmd := exec.CommandContext(ctx, os.Getenv("NFS_VIEWER_TEST_BINARY"), args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		stdin.Close()
		return nil, err
	}
	t.Cleanup(func() {
		stdin.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	ready := make(chan error, 1)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		scan := bufio.NewScanner(stdout)
		var lines []string
		reported := false
		for scan.Scan() {
			line := scan.Text()
			lines = append(lines, line)
			if strings.HasPrefix(line, "Lock 1:") && !reported {
				ready <- nil
				reported = true
			}
		}
		if !reported {
			ready <- fmt.Errorf("CLI did not acquire: %s; %v", strings.Join(lines, "\n"), scan.Err())
		}
	}()
	if _, err := fmt.Fprintf(stdin, "lock --wait-native 10s %s write 8 8\n", name); err != nil {
		return nil, err
	}
	select {
	case err := <-ready:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return func() error {
		if _, err := io.WriteString(stdin, "unlock 1\nexit\n"); err != nil {
			return err
		}
		stdin.Close()
		<-drained
		return cmd.Wait()
	}, nil
}
