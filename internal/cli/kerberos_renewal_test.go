package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKerberosRenewalCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires four-second MIT tickets")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			if version == "3-udp" && security != "krb5" {
				continue
			}
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					t.Parallel()
					args := []string{"127.0.0.1", "--nfs-version", version, "--sec", security, "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"), "--krb5-config", os.Getenv("NFS_VIEWER_KRB5_CONFIG"), "--principal", "root@NFS.TEST", "--spn", "nfs/server.nfs.test", "--export", "/data", "--auto-escape=false", "--batch", "--no-banner", "--color", "never", "--progress", "never"}
					if version == "3-udp" {
						args = append(args, "--nfs-version", "3", "--transport", "udp", "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
					}
					if credential == "ccache" {
						if os.Getenv("NFS_VIEWER_KRB5_CCACHE") == "" {
							t.Skip("requires FILE cache")
						}
						args = append(args, "--ccache", os.Getenv("NFS_VIEWER_KRB5_CCACHE"))
					} else {
						args = append(args, "--keytab", os.Getenv("NFS_VIEWER_KRB5_KEYTAB"))
					}
					testKerberosRenewalCLI(t, args, "root@NFS.TEST ("+security+")")
				})
			}
		}
	}
}

type renewalOutput struct {
	mu    sync.Mutex
	b     bytes.Buffer
	once  sync.Once
	ready chan struct{}
}

func (w *renewalOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.b.Write(p)
	if bytes.Contains(w.b.Bytes(), []byte("Renewals")) {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}
func (w *renewalOutput) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

func testKerberosRenewalCLI(t *testing.T, args []string, identity string) {
	t.Helper()
	testKerberosRenewalCLIWithIdle(t, args, identity, 5*time.Second)
}

func testKerberosRenewalCLIWithIdle(t *testing.T, args []string, identity string, idle time.Duration) {
	t.Helper()
	dir := t.TempDir()
	source, dest := filepath.Join(dir, "source.bin"), filepath.Join(dir, "dest.bin")
	payload := bytes.Repeat([]byte{0, 255, 27, 'R'}, 10000)
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("cli-renew-%x", nonce)
	ctx, cancel := context.WithTimeout(context.Background(), idle+20*time.Second)
	defer cancel()
	in, w := io.Pipe()
	defer in.Close()
	defer w.Close()
	out := &renewalOutput{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		var err error
		if binary := os.Getenv("NFS_VIEWER_TEST_BINARY"); binary != "" {
			cmd := exec.CommandContext(ctx, binary, args...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, out
			err = cmd.Run()
		} else {
			cmd := NewCommand(in, out, out)
			cmd.SetArgs(args)
			err = cmd.ExecuteContext(ctx)
		}
		in.CloseWithError(err)
		done <- err
	}()
	if _, err := io.WriteString(w, "put "+strconv.Quote(source)+" "+name+"\nid\n"); err != nil {
		t.Fatalf("initial commands: %v %s", err, out.String())
	}
	select {
	case <-out.ready:
	case err := <-done:
		t.Fatalf("early exit: %v %s", err, out.String())
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Starts only after the first id completed; the caller chooses an idle
	// period longer than the fixture's service-ticket lifetime.
	select {
	case <-time.After(idle):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := io.WriteString(w, "get "+name+" "+strconv.Quote(dest)+"\nid\nexit\n"); err != nil {
		t.Fatalf("commands after expiry: %v %s", err, out.String())
	}
	w.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("renewed CLI: %v %s", err, out.String())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("renewed download: %v", err)
	}
	if !regexp.MustCompile(`Renewals\s+[1-9][0-9]* `).MatchString(out.String()) || strings.Count(out.String(), identity) < 2 {
		t.Fatalf("renewal/identity not reported: %s", out.String())
	}
}
