package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The same matrix runs in-process and against NFS_VIEWER_TEST_BINARY.
func TestNFS2ServerCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NFS2_SERVER") != "1" {
		t.Skip("requires isolated tests/nfsv2 fixture")
	}
	port := func(key, fallback string) string {
		v := os.Getenv("NFS_VIEWER_NFS2_" + key)
		if v == "" {
			v = fallback
		}
		return v
	}
	for _, transport := range []string{"tcp", "udp"} {
		for _, version := range []string{"2", "auto"} {
			t.Run(transport+"/"+version, func(t *testing.T) {
				base := []string{"127.0.0.1", "--nfs-version", version, "--transport", transport, "--nfs-port", port("PORT", "19049"), "--mount-port", port("MOUNT_PORT", "19048"), "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--groups", "20003", "--no-banner", "--color", "never", "--progress", "never", "--timeout", "3s"}
				run := func(args []string, commands ...string) (string, error) {
					a := append([]string(nil), args...)
					for _, command := range commands {
						a = append(a, "-c", command)
					}
					return runKerberosCLI(t, a)
				}
				local := t.TempDir()
				src, dst := filepath.Join(local, "source"), filepath.Join(local, "download")
				payload := bytes.Repeat([]byte("real-v2-shell\x00"), 8192)
				if err := os.WriteFile(src, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dst+".nfs-part", payload[:32768], 0600); err != nil {
					t.Fatal(err)
				}
				remote := fmt.Sprintf("cli-%s-%s-%d", transport, version, time.Now().UnixNano())
				tree := filepath.Join(local, "tree")
				out, err := run(base, "id", "ls wide", "cat link.txt", "mkdir "+remote, "put "+strconv.Quote(src)+" "+remote+"/binary", "reget --retries 2 "+remote+"/binary "+strconv.Quote(dst), "gettree "+remote+" "+strconv.Quote(tree))
				if err != nil || !strings.Contains(out, "300 entries") || !strings.Contains(out, "NFSv2 / "+strings.ToUpper(transport)) || !strings.Contains(out, "NFSv2 fixture") {
					t.Fatalf("CLI %v: %s", err, out[max(0, len(out)-2000):])
				}
				for _, p := range []string{dst, filepath.Join(tree, "binary")} {
					got, err := os.ReadFile(p)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("CLI bytes", err)
					}
				}
				for _, suffix := range []string{".nfs-part", ".nfs-part.lock"} {
					if _, err := os.Lstat(dst + suffix); !os.IsNotExist(err) {
						t.Fatal("resume artifact left", err)
					}
				}
				out, err = run(base, "replace "+strconv.Quote(src)+" "+remote+"/binary")
				if err == nil || !strings.Contains(out+err.Error(), "replacement refused") {
					t.Fatalf("v2 replacement accepted: %v %s", err, out)
				}
				bob := append(append([]string(nil), base...), "--uid", "20002", "--gid", "20002", "--groups", "")
				deniedDir := t.TempDir()
				out, err = run(bob, "get private.txt "+strconv.Quote(filepath.Join(deniedDir, "denied")))
				if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
					t.Fatal("denied CLI read", err, out)
				}
				entries, err := os.ReadDir(deniedDir)
				if err != nil || len(entries) != 0 {
					t.Fatal("denied download left data", err)
				}
				t.Logf("NFS2_CLI selection=%s transport=%s bytes=%d verified_resume recursive_read replacement_refused permission_denied", version, transport, len(payload))
			})
		}
	}
}
