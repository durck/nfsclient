//go:build linux

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

func TestKCMReleaseCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KCM_NATIVE") != "1" {
		t.Skip("requires disposable MIT KCM/KDC/Ganesha fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				dir := t.TempDir()
				source, dest := filepath.Join(dir, "source"), filepath.Join(dir, "dest")
				empty := filepath.Join(dir, "empty")
				emptyDest := filepath.Join(dir, "empty-dest")
				payload := bytes.Repeat([]byte{0, 255, 128, 'K', 'C', 'M'}, 24000)
				if err := os.WriteFile(source, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(empty, nil, 0600); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("kcm-%d", time.Now().UnixNano())
				args := []string{"127.0.0.1", "--nfs-version", version, "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"), "--sec", security, "--krb5-config", os.Getenv("NFS_VIEWER_KRB5_CONFIG"), "--ccache", os.Getenv("NFS_VIEWER_KCM_NAME"), "--kcm-socket", os.Getenv("NFS_VIEWER_KCM_SOCKET"), "--principal", "root@NFS.TEST", "--spn", "nfs/server.nfs.test", "--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
				commands := []string{"id", "put " + strconv.Quote(source) + " " + name, "get " + name + " " + strconv.Quote(dest), "put " + strconv.Quote(empty) + " " + name + "-empty", "get " + name + "-empty " + strconv.Quote(emptyDest), "rm " + name, "rm " + name + "-empty"}
				for _, command := range commands {
					args = append(args, "-c", command)
				}
				out, err := runKerberosCLI(t, args)
				if err != nil {
					t.Fatal(err, out)
				}
				actual, err := os.ReadFile(dest)
				if err != nil || !bytes.Equal(actual, payload) {
					t.Fatal("KCM binary roundtrip", err)
				}
				actual, err = os.ReadFile(emptyDest)
				if err != nil || len(actual) != 0 {
					t.Fatal("KCM empty roundtrip", err)
				}
				if !strings.Contains(out, "root@NFS.TEST") || !strings.Contains(out, "Ticket ends") {
					t.Fatal("missing pinned/authenticated identity", out)
				}
			})
		}
	}
}
