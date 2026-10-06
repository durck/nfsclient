//go:build linux

package cli

import (
	"bytes"
	"fmt"
	"nfsclient/internal/testutil/kdcfixture"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFASTReleaseCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_FAST_NATIVE") != "1" {
		t.Skip("requires disposable MIT FAST/KDC/Ganesha fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				t.Run(network+"/"+version+"/"+security, func(t *testing.T) {
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
					name := fmt.Sprintf("fast-%d", time.Now().UnixNano())
					conf, peer := kdcfixture.FASTConfig(t, os.Getenv("NFS_VIEWER_KRB5_CONFIG"), network, false)
					args := []string{"127.0.0.1", "--nfs-version", version, "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"), "--sec", security, "--krb5-config", conf, "--keytab", os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), "--require-fast", "--as-helper", os.Getenv("NFS_VIEWER_AS_HELPER"), "--fast-armor", os.Getenv("NFS_VIEWER_FAST_ARMOR"), "--principal", "root@NFS.TEST", "--spn", "nfs/server.nfs.test", "--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
					commands := []string{"id", "put " + strconv.Quote(source) + " " + name, "get " + name + " " + strconv.Quote(dest), "put " + strconv.Quote(empty) + " " + name + "-empty", "get " + name + "-empty " + strconv.Quote(emptyDest), "rm " + name, "rm " + name + "-empty"}
					for _, command := range commands {
						args = append(args, "-c", command)
					}
					out, err := runKerberosCLI(t, args)
					if err != nil {
						t.Fatal(err, out)
					}
					if peer.Armored.Load() == 0 || peer.PlainTimestamp.Load() != 0 {
						t.Fatal("CLI omitted required FAST or sent an unarmored timestamp")
					}
					actual, err := os.ReadFile(dest)
					if err != nil || !bytes.Equal(actual, payload) {
						t.Fatal("FAST binary roundtrip", err)
					}
					actual, err = os.ReadFile(emptyDest)
					if err != nil || len(actual) != 0 {
						t.Fatal("FAST empty roundtrip", err)
					}
					if !strings.Contains(out, "root@NFS.TEST") || !strings.Contains(out, "Ticket ends") {
						t.Fatal("missing pinned/authenticated identity", out)
					}
				})
			}
		}
	}
}
