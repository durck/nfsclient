package nfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfsclient/internal/testiscsi"
)

func TestISCSIBlockLifecycle(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"ok", "partial-layout", "expanded", "signature", "capacity", "recall", "verify-failure", "return-failure"} {
			t.Run(fmt.Sprintf("read/4.%d/%s", minor, mode), func(t *testing.T) { runBlockReadWire(t, minor, "iscsi-"+mode, "", false) })
		}
		for _, mode := range []string{"cow", "invalid", "rw", "slice", "concat", "stripe", "large-block", "expanded", "alias", "signature", "capacity", "unaligned", "recall", "identity", "commit-drop", "return-error", "write-drop", "write-status", "sync-drop", "sync-status", "r2t-offset", "r2t-lun", "r2t-tag", "r2t-sequence", "r2t-length"} {
			t.Run(fmt.Sprintf("write/4.%d/%s", minor, mode), func(t *testing.T) { runBlockWriteWire(t, minor, "iscsi-"+mode, "", false) })
		}
		for _, mode := range []string{"cow", "rw", "invalid", "gap", "empty", "empty-gap", "large-block", "gap-recall", "short-source", "commit-truncated", "no-extend", "return-error"} {
			t.Run(fmt.Sprintf("growth/4.%d/%s", minor, mode), func(t *testing.T) { runBlockGrowthWire(t, minor, "iscsi-"+mode, "", false) })
		}
	}
}

func TestMITISCSIBlockLifecycle(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_GSS") != "1" {
		t.Skip("MIT fixture not enabled")
	}
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"ok", "signature", "return-failure"} {
					t.Run(fmt.Sprintf("read/4.%d/%s/tls=%t/%s", minor, security, secure, mode), func(t *testing.T) { runBlockReadWire(t, minor, "iscsi-"+mode, security, secure) })
				}
				for _, mode := range []string{"cow", "write-drop", "sync-drop"} {
					t.Run(fmt.Sprintf("write/4.%d/%s/tls=%t/%s", minor, security, secure, mode), func(t *testing.T) { runBlockWriteWire(t, minor, "iscsi-"+mode, security, secure) })
				}
				for _, mode := range []string{"gap", "empty", "commit-truncated"} {
					t.Run(fmt.Sprintf("growth/4.%d/%s/tls=%t/%s", minor, security, secure, mode), func(t *testing.T) { runBlockGrowthWire(t, minor, "iscsi-"+mode, security, secure) })
				}
			}
		}
	}
}

func TestBlockStorageApprovals(t *testing.T) {
	raw := "iscsi://127.0.0.1:3260/" + testiscsi.Name + "/0"
	for _, mode := range []string{"missing-initiator", "unused-initiator", "duplicate", "file-layout", "invalid-target", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			o := PNFSOptions{Layout: "block", BlockTargets: []string{raw}, BlockInitiator: testiscsi.Initiator}
			switch mode {
			case "missing-initiator":
				o.BlockInitiator = ""
			case "unused-initiator":
				o.BlockTargets = nil
				o.BlockVolumes = []string{filepath.Join(t.TempDir(), "volume")}
			case "duplicate":
				o.BlockTargets = append(o.BlockTargets, raw)
			case "file-layout":
				o.Layout = "file"
			case "invalid-target":
				o.BlockTargets = []string{"iscsi://host:3260/" + testiscsi.Name + "/0"}
			case "too-many":
				o.BlockTargets = make([]string, 65)
			}
			if _, err := validatePNFSOptions(o); err == nil {
				t.Fatal("unsafe storage approval accepted")
			}
		})
	}
	// Two explicitly approved portals with one NAA still alias one physical LU.
	path := filepath.Join(t.TempDir(), "storage")
	if err := os.WriteFile(path, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	a := testiscsi.Start(t, path, testiscsi.Options{})
	b := testiscsi.Start(t, path, testiscsi.Options{})
	o := PNFSOptions{Layout: "block", BlockTargets: []string{a.URL(), b.URL()}, BlockInitiator: testiscsi.Initiator}
	files, err := openBlockStorage(context.Background(), o, time.Second, true)
	if err == nil {
		files.close()
		t.Fatal("same logical unit approved twice")
	}
}
