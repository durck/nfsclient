package nfs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfs-viewer/internal/testiscsi"
)

func TestBlockReadPortalRecovery(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"success", "lease", "recall", "device-change", "signature", "wrong-device", "no-approval"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				v, o, want, path, counts := blockWireFixture(t, minor, "ok")
				v.leaseSeconds = 60
				now := time.Now()
				v.lastLease.Store(&now)
				deviceID := func() [8]byte { return [8]byte{0x50, 1, 2, 3, 4, 5, 6, 7} }
				beforeDrop := func() {
					switch mode {
					case "lease":
						expired := time.Now().Add(-61 * time.Second)
						v.lastLease.Store(&expired)
					case "recall", "device-change":
						v.recall.mu.Lock()
						if mode == "recall" {
							v.recall.recalled = true
						} else {
							v.recall.devices = map[string]deviceNotice{"device": {invalid: true}}
						}
						v.recall.mu.Unlock()
					}
				}
				first := testiscsi.Start(t, path, testiscsi.Options{DeviceIDForSession: deviceID, ReadDropAfter: 2, BeforeReadDrop: beforeDrop, AllowProcessKill: true})
				altPath := path
				altOptions := testiscsi.Options{DeviceIDForSession: deviceID, AllowProcessKill: true}
				if mode == "signature" {
					b, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					b[len(b)-1] ^= 1
					altPath = filepath.Join(t.TempDir(), "changed-signature")
					if err := os.WriteFile(altPath, b, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "wrong-device" {
					altOptions.DeviceIDForSession = func() [8]byte { return [8]byte{0x50, 7, 6, 5, 4, 3, 2, 1} }
				}
				second := testiscsi.Start(t, altPath, altOptions)
				o.BlockVolumes = nil
				o.BlockTargets = []string{first.URL()}
				o.BlockInitiator = testiscsi.Initiator
				if mode != "no-approval" {
					o.ReadFailover = true
					o.BlockReadAlternates = map[string][]string{first.URL(): {second.URL()}}
				}
				var out bytes.Buffer
				n, err := v.c.ReadPNFSToProgress(context.Background(), []byte("file"), uint64(len(want)), &out, o, nil)
				if mode == "success" {
					if err != nil || n != int64(len(want)) || !bytes.Equal(out.Bytes(), want) || counts.returned.Load() != 1 || counts.closed.Load() != 1 {
						t.Fatal("recovered block read", n, err)
					}
				} else if err == nil || n != 0 || out.Len() != 0 {
					t.Fatal("invalid recovery published bytes", n, err)
				}
				if mode == "lease" || mode == "recall" || mode == "device-change" || mode == "no-approval" {
					if len(second.Events()) != 0 {
						t.Fatal("revoked read contacted alternate")
					}
				}
			})
		}
	}
}

func TestBlockReadAlternatePolicy(t *testing.T) {
	primary := "iscsi://127.0.0.1:3260/" + testiscsi.Name + "/0"
	alternate := "iscsi://127.0.0.1:3261/" + testiscsi.Name + "/0"
	for _, mode := range []string{"ok", "missing-approval", "wrong-lun", "duplicate", "unknown-primary", "write"} {
		t.Run(mode, func(t *testing.T) {
			o := PNFSOptions{Layout: "block", ReadFailover: true, BlockTargets: []string{primary}, BlockInitiator: testiscsi.Initiator, BlockReadAlternates: map[string][]string{primary: {alternate}}}
			switch mode {
			case "missing-approval":
				o.ReadFailover = false
			case "wrong-lun":
				o.BlockReadAlternates[primary] = []string{alternate[:len(alternate)-1] + "1"}
			case "duplicate":
				o.BlockReadAlternates[primary] = []string{alternate, alternate}
			case "unknown-primary":
				o.BlockReadAlternates = map[string][]string{alternate: {primary}}
			case "write":
				o.BlockWrite = true
			}
			var err error
			if mode == "write" {
				_, err = validateBlockWriteOptions(o)
			} else {
				_, err = validatePNFSOptions(o)
			}
			if (err == nil) != (mode == "ok") {
				t.Fatal(err)
			}
		})
	}
}
