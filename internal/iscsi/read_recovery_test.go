package iscsi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfsclient/internal/testiscsi"
)

func TestApprovedReadRecovery(t *testing.T) {
	for _, mode := range []string{"plain", "mutual", "4096", "prefix", "same-portal", "redirect", "digest", "wrong-device", "geometry", "signature", "guard-before", "guard-after", "cancel", "changed-secret", "protocol", "scsi", "budget", "closed", "writable"} {
		t.Run(mode, func(t *testing.T) {
			policy, opts := securityFixture(t, "none")
			if mode == "mutual" || mode == "changed-secret" || mode == "digest" {
				policy, opts = securityFixture(t, "mutual-chap")
				policy.HeaderDigest, policy.DataDigest = "crc32c", "crc32c"
				opts.HeaderDigest, opts.DataDigest = true, true
			}
			if mode == "4096" {
				opts.SectorSize = 4096
			}
			path := filepath.Join(t.TempDir(), "disk")
			before := make([]byte, 262144)
			for i := range before {
				before[i] = byte(i*17 + 11)
			}
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			bad := opts
			bad.Fault = "read-drop"
			if mode == "prefix" || mode == "same-portal" {
				bad.Fault = ""
				bad.ReadDropAfter = 2
			}
			if mode == "digest" {
				bad.Fault = "data-corrupt-read"
			}
			if mode == "protocol" {
				bad.Fault = "data-sequence"
			}
			if mode == "scsi" {
				bad.Fault = "unit-attention"
			}
			first := testiscsi.Start(t, path, bad)
			otherPath := path
			if mode == "wrong-device" {
				otherPath = filepath.Join(t.TempDir(), "different")
				if err := os.WriteFile(otherPath, before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "geometry" {
				opts.SectorSize = 4096
			}
			if mode == "budget" {
				opts.Fault = "read-drop"
			}
			if mode == "redirect" {
				opts.Fault = "redirect"
			}
			second := testiscsi.Start(t, otherPath, opts)
			primary, _ := ParseTarget(first.URL())
			alternate, _ := ParseTarget(second.URL())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v, err := OpenWithSecurity(ctx, primary, testiscsi.Initiator, time.Second, mode == "writable", policy)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			guardCalls := 0
			guard := func() error {
				guardCalls++
				if mode == "guard-before" && guardCalls >= 3 || mode == "guard-after" && guardCalls >= 4 {
					return errors.New("enclosing lease or lock lost")
				}
				return nil
			}
			portals := []Target{alternate}
			if mode == "same-portal" {
				portals = nil
			}
			err = v.EnableReadRecovery(portals, guard, nil)
			if mode == "writable" {
				if err == nil {
					t.Fatal("writable volume received replay policy")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "signature" {
				v.recovery.validate = func(_ io.ReaderAt) error { return errors.New("signature changed") }
			}
			if mode == "cancel" {
				cancel()
			}
			if mode == "closed" {
				v.Close()
			}
			if mode == "changed-secret" {
				if err := os.WriteFile(policy.SecretFile, []byte("different-valid-secret"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got := bytes.Repeat([]byte{0xa3}, 130003)
			if mode == "same-portal" {
				got = got[:70003]
			}
			n, err := v.ReadAt(got, 37)
			if mode == "plain" || mode == "mutual" || mode == "4096" || mode == "prefix" || mode == "same-portal" {
				if err != nil || n != len(got) || !bytes.Equal(got, before[37:37+len(got)]) {
					t.Fatal("read recovery data", n, err)
				}
				if _, err := v.WriteAt(make([]byte, 4096), 0); err == nil {
					t.Fatal("recovery broadened write privilege")
				}
			} else {
				if err == nil || n != 0 || !bytes.Equal(got, bytes.Repeat([]byte{0xa3}, len(got))) {
					t.Fatal("failed recovery exposed data", n, err)
				}
				events := bytes.Clone(second.Events())
				if _, err := v.ReadAt(got, 0); err == nil {
					t.Fatal("quarantined read revived")
				}
				if !bytes.Equal(events, second.Events()) {
					t.Fatal("repeated call extended retry budget")
				}
			}
			if mode == "guard-before" || mode == "cancel" || mode == "changed-secret" || mode == "protocol" || mode == "scsi" || mode == "closed" || mode == "digest" || mode == "same-portal" {
				if len(second.Events()) != 0 {
					t.Fatal("refusal contacted alternate", second.Events())
				}
			}
			if bytes.Contains(second.Events(), []byte{0x8a}) || bytes.Contains(second.Events(), []byte{0x91}) {
				t.Fatal("read recovery sent mutation")
			}
		})
	}
}
