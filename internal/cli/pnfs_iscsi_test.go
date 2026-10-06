package cli

import (
	"context"
	"fmt"
	"io"
	"testing"
)

func TestISCSIBlockUpload(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli", "empty", "empty-cli", "collision", "initial-identity", "identity", "eof-identity", "source-change", "commit-error", "commit-size", "return-failure"} {
			t.Run(fmt.Sprintf("new/4.%d/%s", minor, mode), func(t *testing.T) { runBlockUploadFlow(t, minor, "iscsi-"+mode, false) })
		}
		for _, mode := range []string{"api", "cli", "no-extend", "identity", "source-change", "gap-source-change", "commit-error", "return-failure"} {
			t.Run(fmt.Sprintf("growth/4.%d/%s", minor, mode), func(t *testing.T) { runBlockUploadFlow(t, minor, "iscsi-"+mode, true) })
		}
	}
}

func TestISCSIBlockDownloadPublication(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli", "empty", "collision", "race-collision", "initial-identity", "base-identity", "cwd", "cancel", "return-failure", "close-failure", "source-change", "post-return-change", "signature"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runBlockDownloadPublication(t, minor, "iscsi-"+mode) })
		}
	}
}

func TestISCSICLIArguments(t *testing.T) {
	for _, command := range []string{"getpnfs a b --layout block --block-target", "getpnfs a b --layout block --block-target --parallel", "getpnfs a b --layout block --block-volume image --block-initiator", "getpnfs a b --layout block --block-volume image --block-initiator iqn.2026-10.test:viewer --block-initiator iqn.2026-10.test:viewer", "getpnfs a b --block-target iscsi://127.0.0.1:3260/iqn.2026-10.test:disk/0", "putpnfs a b --layout block --block-target iscsi://127.0.0.1:3260/iqn.2026-10.test:disk/0"} {
		t.Run(command, func(t *testing.T) {
			if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil {
				t.Fatal("unsafe block command accepted")
			}
		})
	}
}
