package cli

import (
	"fmt"
	"testing"
)

func TestISCSIReadRecoveryPublication(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, profile := range []string{"", "secure-"} {
			for _, mode := range []string{"api", "cli", "source-change", "return-failure"} {
				t.Run(fmt.Sprintf("4.%d/%s%s", minor, profile, mode), func(t *testing.T) { runBlockDownloadPublication(t, minor, profile+"recovery-iscsi-"+mode) })
			}
		}
	}
}
