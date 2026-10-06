package nfs

import (
	"fmt"
	"testing"
)

func TestPNFSMultipathReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, packing := range []string{"dense", "sparse-many", "sparse-one", "sparse-mds"} {
			for _, parallel := range []int{1, 8} {
				t.Run(fmt.Sprintf("4.%d/%s/%d", minor, packing, parallel), func(t *testing.T) {
					runPNFSStripedRead(t, minor, "paths-segments-"+packing, 128, "data", parallel)
				})
			}
		}
		for _, mode := range []string{"paths-cache", "init-denied", "exchange-lost", "create-lost", "read-lost", "all-paths-failed", "paths-unapproved", "denied", "cancel-hole", "recall-hole", "writer-hole"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				runPNFSStripedRead(t, minor, "paths-segments-dense", 128, mode, 1)
			})
		}
	}
}
