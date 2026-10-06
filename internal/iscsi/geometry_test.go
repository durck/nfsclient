package iscsi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"nfs-viewer/internal/testiscsi"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCapacityGeometry(t *testing.T) {
	for _, sector := range []uint32{0, 512, 1024, 4096, 65536} {
		for _, last := range []uint64{0, 31, uint64(math.MaxInt64)/uint64(max(sector, 1)) - 1, uint64(math.MaxInt64) / uint64(max(sector, 1)), math.MaxUint64} {
			data := make([]byte, 32)
			binary.BigEndian.PutUint64(data, last)
			binary.BigEndian.PutUint32(data[8:], sector)
			size, block, err := decodeCapacity(data)
			valid := (sector == 512 || sector == 4096) && last < uint64(math.MaxInt64)/uint64(sector)
			if (err == nil) != valid || valid && (size != int64(last+1)*int64(sector) || block != int64(sector)) {
				t.Fatalf("sector=%d last=%d: size=%d block=%d err=%v", sector, last, size, block, err)
			}
		}
	}
}

func TestNativeSectorTransfers(t *testing.T) {
	for _, sector := range []uint32{512, 4096} {
		t.Run(fmt.Sprint(sector), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "disk")
			original := make([]byte, 256<<10)
			for i := range original {
				original[i] = byte(i*17 + i/259)
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			peer := testiscsi.Start(t, path, testiscsi.Options{SectorSize: sector})
			target, err := ParseTarget(peer.URL())
			if err != nil {
				t.Fatal(err)
			}
			v, err := Open(context.Background(), target, testiscsi.Initiator, time.Second, true)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if v.SectorSize() != int64(sector) || v.size != int64(len(original)) {
				t.Fatal("geometry", v.SectorSize(), v.size)
			}
			for _, span := range [][2]int{{1, 70003}, {4095, 65539}, {len(original) - 1, 1}, {len(original), 0}} {
				data := make([]byte, span[1])
				n, err := v.ReadAt(data, int64(span[0]))
				if err != nil || n != len(data) || !bytes.Equal(data, original[span[0]:span[0]+span[1]]) {
					t.Fatal("unaligned read", span, n, err)
				}
			}
			before := peer.Events()
			if _, err := v.WriteAt(make([]byte, sector), 1); err == nil {
				t.Fatal("unaligned offset accepted")
			}
			if _, err := v.WriteAt(make([]byte, sector-1), int64(sector)); err == nil {
				t.Fatal("short sector accepted")
			}
			if !bytes.Equal(before, peer.Events()) {
				t.Fatal("unaligned write reached peer")
			}
			patch := bytes.Repeat([]byte{0xa7}, int(sector)*19)
			n, err := v.WriteAt(patch, int64(sector))
			if err != nil || n != len(patch) {
				t.Fatal("aligned write", n, err)
			}
			if err := v.Sync(); err != nil {
				t.Fatal(err)
			}
			copy(original[int(sector):], patch)
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("unrelated bytes changed", err)
			}
		})
	}
}
