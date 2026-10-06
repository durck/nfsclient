package nfs

import (
	"bytes"
	"context"
	"nfsclient/internal/testiscsi"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlockStorageGeometryRecovery(t *testing.T) {
	for _, mode := range []string{"same", "sector", "identity"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "volume")
			if err := os.WriteFile(path, make([]byte, 16384), 0600); err != nil {
				t.Fatal(err)
			}
			var sector, identity atomic.Uint32
			sector.Store(4096)
			identity.Store(1)
			peer := testiscsi.Start(t, path, testiscsi.Options{SectorSizeForSession: sector.Load, DeviceIDForSession: func() [8]byte { return [8]byte{0x50, 0, 0, 0, 0, 0, 0, byte(identity.Load())} }})
			o := PNFSOptions{Layout: "block", BlockTargets: []string{peer.URL()}, BlockInitiator: testiscsi.Initiator, BlockJournal: filepath.Join(t.TempDir(), "journal")}
			first, err := openBlockStorage(context.Background(), o, time.Second, true)
			if err != nil {
				t.Fatal(err)
			}
			o.blockGeometry = first.geometryFingerprint()
			first.close()
			c := &Client{version: "4.1", config: &Config{}, v4: &v4Client{clientID: 7, clientNonce: bytes.Repeat([]byte{1}, 16)}}
			input := bytes.Repeat([]byte{1}, 4096)
			j, r, err := c.beginBlockRecovery(o, []byte("file"), 0, uint64(len(input)), bytes.NewReader(input), Attr{Size: 8192}, 4096)
			if err != nil {
				t.Fatal(err)
			}
			j.file.Close()
			r.Close()
			// A real restart has a new incarnation. It must not mask the profile gate.
			c.v4.clientID++
			c.v4.clientNonce = bytes.Repeat([]byte{2}, 16)
			if mode == "sector" {
				sector.Store(512)
			}
			if mode == "identity" {
				identity.Store(2)
			}
			files, err := openBlockStorage(context.Background(), o, time.Second, false)
			if files != nil {
				files.close()
			}
			if (err == nil) != (mode == "same") {
				t.Fatalf("fresh storage mode=%s: %v", mode, err)
			}
			next := o
			next.blockGeometry = ""
			second, err := openBlockStorage(context.Background(), next, time.Second, true)
			if err != nil {
				t.Fatal(err)
			}
			defer second.close()
			next.blockGeometry = second.geometryFingerprint()
			next.BlockResume = true
			j, r, err = c.beginBlockRecovery(next, []byte("file"), 0, uint64(len(input)), bytes.NewReader(input), Attr{Size: 8192}, 4096)
			if err == nil {
				j.file.Close()
				r.Close()
			}
			if mode == "same" {
				if err != nil {
					t.Fatal("same device refused", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "geometry or profile changed") {
				t.Fatal("wrong profile refusal", err)
			}
			if bytes.Contains(peer.Events(), []byte{0x8a}) {
				t.Fatal("geometry validation wrote storage")
			}
		})
	}
}

func TestBlockNativeSectorMappingRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "volume")
	if err := os.WriteFile(path, make([]byte, 32768), 0600); err != nil {
		t.Fatal(err)
	}
	peer := testiscsi.Start(t, path, testiscsi.Options{SectorSize: 4096})
	files, err := openBlockStorage(context.Background(), PNFSOptions{BlockTargets: []string{peer.URL()}, BlockInitiator: testiscsi.Initiator}, time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	defer files.close()
	volumes := []*blockVolume{{kind: 0, file: files[0].file, size: 32768}}
	for _, tc := range []struct {
		name                  string
		offset, length, block uint64
		valid                 bool
	}{{"valid", 8192, 8192, 4096, true}, {"physical", 8704, 8192, 4096, false}, {"length", 8192, 4608, 512, false}, {"server-block", 8192, 8192, 512, false}} {
		t.Run(tc.name, func(t *testing.T) {
			layout := &fileLayout{offset: 0, length: tc.length, block: []blockExtent{{device: []byte("id"), offset: 0, length: tc.length, storage: tc.offset, state: 0}}}
			if err := checkBlockWriteMapping([]*fileLayout{layout}, map[string][]*blockVolume{"id": volumes}, tc.block); (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
	if bytes.Contains(peer.Events(), []byte{0x8a}) {
		t.Fatal("mapping validation wrote storage")
	}
}
