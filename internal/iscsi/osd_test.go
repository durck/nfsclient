package iscsi

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfs-viewer/internal/testiscsi"
)

func TestOSDTCP(t *testing.T) {
	for _, mode := range []string{"ok", "osd-type", "osd-id", "osd-attribute", "osd-residual", "osd-data-sequence", "osd-drop", "cancel", "bad-cap"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture")
			if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
				t.Fatal(err)
			}
			id := bytes.Repeat([]byte{0x17}, 20)
			data := bytes.Repeat([]byte("object-value"), 1000)
			cap := make([]byte, 80)
			peer := testiscsi.Start(t, path, testiscsi.Options{Fault: mode, AllowProcessKill: true, OSDSystemID: id, OSDName: []byte("fixture"), OSDObjects: map[[2]uint64][]byte{{0x10000, 0x10001}: data}})
			target, err := ParseTarget(peer.URL())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v, err := OpenObject(ctx, target, testiscsi.Initiator, time.Second, id, []byte("fixture"), cap)
			if mode == "osd-type" || mode == "osd-id" || mode == "osd-attribute" || mode == "osd-residual" || mode == "osd-data-sequence" {
				if err == nil {
					v.Close()
					t.Fatal("unsafe device accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if mode == "cancel" {
				cancel()
				if _, err := v.Length(0x10000, 0x10001, cap); err == nil {
					t.Fatal("cancel accepted")
				}
				return
			}
			if mode == "bad-cap" {
				cap[2] = 1
				if _, err := v.Length(0x10000, 0x10001, cap); err == nil {
					t.Fatal("secure cap silently downgraded")
				}
				return
			}
			n, err := v.Length(0x10000, 0x10001, cap)
			if err != nil || n != uint64(len(data)) {
				t.Fatal(n, err)
			}
			out := make([]byte, 3071)
			err = v.Read(0x10000, 0x10001, 513, cap, out)
			if mode == "osd-drop" {
				if err == nil {
					t.Fatal("dropped command accepted")
				}
				events := peer.Events()
				if err = v.Read(0x10000, 0x10001, 513, cap, out); err == nil {
					t.Fatal("lost session reused")
				}
				if !bytes.Equal(events, peer.Events()) {
					t.Fatal("command replay")
				}
				return
			}
			if err != nil || !bytes.Equal(out, data[513:513+len(out)]) {
				t.Fatal(err, "wrong object bytes")
			}
		})
	}
}

func TestOSDCDBGolden(t *testing.T) {
	c := objectCDB(0x8805, 0x10001, 0x10002, make([]byte, 80))
	if len(c) != 200 || !bytes.Equal(c[:12], []byte{0x7f, 0, 0, 0, 0, 0, 0, 192, 0x88, 5, 0, 0x30}) || binary.BigEndian.Uint64(c[16:]) != 0x10001 || binary.BigEndian.Uint64(c[24:]) != 0x10002 {
		t.Fatal("OSD-1 CDB prefix/object")
	}
	for _, off := range []int{56, 64, 72, 192, 196} {
		if binary.BigEndian.Uint32(c[off:]) != 0xffffffff {
			t.Fatal("undefined offset", off)
		}
	}
}
