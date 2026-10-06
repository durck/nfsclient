package iscsi

import (
	"bytes"
	"context"
	"nfsclient/internal/testiscsi"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOSDAllDataTCP(t *testing.T) {
	for _, mode := range []string{"ok", "root-nosec", "osd-algorithm", "osd-secure-data", "osd-secure-count", "osd-secure-icv", "osd-secure-status", "osd-secure-drop", "osd-write-drop", "wrong-key", "wrong-system", "cancel", "rights", "closed"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "device")
			if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
				t.Fatal(err)
			}
			id, key := bytes.Repeat([]byte{0x71}, 20), bytes.Repeat([]byte{0x59}, 20)
			data := bytes.Repeat([]byte("osd authenticated content"), 4000)
			peer := testiscsi.Start(t, path, testiscsi.Options{OSDSystemID: id, OSDName: []byte("secure"), OSDKey: key, OSDObjects: map[[2]uint64][]byte{{0x10000, 0x10001}: bytes.Clone(data)}, Fault: mode, AllowProcessKill: true})
			target, err := ParseTarget(peer.URL())
			if err != nil {
				t.Fatal(err)
			}
			rootCap, rootKey := testiscsi.OSDCredential(id, key, 0, 0, ObjectGetAttributes, time.Now().Add(time.Hour))
			if mode == "root-nosec" {
				rootCap = make([]byte, 80)
				rootKey = nil
			}
			root, err := NewObjectCredential(0, 0, rootCap, rootKey)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dev, err := OpenObjectWithCredential(ctx, target, testiscsi.Initiator, time.Second, id, []byte("secure"), root, Security{})
			if mode == "osd-algorithm" {
				if err == nil {
					dev.Close()
					t.Fatal("algorithm downgrade accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer dev.Close()
			rights := ObjectRead | ObjectWrite | ObjectGetAttributes | ObjectManage
			if mode == "rights" {
				rights = ObjectRead | ObjectGetAttributes
			}
			cap, capKey := testiscsi.OSDCredential(id, key, 0x10000, 0x10001, rights, time.Now().Add(time.Hour))
			if mode == "wrong-key" {
				capKey[0] ^= 1
			}
			if mode == "wrong-system" {
				other := bytes.Clone(id)
				other[0] ^= 1
				cap, capKey = testiscsi.OSDCredential(other, key, 0x10000, 0x10001, rights, time.Now().Add(time.Hour))
			}
			cred, err := NewObjectCredential(0x10000, 0x10001, cap, capKey)
			if err != nil {
				t.Fatal(err)
			}
			defer cred.Close()
			// Constructor owns independent buffers; caller zeroing cannot break it.
			clear(cap)
			clear(capKey)
			if mode == "closed" {
				cred.Close()
			}
			if mode == "cancel" {
				cancel()
			}
			if mode == "rights" {
				before := peer.Events()
				if err := dev.WriteWithCredential(0x10000, 0x10001, 7, cred, []byte("bad")); err == nil {
					t.Fatal("unauthorized write")
				}
				if !bytes.Equal(before, peer.Events()) {
					t.Fatal("denied command sent")
				}
				return
			}
			out := bytes.Repeat([]byte{0xcc}, ObjectMaxTransfer)
			untouched := bytes.Clone(out)
			if mode == "osd-write-drop" {
				err = dev.WriteWithCredential(0x10000, 0x10001, 9, cred, []byte("changed"))
				if err == nil {
					t.Fatal("lost write accepted")
				}
				if !bytes.Equal(peer.ObjectBytes(0x10000, 0x10001)[9:16], []byte("changed")) {
					t.Fatal("fixture did not execute write")
				}
			} else {
				err = dev.ReadWithCredential(0x10000, 0x10001, 513, cred, out)
			}
			if mode != "ok" {
				if err == nil {
					t.Fatal("unsafe secured command accepted")
				}
				if !bytes.Equal(out, untouched) {
					t.Fatal("unverified data published")
				}
				before := peer.Events()
				if dev.ReadWithCredential(0x10000, 0x10001, 513, cred, out) == nil {
					t.Fatal("invalid session reused")
				}
				if !bytes.Equal(before, peer.Events()) {
					t.Fatal("failed request replayed")
				}
				return
			}
			if err != nil || !bytes.Equal(out, data[513:513+len(out)]) {
				t.Fatal(err, "secure read mismatch")
			}
			beforeEvents := peer.Events()
			plain, err := NewObjectCredential(0x10000, 0x10001, make([]byte, 80), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer plain.Close()
			if dev.ReadWithCredential(0x10000, 0x10001, 0, plain, out) == nil || dev.Read(0x10000, 0x10001, 0, make([]byte, 80), out) == nil {
				t.Fatal("authenticated device silently downgraded")
			}
			if _, err := dev.Length(0x10000, 0x10001, make([]byte, 80)); err == nil {
				t.Fatal("attribute downgrade")
			}
			if !bytes.Equal(beforeEvents, peer.Events()) {
				t.Fatal("mode mismatch sent command")
			}
			n, err := dev.LengthWithCredential(0x10000, 0x10001, cred)
			if err != nil || n != uint64(len(data)) {
				t.Fatal(n, err)
			}
			patch := bytes.Repeat([]byte{0x39}, ObjectMaxTransfer)
			if err := dev.WriteWithCredential(0x10000, 0x10001, 29, cred, patch); err != nil {
				t.Fatal(err)
			}
			if err := dev.FlushWithCredential(0x10000, 0x10001, cred); err != nil {
				t.Fatal(err)
			}
			expected := bytes.Clone(data)
			copy(expected[29:], patch)
			if !bytes.Equal(expected, peer.ObjectBytes(0x10000, 0x10001)) {
				t.Fatal("write damaged object")
			}
		})
	}
}

func TestOSDCredentialScopeLifetime(t *testing.T) {
	cap, key := testiscsi.OSDCredential(bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 20), 0x10000, 0x10001, ObjectRead|ObjectGetAttributes, time.Now().Add(time.Hour))
	for _, mode := range []string{"object", "expired", "unlimited", "method", "slot", "key", "root", "rights"} {
		t.Run(mode, func(t *testing.T) {
			b, k := bytes.Clone(cap), bytes.Clone(key)
			p, o := uint64(0x10000), uint64(0x10001)
			switch mode {
			case "object":
				o++
			case "expired":
				clear(b[4:10])
				b[9] = 1
			case "unlimited":
				clear(b[4:10])
			case "method":
				b[2] = 2
			case "slot":
				b[1] = 1
			case "key":
				k = k[:19]
			case "root":
				p = 0
				o = 0
			case "rights":
			}
			c, err := NewObjectCredential(p, o, b, k)
			if mode != "rights" {
				if err == nil {
					c.Close()
					t.Fatal("invalid credential accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.Check(p, o, ObjectWrite) == nil {
				t.Fatal("write right missing")
			}
			c.expiry = time.Now().Add(-time.Second).UnixMilli()
			if c.Check(p, o, ObjectRead) == nil {
				t.Fatal("expired live credential accepted")
			}
			c.Close()
			if !bytes.Equal(c.key, make([]byte, 20)) || c.Check(p, o, 0) == nil {
				t.Fatal("closed key remains usable")
			}
		})
	}
}
