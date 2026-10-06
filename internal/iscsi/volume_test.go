package iscsi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfsclient/internal/testiscsi"
)

func TestTCPStorage(t *testing.T) {
	for _, mode := range []string{"read", "noop", "separate-status", "write", "readonly", "cancel", "redirect", "chap", "digest", "login-stat", "login-id", "login-continue", "duplicate-key", "identity", "sector", "capacity", "data-sequence", "data-offset", "task-tag", "status-sequence", "residual", "window", "ahs", "oversize", "payload-drop", "read-drop", "unit-attention", "r2t-offset", "r2t-lun", "r2t-tag", "r2t-sequence", "r2t-length", "write-drop", "write-status", "sync-drop", "sync-status"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "storage")
			before := make([]byte, 131072)
			for i := range before {
				before[i] = byte(i*23 + 7)
			}
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			fault := mode
			if mode == "read" || mode == "write" || mode == "readonly" || mode == "cancel" {
				fault = ""
			}
			peer := testiscsi.Start(t, path, testiscsi.Options{Fault: fault})
			target, err := ParseTarget(peer.URL())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v, err := Open(ctx, target, testiscsi.Initiator, time.Second, mode != "readonly")
			switch mode {
			case "redirect", "chap", "digest", "login-stat", "login-id", "login-continue", "duplicate-key", "identity", "sector", "capacity":
				if err == nil {
					v.Close()
					t.Fatal("unsafe login accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if mode == "cancel" {
				cancel()
				if _, err := v.ReadAt(make([]byte, 512), 0); err == nil {
					t.Fatal("cancelled I/O succeeded")
				}
				return
			}
			if mode == "write" || mode == "readonly" || mode == "r2t-offset" || mode == "r2t-lun" || mode == "r2t-tag" || mode == "r2t-sequence" || mode == "r2t-length" || mode == "write-drop" || mode == "write-status" || mode == "sync-drop" || mode == "sync-status" {
				patch := bytes.Repeat([]byte{0xba}, 70656)
				n, err := v.WriteAt(patch, 512)
				if mode == "readonly" {
					if err == nil || n != 0 {
						t.Fatal("readonly write accepted")
					}
					if bytes.Contains(peer.Events(), []byte{0x8a}) {
						t.Fatal("readonly sent WRITE")
					}
					return
				}
				if mode != "write" && mode != "sync-drop" && mode != "sync-status" {
					if err == nil || n != 0 {
						t.Fatal("unknown write was accepted", n, err)
					}
					events := peer.Events()
					if n, e := v.WriteAt(patch, 512); e == nil || n != 0 {
						t.Fatal("lost session reused")
					}
					if !bytes.Equal(events, peer.Events()) {
						t.Fatal("command replay")
					}
					return
				}
				if err != nil || n != len(patch) {
					t.Fatal(n, err)
				}
				err = v.Sync()
				if mode != "write" {
					if err == nil {
						t.Fatal("unknown cache sync accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := bytes.Clone(before)
				copy(want[512:], patch)
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatal("physical bytes corrupted", err)
				}
			} else {
				b := make([]byte, 70003)
				n, err := v.ReadAt(b, 511)
				if mode != "read" && mode != "noop" && mode != "separate-status" {
					if err == nil || n != 0 {
						t.Fatal("malformed read accepted", n, err)
					}
					return
				}
				if err != nil || n != len(b) || !bytes.Equal(b, before[511:511+len(b)]) {
					t.Fatal("unaligned read mismatch", n, err)
				}
			}
			t.Logf("ISCSI_TRANSPORT mode=%s commands=%x verified", mode, peer.Events())
		})
	}
}

func TestPDUFrameBounds(t *testing.T) {
	for _, n := range []int{0, 1, 3, 4, 65536} {
		p := pdu{data: bytes.Repeat([]byte{17}, n)}
		p.h[0] = 0x25
		var b bytes.Buffer
		if err := writePDU(&b, p); err != nil {
			t.Fatal(err)
		}
		q, err := readPDU(&b)
		if err != nil || !bytes.Equal(q.data, p.data) || b.Len() != 0 {
			t.Fatal(n, err)
		}
	}
	for _, mode := range []string{"header", "ahs", "oversize", "payload"} {
		var b bytes.Buffer
		var h [48]byte
		switch mode {
		case "header":
			b.Write(h[:47])
		case "ahs":
			h[4] = 1
			b.Write(h[:])
		case "oversize":
			h[5] = 1
			h[7] = 1
			b.Write(h[:])
		case "payload":
			h[7] = 5
			b.Write(h[:])
			b.WriteByte(0)
		}
		if _, err := readPDU(&b); err == nil {
			t.Fatal(mode)
		}
	}
}
