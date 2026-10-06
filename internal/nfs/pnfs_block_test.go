package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"

	"nfs-viewer/internal/testiscsi"
	"strings"
	"time"
)

func blockExtentWire(id byte, offset, length, storage uint64, state uint32) encoder {
	e := encoder(bytes.Repeat([]byte{id}, 16))
	e.u64(offset)
	e.u64(length)
	e.u64(storage)
	e.u32(state)
	return e
}

func TestBlockDeviceValidation(t *testing.T) {
	for _, mode := range []string{"empty", "count", "type", "empty-signature", "signature-count", "signature-size", "cycle", "forward", "empty-children", "slice-overflow", "stripe-zero", "stripe-unaligned", "trailing", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			var e encoder
			e.u32(1)
			e = append(e, simpleBlockVolume(0, []byte{1})...)
			switch mode {
			case "empty":
				e = nil
				e.u32(0)
			case "count":
				e = nil
				e.u32(65)
			case "type":
				e = nil
				e.u32(1)
				e.u32(4)
			case "empty-signature":
				e = nil
				e.u32(1)
				e = append(e, simpleBlockVolume(0, nil)...)
			case "signature-count":
				e = nil
				e.u32(1)
				e.u32(0)
				e.u32(17)
			case "signature-size":
				e = nil
				e.u32(1)
				e.u32(0)
				e.u32(1)
				e.u64(0)
				e.u32(4097)
			case "cycle", "forward":
				e = nil
				e.u32(1)
				e.u32(1)
				e.u64(0)
				e.u64(512)
				if mode == "cycle" {
					e.u32(0)
				} else {
					e.u32(1)
				}
			case "empty-children":
				e = nil
				e.u32(1)
				e.u32(2)
				e.u32(0)
			case "slice-overflow":
				e = nil
				e.u32(1)
				e.u32(1)
				e.u64(1 << 63)
				e.u64(512)
				e.u32(0)
			case "stripe-zero", "stripe-unaligned":
				e = nil
				e.u32(1)
				e.u32(3)
				if mode == "stripe-zero" {
					e.u64(0)
				} else {
					e.u64(513)
				}
				e.u32(1)
				e.u32(0)
			case "trailing":
				e = append(e, 0)
			case "truncated":
				e = e[:len(e)-1]
			}
			d := &decoder{b: e}
			decodeBlockVolumes(d)
			if d.err == nil {
				t.Fatal("accepted malformed block topology")
			}
		})
	}
}

func TestBlockFileGuards(t *testing.T) {
	for _, mode := range []string{"missing", "directory", "empty", "unaligned", "alias", "changed", "substituted", "ambiguous", "signature", "negative-outside", "signature-second", "slice-capacity", "stripe-capacity"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "volume")
			data := bytes.Repeat([]byte{0x61}, 1024)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			paths := []string{path}
			switch mode {
			case "missing":
				paths[0] += "-missing"
			case "directory":
				paths[0] = filepath.Dir(path)
			case "empty":
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			case "unaligned":
				if err := os.Truncate(path, 1023); err != nil {
					t.Fatal(err)
				}
			case "alias":
				alias := path + "-alias"
				if err := os.Link(path, alias); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, alias)
			case "ambiguous":
				alias := path + "-copy"
				if err := os.WriteFile(alias, data, 0600); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, alias)
			}
			files, err := openBlockFiles(paths)
			if mode == "missing" || mode == "directory" || mode == "empty" || mode == "unaligned" || mode == "alias" {
				if err == nil {
					files.close()
					t.Fatal("unsafe image accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer files.close()
			if mode == "changed" {
				if err := os.Truncate(path, 512); err != nil {
					t.Fatal(err)
				}
				if files.check() == nil {
					t.Fatal("image resize missed")
				}
				return
			}
			if mode == "substituted" {
				if err := os.Rename(path, path+"-old"); err != nil {
					if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(32)) {
						if err := files.check(); err != nil {
							t.Fatal(err)
						}
						t.Log("Windows sharing mode refused substitution of the open image")
						return
					}
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if files.check() == nil {
					t.Fatal("path substitution missed")
				}
				return
			}
			var e encoder
			count := uint32(1)
			if mode == "slice-capacity" {
				count = 2
			}
			if mode == "stripe-capacity" {
				count = 3
			}
			e.u32(count)
			offset, signature := int64(0), []byte{0x61}
			if mode == "signature" {
				signature = []byte{0x62}
			}
			if mode == "negative-outside" {
				offset = -1025
			}
			if mode == "signature-second" {
				e.u32(0)
				e.u32(2)
				e.u64(0)
				e.opaque([]byte{0x61})
				e.u64(1)
				e.opaque([]byte{0x62})
			} else {
				e = append(e, simpleBlockVolume(offset, signature)...)
			}
			if mode == "slice-capacity" {
				e.u32(1)
				e.u64(512)
				e.u64(1024)
				e.u32(0)
			}
			if mode == "stripe-capacity" {
				e = append(e, simpleBlockVolume(0, signature)...)
				e.u32(3)
				e.u64(1536)
				e.u32(2)
				e.u32(0)
				e.u32(1)
			}
			d := &decoder{b: e}
			volumes := decodeBlockVolumes(d)
			if d.err != nil {
				t.Fatal(d.err)
			}
			if files.bind(volumes) == nil {
				t.Fatal("unsafe signature/capacity accepted")
			}
		})
	}
}

type blockWireCounts struct{ hints, layouts, devices, returned, closed atomic.Int32 }

func blockWireFixture(t *testing.T, minor uint32, mode string) (*v4Client, PNFSOptions, []byte, string, *blockWireCounts) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "volume")
	image := make([]byte, 4096)
	for i := 512; i < 1536; i++ {
		image[i] = byte(i*31 + 7)
	}
	copy(image[4088:], []byte{0x31, 0, 3, 4, 5, 6, 7, 8})
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	want := append(append(append([]byte(nil), image[512:1024]...), make([]byte, 512)...), image[1024:1153]...)
	if mode == "partial-layout" {
		want = append(append([]byte(nil), image[512:1024]...), image[1024:1153]...)
	}
	counts := &blockWireCounts{}
	openSID, layoutSID := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
	binary.BigEndian.PutUint32(layoutSID, 1)
	device := bytes.Repeat([]byte{0x45}, 16)
	v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 18:
			d.take(12)
			d.u64()
			d.opaque(128)
			d.u32()
			d.u32()
			d.str()
			e = append(e, openSID...)
			e.u32(1)
			e.u64(1)
			e.u64(1)
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 10:
			e.opaque([]byte("file"))
		case 34:
			counts.hints.Add(1)
			if !bytes.Equal(d.take(16), openSID) || !bytes.Equal(bitmapWords(readBitmap4(d)), bitmapWords([]uint32{63})) {
				return nil, 0, errors.New("incorrect block hint attributes")
			}
			value := &decoder{b: d.opaque(64)}
			if value.u32() != 3 {
				return nil, 0, errors.New("incorrect block hint type")
			}
			hint := &decoder{b: value.opaque(16)}
			if hint.u64() != math.MaxUint64 || hint.err != nil || len(hint.b) != 0 || value.err != nil || len(value.b) != 0 {
				return nil, 0, errors.New("incorrect maximum block I/O time")
			}
			if mode == "hint-denied" {
				e.u32(0)
				return e, 22, nil
			}
			if mode == "hint-omitted" {
				e.u32(0)
			} else {
				bitmap4(&e, 63)
			}
		case 50:
			counts.layouts.Add(1)
			if counts.hints.Load() != 1 || d.u32() != 0 || d.u32() != 3 || d.u32() != 1 {
				return nil, 0, errors.New("block LAYOUTGET before accepted hint or incorrect type")
			}
			offset := d.u64()
			if d.u64() != math.MaxUint64 || d.u64() != 1 || len(d.take(16)) != 16 || d.u32() != 32768 {
				return nil, 0, errors.New("incorrect block LAYOUTGET range")
			}
			if offset != 0 && mode != "partial-layout" && mode != "expanded" {
				return nil, 0, errors.New("unexpected incremental grant")
			}
			e.u32(1)
			if offset != 0 {
				binary.BigEndian.PutUint32(layoutSID, 2)
			}
			e = append(e, layoutSID...)
			e.u32(1)
			grantOffset := offset
			if mode == "expanded" && offset != 0 {
				grantOffset = 512
			}
			e.u64(grantOffset)
			length := uint64(1536)
			if mode == "partial-layout" {
				length = 512
			}
			if mode == "expanded" {
				length = 1024
			}
			if mode == "empty" {
				return nil, 0, errors.New("empty source requested a layout")
			}
			e.u64(length)
			e.u32(1)
			e.u32(3)
			var body encoder
			if mode == "expanded" {
				if offset == 0 {
					body.u32(1)
					body = append(body, blockExtentWire(0x45, 0, 1024, 0, 1)...)
				} else {
					body.u32(2)
					body = append(body, blockExtentWire(0, 512, 512, math.MaxUint64, 3)...)
					body = append(body, blockExtentWire(0x45, 1024, 512, 512, 1)...)
				}
			} else if mode == "partial-layout" {
				body.u32(1)
				body = append(body, blockExtentWire(0x45, offset, 512, offset, 1)...)
			} else {
				body.u32(3)
				storage := uint64(0)
				if mode == "capacity" {
					storage = 3584
				}
				body = append(body, blockExtentWire(0x45, 0, 512, storage, 1)...)
				body = append(body, blockExtentWire(0, 512, 512, math.MaxUint64, 3)...)
				lastID := byte(0x45)
				if mode == "second-device" {
					lastID = 0x46
				}
				body = append(body, blockExtentWire(lastID, 1024, 512, 512, 1)...)
			}
			if mode == "bad-layout" {
				body = append(body, 0)
			}
			e.opaque(body)
		case 47:
			counts.devices.Add(1)
			id := d.take(16)
			if d.u32() != 3 || d.u32() != 32768 || d.u32() != 0 {
				return nil, 0, errors.New("incorrect block GETDEVICEINFO")
			}
			if mode == "device-denied" {
				return nil, 13, nil
			}
			var body encoder
			body.u32(2)
			signature := image[4088:]
			if mode == "signature" || mode == "second-device" && !bytes.Equal(id, device) {
				signature = []byte("unknown")
			}
			body = append(body, simpleBlockVolume(-8, signature)...)
			body.u32(1)
			body.u64(512)
			body.u64(3072)
			body.u32(0)
			if mode == "bad-device" {
				body = append(body, 0)
			}
			if mode == "device-type" {
				e.u32(1)
			} else {
				e.u32(3)
			}
			e.opaque(body)
			if mode == "notification" {
				bitmap4(&e, 1)
			} else {
				e.u32(0)
			}
		case 51:
			counts.returned.Add(1)
			if d.u32() != 0 || d.u32() != 3 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != math.MaxUint64 || !bytes.Equal(d.take(16), layoutSID) || len(d.opaque(32)) != 0 {
				return nil, 0, errors.New("incorrect block LAYOUTRETURN")
			}
			if mode == "return-failure" {
				return nil, 10025, nil
			}
			e.u32(0)
		case 4:
			counts.closed.Add(1)
			d.u32()
			e = append(e, d.take(16)...)
			if mode == "close-failure" {
				return nil, 10025, nil
			}
		default:
			return nil, 0, fmt.Errorf("unexpected MDS operation %d; no READ or WRITE fallback is permitted", code)
		}
		return e, 0, nil
	})
	v.recall = &layoutRecall{}
	v.c.config = &Config{PNFS: true, Timeout: time.Second}
	v.c.ReadSize = 129 // Unaligned user reads may cross logical block boundaries.
	options := PNFSOptions{Layout: "block", BlockVolumes: []string{path}}
	if mode == "ambiguous" {
		copyPath := path + "-copy"
		if err := os.WriteFile(copyPath, image, 0600); err != nil {
			t.Fatal(err)
		}
		options.BlockVolumes = append(options.BlockVolumes, copyPath)
	}
	return v, options, want, path, counts
}

func bitmapWords(bits []uint32) []byte { var e encoder; bitmap4(&e, bits...); return e }

func runBlockReadWire(t *testing.T, minor uint32, mode, security string, secure bool) {
	t.Helper()
	transport := strings.HasPrefix(mode, "iscsi-")
	mode = strings.TrimPrefix(mode, "iscsi-")
	v, o, want, path, counts := blockWireFixture(t, minor, mode)
	if transport {
		peer := testiscsi.Start(t, path, testiscsi.Options{})
		o.BlockVolumes = nil
		o.BlockTargets = []string{peer.URL()}
		o.BlockInitiator = testiscsi.Initiator
	}
	if security != "" {
		if secure {
			policy, server := pnfsTLSFixture(t, "data")
			pnfsMITWrapClient(t, v.c, security, nil, mitTLSOptions{client: policy, server: server(0), expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]})
		} else {
			pnfsMITWrapClient(t, v.c, security, nil, mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]})
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	var writer io.Writer = &out
	if mode == "writer" {
		writer = pnfsShortWriter{}
	}
	verified := false
	progress := func(done uint64) {
		if done == 0 {
			return
		}
		switch mode {
		case "cancel":
			cancel()
		case "recall":
			v.recall.mu.Lock()
			v.recall.recalled = true
			v.recall.mu.Unlock()
		case "identity":
			v.c.Auth.UID++
		case "groups":
			v.c.Auth.Groups[0]++
		case "changed":
			if err := os.Truncate(path, 512); err != nil {
				t.Fatal(err)
			}
		case "lease":
			v.leaseSeconds = 1
			expired := time.Now().Add(-2 * time.Second)
			v.lastLease.Store(&expired)
		case "eof-identity":
			if done == uint64(len(want)) {
				v.c.Auth.GID++
			}
		}
	}
	if mode == "groups" {
		v.c.Auth.Groups = []uint32{21}
	}
	if mode == "expired" {
		v.leaseSeconds = 1
		expired := time.Now().Add(-2 * time.Second)
		v.lastLease.Store(&expired)
	}
	if mode == "empty" {
		want = nil
	}
	n, err := v.c.ReadPNFSToProgressVerified(ctx, []byte("file"), uint64(len(want)), writer, o, progress, func() error {
		verified = true
		if counts.returned.Load() != 0 || counts.closed.Load() != 0 || !bytes.Equal(out.Bytes(), want) {
			t.Fatal("verification must follow exact bytes and precede cleanup")
		}
		if mode == "verify-failure" {
			return errors.New("source changed")
		}
		if mode == "verify-recall" {
			v.recall.mu.Lock()
			v.recall.recalled = true
			v.recall.mu.Unlock()
		}
		return nil
	})
	ok := mode == "ok" || mode == "partial-layout" || mode == "expanded" || mode == "empty"
	if ok {
		if err != nil || n != int64(len(want)) || !verified || !bytes.Equal(out.Bytes(), want) {
			t.Fatal(n, err, verified, out.Len())
		}
	} else if err == nil {
		t.Fatal("expected block refusal", mode)
	}
	if mode == "signature" || mode == "ambiguous" || mode == "capacity" || mode == "second-device" || mode == "bad-device" || mode == "device-type" || mode == "device-denied" || mode == "notification" {
		if n != 0 || out.Len() != 0 || verified {
			t.Fatal("device failure leaked transfer bytes")
		}
	}
	if mode == "hint-denied" || mode == "hint-omitted" {
		if counts.layouts.Load() != 0 || counts.devices.Load() != 0 || counts.returned.Load() != 0 {
			t.Fatal("hint refusal reached layout or device operations")
		}
	} else if mode == "bad-device" || mode == "device-type" || mode == "notification" || mode == "bad-layout" {
		if counts.returned.Load() != 0 || !v.stateLost.Load() {
			t.Fatal("malformed reply did not quarantine metadata state")
		}
	} else if mode != "empty" && counts.returned.Load() != 1 {
		t.Fatal("layout not returned exactly once", counts.returned.Load())
	}
	if ok && counts.closed.Load() != 1 {
		t.Fatal("OPEN not closed")
	}
	t.Logf("BLOCK_READ transport=%t minor=%d mode=%s security=%s tls=%t bytes=%d checked", transport, minor, mode, security, secure, n)
}

func TestBlockExpandedGrantBoundary(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("4.%d", minor), func(t *testing.T) { runBlockReadWire(t, minor, "expanded", "", false) })
	}
}

func TestBlockReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"ok", "partial-layout", "empty", "hint-denied", "hint-omitted", "signature", "ambiguous", "capacity", "second-device", "bad-device", "device-type", "device-denied", "notification", "bad-layout", "cancel", "recall", "identity", "groups", "eof-identity", "changed", "lease", "writer", "verify-failure", "verify-recall", "return-failure", "close-failure"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runBlockReadWire(t, minor, mode, "", false) })
		}
	}
}

func TestMITBlockReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"ok", "expanded", "signature", "eof-identity", "verify-failure"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls%t/%s", minor, security, secure, mode), func(t *testing.T) { runBlockReadWire(t, minor, mode, security, secure) })
				}
			}
		}
	}
}

func TestBlockExtentValidation(t *testing.T) {
	for _, mode := range []string{"data", "hole", "gap", "overlap", "unaligned", "empty", "overflow", "storage-overflow", "rw", "invalid", "state", "outside", "trailing", "truncated", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			var e encoder
			e.u32(2)
			first := blockExtentWire(1, 0, 512, 512, 1)
			second := blockExtentWire(2, 512, 512, 0, 1)
			switch mode {
			case "hole":
				second = blockExtentWire(0, 512, 512, math.MaxUint64, 3)
			case "gap":
				second = blockExtentWire(2, 1024, 512, 0, 1)
			case "overlap":
				second = blockExtentWire(2, 0, 512, 0, 1)
			case "unaligned":
				first = blockExtentWire(1, 0, 513, 512, 1)
			case "empty":
				first = blockExtentWire(1, 0, 0, 512, 1)
			case "overflow":
				second = blockExtentWire(2, math.MaxUint64-511, 512, 0, 1)
			case "storage-overflow":
				second = blockExtentWire(2, 512, 512, math.MaxUint64-511, 1)
			case "rw":
				second = blockExtentWire(2, 512, 512, 0, 0)
			case "invalid":
				second = blockExtentWire(2, 512, 512, 0, 2)
			case "state":
				second = blockExtentWire(2, 512, 512, 0, 4)
			case "outside":
				first = blockExtentWire(1, 512, 512, 0, 1)
			case "too-many":
				e = nil
				e.u32(1025)
			}
			e = append(e, first...)
			e = append(e, second...)
			if mode == "trailing" {
				e = append(e, 0)
			}
			if mode == "truncated" {
				e = e[:len(e)-1]
			}
			d := &decoder{b: e}
			extents := decodeBlockExtents(d, 0, 1024)
			if mode == "data" || mode == "hole" {
				if d.err != nil || len(extents) != 2 {
					t.Fatal(extents, d.err)
				}
			} else if d.err == nil {
				t.Fatal("accepted malformed block layout")
			}
		})
	}
}

func simpleBlockVolume(offset int64, signature []byte) encoder {
	var e encoder
	e.u32(0)
	e.u32(1)
	e.u64(uint64(offset))
	e.opaque(signature)
	return e
}

func TestBlockVolumeMapping(t *testing.T) {
	for _, kind := range []string{"simple", "slice", "concat", "stripe", "nested"} {
		t.Run(kind, func(t *testing.T) {
			var paths []string
			data := [][]byte{bytes.Repeat([]byte{0x41}, 4096), bytes.Repeat([]byte{0x42}, 4096)}
			for i, b := range data {
				copy(b[len(b)-8:], []byte{byte(i + 1), 0, 3, 4, 5, 6, 7, 8})
				path := filepath.Join(t.TempDir(), "volume")
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, path)
			}
			files, err := openBlockFiles(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer files.close()
			var e encoder
			count := uint32(1)
			if kind == "slice" {
				count = 2
			}
			if kind == "concat" || kind == "stripe" {
				count = 3
			}
			if kind == "nested" {
				count = 4
			}
			e.u32(count)
			e = append(e, simpleBlockVolume(-8, data[0][4088:])...)
			want := data[0][:2048]
			if kind == "slice" {
				e.u32(1)
				e.u64(512)
				e.u64(2048)
				e.u32(0)
				want = data[0][512:2560]
			}
			if kind == "concat" || kind == "stripe" || kind == "nested" {
				e = append(e, simpleBlockVolume(-8, data[1][4088:])...)
				if kind == "concat" {
					e.u32(2)
					e.u32(2)
					e.u32(0)
					e.u32(1)
					want = append(append([]byte(nil), data[0]...), data[1][:1024]...)
				} else {
					e.u32(3)
					e.u64(512)
					e.u32(2)
					e.u32(0)
					e.u32(1)
					want = append(append(append(append([]byte(nil), data[0][:512]...), data[1][:512]...), data[0][512:1024]...), data[1][512:1024]...)
				}
			}
			if kind == "nested" {
				e.u32(1)
				e.u64(512)
				e.u64(1024)
				e.u32(2)
				want = want[512:1536]
			}
			d := &decoder{b: e}
			volumes := decodeBlockVolumes(d)
			if d.err != nil {
				t.Fatal(d.err)
			}
			if err := files.bind(volumes); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			if err := readBlockVolume(volumes, len(volumes)-1, got, 0); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("logical volume mapping corrupted bytes")
			}
		})
	}
}

func TestBlockOptionRefusals(t *testing.T) {
	base := PNFSOptions{Layout: "block", BlockVolumes: []string{filepath.Join(t.TempDir(), "volume")}}
	if _, err := validatePNFSOptions(base); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"none", "relative", "duplicate", "ds", "spn", "tls", "parallel", "failover", "mirror", "refresh", "trunk", "extend", "file"} {
		t.Run(mode, func(t *testing.T) {
			o := base
			switch mode {
			case "none":
				o.BlockVolumes = nil
			case "relative":
				o.BlockVolumes = []string{"volume"}
			case "duplicate":
				o.BlockVolumes = []string{base.BlockVolumes[0], base.BlockVolumes[0]}
			case "ds":
				o.DataServers = map[string]string{"192.0.2.1:2049": "192.0.2.1:2049"}
			case "spn":
				o.SPNs = map[string]string{"192.0.2.1:2049": "nfs/test"}
			case "tls":
				o.TLSNames = map[string]string{"192.0.2.1:2049": "test"}
			case "parallel":
				o.Parallelism = 2
			case "failover":
				o.ReadFailover = true
			case "mirror":
				o.MirrorFailover = true
			case "refresh":
				o.RefreshDevices = true
			case "trunk":
				o.SessionTrunking = true
			case "extend":
				o.Extend = true
			case "file":
				o.Layout = "file"
				o.DataServers = map[string]string{"192.0.2.1:2049": "192.0.2.1:2049"}
			}
			if _, err := validatePNFSOptions(o); err == nil {
				t.Fatal("accepted incompatible block options")
			}
		})
	}
}
