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
	"slices"
	"sync/atomic"
	"testing"

	"nfsclient/internal/testiscsi"
	"strings"
	"time"
)

func TestBlockWritableLayout(t *testing.T) {
	for _, mode := range []string{"valid", "gap", "readonly-alone", "overlap", "order", "hole", "read-overlap"} {
		t.Run(mode, func(t *testing.T) {
			extents := []encoder{blockExtentWire(1, 0, 1024, 0, 1), blockExtentWire(2, 0, 1024, 2048, 2), blockExtentWire(2, 1024, 512, 3072, 0)}
			switch mode {
			case "gap":
				extents[2] = blockExtentWire(2, 1536, 512, 3072, 0)
			case "readonly-alone":
				extents = extents[:1]
			case "overlap":
				extents[2] = blockExtentWire(2, 512, 1024, 3072, 0)
			case "order":
				extents[0], extents[1] = extents[1], extents[0]
			case "hole":
				extents[2] = blockExtentWire(2, 1024, 512, 3072, 3)
			case "read-overlap":
				extents[0] = blockExtentWire(1, 0, 1536, 0, 1)
			}
			var body, e encoder
			body.u32(uint32(len(extents)))
			for _, x := range extents {
				body = append(body, x...)
			}
			e.u32(0)
			e = append(e, make([]byte, 16)...)
			e.u32(1)
			e.u64(0)
			e.u64(1536)
			e.u32(2)
			e.u32(3)
			e.opaque(body)
			d := &decoder{b: e}
			_, ls := decodeLayoutRange(d, 0, 1536, 3)
			if (d.err == nil) != (mode == "valid") {
				t.Fatalf("layouts=%v error=%v", ls, d.err)
			}
		})
	}
}

func TestBlockWriteOptionRefusals(t *testing.T) {
	for _, mode := range []string{"approval", "layout", "ds", "spn", "tls", "parallel", "failover", "mirror", "refresh", "trunk", "relative"} {
		t.Run(mode, func(t *testing.T) {
			o := PNFSOptions{Layout: "block", BlockWrite: true, BlockVolumes: []string{filepath.Join(t.TempDir(), "volume")}}
			switch mode {
			case "approval":
				o.BlockWrite = false
			case "layout":
				o.Layout = "file"
			case "ds":
				o.DataServers = map[string]string{"a": "b"}
			case "spn":
				o.SPNs = map[string]string{"a": "b"}
			case "tls":
				o.TLSNames = map[string]string{"a": "b"}
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
			case "relative":
				o.BlockVolumes = []string{"volume"}
			}
			if _, err := validateBlockWriteOptions(o); err == nil {
				t.Fatal("invalid write profile accepted")
			}
		})
	}
}

func TestBlockWriteWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"cow", "invalid", "rw", "slice", "concat", "stripe", "large-block", "expanded", "alias", "signature", "capacity", "unaligned", "bad-block-size", "missing-block-size", "no-approval", "source-alias", "no-lock", "read-lock", "partial-lock", "past-eof", "hint-denied", "hint-omitted", "recall-before", "recall", "lease", "identity", "lock-change", "changed", "cancel", "short-source", "reader-cancel", "commit-error", "commit-drop", "commit-size", "return-error", "eof-identity"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runBlockWriteWire(t, minor, mode, "", false) })
		}
	}
}

func TestMITBlockWriteWire(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_GSS") != "1" {
		t.Skip("MIT fixture not enabled")
	}
	for _, minor := range []uint32{1, 2} {
		for _, sec := range []string{"krb5i", "krb5p"} {
			for _, tls := range []bool{false, true} {
				for _, mode := range []string{"cow", "invalid", "rw", "recall", "commit-error", "eof-identity"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%t/%s", minor, sec, tls, mode), func(t *testing.T) { runBlockWriteWire(t, minor, mode, sec, tls) })
				}
			}
		}
	}
}

type blockTestReader struct {
	r      io.Reader
	before func()
}

func (r blockTestReader) Read(p []byte) (int, error) { r.before(); return r.r.Read(p) }

func runBlockWriteWire(t *testing.T, minor uint32, mode, security string, secure bool) {
	t.Helper()
	journaled := strings.HasPrefix(mode, "journal-")
	mode = strings.TrimPrefix(mode, "journal-")
	transport := strings.HasPrefix(mode, "iscsi-")
	mode = strings.TrimPrefix(mode, "iscsi-")
	fault := ""
	if slices.Contains([]string{"write-drop", "write-status", "sync-drop", "sync-status", "r2t-offset", "r2t-lun", "r2t-tag", "r2t-sequence", "r2t-length"}, mode) {
		fault = mode
		mode = "cow"
	}
	path := filepath.Join(t.TempDir(), "volume")
	blockSize, sourceBase, imageSize := uint64(512), uint64(512), 8192
	if mode == "large-block" {
		blockSize, sourceBase, imageSize = 4096, 8192, 65536
	}
	image := make([]byte, imageSize)
	for i := range image {
		image[i] = byte(i*19 + 7)
	}
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(image)
	sid := bytes.Repeat([]byte{7}, 16)
	layoutSID := bytes.Repeat([]byte{8}, 16)
	binary.BigEndian.PutUint32(layoutSID, 1)
	input := bytes.Repeat([]byte("PATCH!"), 167)[:1000]
	const offset = uint64(101)
	var commits, returned, acquired atomic.Int32
	var v *v4Client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	extentState := uint32(2)
	if mode == "rw" {
		extentState = 0
	}
	target := uint64(2048)
	if mode == "large-block" {
		target = 32768
	}
	if mode == "concat" {
		target = 3584
	}
	if mode == "alias" {
		target = 512
	}
	if mode == "signature" {
		target = 6656
	}
	if mode == "capacity" {
		target = 7680
	}
	if mode == "unaligned" {
		target = 2304
	}
	physical := func(off uint64) uint64 {
		if mode == "slice" {
			return 512 + off
		}
		if mode == "stripe" {
			return (off/512%2)*4096 + (off/1024)*512 + off%512
		}
		return off
	}
	invalidOnly := mode == "invalid"
	var storage *testiscsi.Target
	if transport {
		opts := testiscsi.Options{Fault: fault}
		if mode == "cow" || mode == "invalid" || mode == "large-block" {
			opts.InvalidStart = target
			opts.InvalidEnd = target + ((1201+blockSize-1)/blockSize)*blockSize
		}
		storage = testiscsi.Start(t, path, opts)
	}
	v = peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 9:
			bits := readBitmap4(d)
			if slices.Equal(bits, []uint32{65}) {
				if mode == "missing-block-size" {
					e.u32(0)
					e.opaque(nil)
					break
				}
				bs := uint32(blockSize)
				if mode == "bad-block-size" {
					bs = 513
				}
				return replacementTestReply(bits, map[uint32]encoder{65: replacementTestU32(bs)}), 0, nil
			}
			return replacementTestReply(bits, map[uint32]encoder{1: replacementTestU32(1), 4: replacementTestU64(1201)}), 0, nil
		case 34:
			if !bytes.Equal(d.take(16), sid) || !slices.Equal(readBitmap4(d), []uint32{63}) {
				return nil, 0, errors.New("invalid hint owner")
			}
			hint := &decoder{b: d.opaque(64)}
			if hint.u32() != 3 || !bytes.Equal(hint.opaque(16), bytes.Repeat([]byte{255}, 8)) || hint.err != nil || len(hint.b) != 0 {
				return nil, 0, errors.New("false bounded I/O hint")
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
			requestOffset := uint64(0)
			expectedSID := sid
			if mode == "expanded" && acquired.Load() > 0 {
				requestOffset = 1024
				expectedSID = layoutSID
			}
			if d.u32() != 0 || d.u32() != 3 || d.u32() != 2 || d.u64() != requestOffset || d.u64() != math.MaxUint64 || d.u64() != 1 || !bytes.Equal(d.take(16), expectedSID) || d.u32() != 32768 {
				return nil, 0, errors.New("bad RW block grant request")
			}
			grantOffset, grantLength, storage := uint64(0), blockSize*3, target
			if mode == "expanded" {
				grantLength = 1024
				if acquired.Load() > 0 {
					grantOffset = 512
					storage = 4096
					binary.BigEndian.PutUint32(layoutSID, 2)
				}
			}
			acquired.Add(1)
			e.u32(1)
			e = append(e, layoutSID...)
			e.u32(1)
			e.u64(grantOffset)
			e.u64(grantLength)
			e.u32(2)
			e.u32(3)
			var body encoder
			n := uint32(1)
			if !invalidOnly && extentState == 2 {
				n = 2
			}
			body.u32(n)
			if n == 2 {
				body = append(body, blockExtentWire(0x45, grantOffset, grantLength, sourceBase+grantOffset, 1)...)
			}
			body = append(body, blockExtentWire(0x45, grantOffset, grantLength, storage, extentState)...)
			e.opaque(body)
		case 47:
			d.take(16)
			if d.u32() != 3 || d.u32() != 32768 || d.u32() != 0 {
				return nil, 0, errors.New("bad block device")
			}
			var body encoder
			count := uint32(1)
			if mode == "slice" {
				count = 2
			}
			if mode == "concat" || mode == "stripe" {
				count = 4
			}
			body.u32(count)
			body = append(body, simpleBlockVolume(-8, image[len(image)-8:])...)
			if mode == "slice" {
				body.u32(1)
				body.u64(512)
				body.u64(7168)
				body.u32(0)
			}
			if mode == "concat" || mode == "stripe" {
				for _, start := range []uint64{0, 4096} {
					body.u32(1)
					body.u64(start)
					body.u64(4096)
					body.u32(0)
				}
				if mode == "stripe" {
					body.u32(3)
					body.u64(512)
				} else {
					body.u32(2)
				}
				body.u32(2)
				body.u32(1)
				body.u32(2)
			}
			e.u32(3)
			e.opaque(body)
			e.u32(0)
			if mode == "recall-before" {
				v.recall.mu.Lock()
				v.recall.recalled = true
				v.recall.mu.Unlock()
			}
		case 49:
			if storage != nil {
				events := storage.Events()
				if len(events) == 0 || events[len(events)-1] != 0x91 || bytes.Count(events, []byte{0x91}) != int(commits.Load())+1 {
					return nil, 0, errors.New("LAYOUTCOMMIT before storage cache sync")
				}
			}
			index := uint64(commits.Add(1) - 1)
			logical := index * blockSize
			if d.u64() != logical || d.u64() != blockSize || d.boolean() || !bytes.Equal(d.take(16), layoutSID) || !d.boolean() || d.u64() != min(logical+blockSize, offset+uint64(len(input)))-1 || d.boolean() || d.u32() != 3 {
				return nil, 0, errors.New("invalid block LAYOUTCOMMIT header")
			}
			update := &decoder{b: d.opaque(256)}
			n := update.u32()
			if extentState == 0 {
				if n != 0 {
					return nil, 0, errors.New("initialized data falsely marked invalid")
				}
			} else {
				if n != 1 || !bytes.Equal(update.take(16), bytes.Repeat([]byte{0x45}, 16)) || update.u64() != logical || update.u64() != blockSize || update.u64() != 0 || update.u32() != 0 {
					return nil, 0, errors.New("incorrect initialized block commit list")
				}
			}
			if update.err != nil || len(update.b) != 0 {
				return nil, 0, errors.New("malformed block update")
			}
			// Independently compute the full expected physical block and inspect storage
			// before acknowledging metadata. Uninitialized destination bytes are never read.
			block := make([]byte, blockSize)
			if !invalidOnly {
				base := sourceBase
				if extentState == 0 {
					base = target
				}
				for i := range block {
					block[i] = image[physical(base+logical+uint64(i))]
				}
			}
			if logical+blockSize > 1201 {
				clear(block[max(uint64(1201), logical)-logical:])
			}
			start, stop := max(logical, offset), min(logical+blockSize, offset+uint64(len(input)))
			copy(block[start-logical:stop-logical], input[start-offset:stop-offset])
			destination := target + logical
			if mode == "expanded" && logical >= 512 {
				destination = 4096 + logical - 512
			}
			for i, b := range block {
				want[physical(destination+uint64(i))] = b
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, want) {
				return nil, 0, fmt.Errorf("COW bytes or unrelated regions corrupted: %v", err)
			}
			if mode == "commit-error" {
				return nil, 5, nil
			}
			if mode == "commit-drop" {
				return nil, 0, nil
			} // Truncated success body: outcome remains unknown.
			if mode == "commit-size" {
				e.u32(1)
				e.u64(1202)
			} else {
				e.u32(0)
			}
		case 51:
			returned.Add(1)
			if d.u32() != 0 || d.u32() != 3 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != math.MaxUint64 || !bytes.Equal(d.take(16), layoutSID) || len(d.opaque(8)) != 0 {
				return nil, 0, errors.New("bad layout return")
			}
			if mode == "return-error" {
				return nil, 5, nil
			}
			e.u32(0)
		default:
			return nil, 0, fmt.Errorf("unexpected MDS op %d; WRITE replay/fallback prohibited", code)
		}
		return e, 0, nil
	})
	v.recall = &layoutRecall{}
	v.c.config = &Config{PNFS: true, Timeout: time.Second}
	v.c.WriteSize = 129
	if security != "" {
		if secure {
			policy, server := pnfsTLSFixture(t, "data")
			pnfsMITWrapClient(t, v.c, security, nil, mitTLSOptions{client: policy, server: server(0), expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]})
		} else {
			pnfsMITWrapClient(t, v.c, security, nil, mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]})
		}
	}
	lock := &v4Lock{info: LockInfo{ID: 1, Write: mode != "read-lock", Length: LockToEOF}, sid: slices.Clone(sid), file: &v4Open{fh: []byte("file"), auth: v.c.Auth}}
	v.locks = map[uint64]*v4Lock{1: lock}
	if mode == "no-lock" {
		v.locks = nil
	}
	if mode == "partial-lock" {
		lock.info.Length = 1201
	}
	o := PNFSOptions{Layout: "block", BlockWrite: mode != "no-approval", BlockVolumes: []string{path}}
	if journaled {
		o.BlockJournal = filepath.Join(filepath.Dir(path), "journal")
		v.clientNonce = bytes.Repeat([]byte{17}, 16)
	}
	if storage != nil {
		o.BlockVolumes = nil
		o.BlockTargets = []string{storage.URL()}
		o.BlockInitiator = testiscsi.Initiator
	}
	var reader io.Reader = bytes.NewReader(input)
	if mode == "source-alias" {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		reader = file
	}
	if mode == "short-source" {
		reader = bytes.NewReader(input[:412])
	}
	if mode == "reader-cancel" {
		reader = blockTestReader{reader, cancel}
	}
	off := offset
	if mode == "past-eof" {
		off = 600
	}
	var progress []uint64
	n, err := v.c.WritePNFSRangeFromProgress(ctx, []byte("file"), off, uint64(len(input)), reader, o, func(done uint64) {
		progress = append(progress, done)
		switch mode {
		case "recall":
			v.recall.mu.Lock()
			v.recall.recalled = true
			v.recall.mu.Unlock()
		case "cancel":
			cancel()
		case "identity":
			v.c.Auth.UID++
		case "lock-change":
			lock.sid[0]++
		case "changed":
			if err := os.Truncate(path, 4096); err != nil {
				t.Fatal(err)
			}
		case "lease":
			v.leaseSeconds = 1
			old := time.Now().Add(-2 * time.Second)
			v.lastLease.Store(&old)
		case "eof-identity":
			if done == uint64(len(input)) {
				v.c.Auth.GID++
			}
		}
	})
	if journaled {
		info, e := InspectBlockJournal(o.BlockJournal)
		if e != nil {
			t.Fatal(e)
		}
		phase := "completed"
		if fault != "" {
			phase = "write-issued"
		} else if mode == "commit-drop" {
			phase = "commit-issued"
		}
		if info.Phase != phase || info.Progress != uint64(n) {
			t.Fatal("durable journal mismatch", info, n, err)
		}
		t.Logf("BLOCK_JOURNAL_WRITE minor=%d security=%s tls=%t phase=%s verified", minor, security, secure, phase)
	}
	if fault != "" {
		if n != 0 || err == nil || len(progress) != 0 || commits.Load() != 0 || returned.Load() != 0 || !v.stateLost.Load() {
			t.Fatal("unknown transport mutation acknowledged/replayed/returned", n, err, commits.Load(), returned.Load())
		}
		if bytes.Count(storage.Events(), []byte{0x8a}) != 1 {
			t.Fatal("storage WRITE replay", storage.Events())
		}
		if fault == "write-drop" || fault == "write-status" || fault == "sync-drop" || fault == "sync-status" {
			block := bytes.Clone(image[sourceBase : sourceBase+512])
			copy(block[offset:], input[:512-offset])
			copy(want[target:target+512], block)
		}
		actual, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(actual, want) {
			t.Fatal("unknown transport modified unexpected bytes", e)
		}
		t.Logf("BLOCK_STORAGE_FAULT minor=%d fault=%s commands=%x quarantine verified", minor, fault, storage.Events())
		return
	}

	success := mode == "cow" || mode == "invalid" || mode == "rw" || mode == "slice" || mode == "concat" || mode == "stripe" || mode == "large-block" || mode == "expanded"
	expectedCommits := int32(3)
	if mode == "large-block" {
		expectedCommits = 1
	}
	if success && (err != nil || n != int64(len(input)) || commits.Load() != expectedCommits || returned.Load() != 1) {
		t.Fatal(n, err, commits.Load(), returned.Load())
	}
	if !success && err == nil {
		t.Fatal("unsafe block write accepted", mode)
	}
	unknown := mode == "commit-error" || mode == "commit-drop" || mode == "commit-size"
	if unknown && (!v.stateLost.Load() || returned.Load() != 0 || n != 0 || len(progress) != 0 || commits.Load() != 1) {
		t.Fatal("unknown mutation was published/replayed/returned", n, err, commits.Load(), returned.Load())
	}
	if len(progress) > 0 && progress[len(progress)-1] != uint64(n) {
		t.Fatal("non-durable progress", progress, n)
	}
	actual, readErr := os.ReadFile(path)
	if mode != "changed" && (readErr != nil || !bytes.Equal(actual, want)) {
		t.Fatal("physical storage mismatch", mode, readErr, n, err)
	}
	t.Logf("BLOCK_WRITE transport=%t platform=%s minor=%d mode=%s security=%s tls=%t durable=%d commits=%d verified", transport, runtime.GOOS, minor, mode, security, secure, n, commits.Load())
}
