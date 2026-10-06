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
	"strings"
	"sync/atomic"
	"testing"

	"nfsclient/internal/testiscsi"
	"time"
)

func TestBlockGrowthWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"cow", "rw", "invalid", "gap", "empty", "empty-gap", "large-block", "no-extend", "hint-denied", "short-source", "commit-error", "commit-truncated", "commit-size", "gap-commit-error", "gap-recall", "recall", "cancel", "identity", "return-error"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runBlockGrowthWire(t, minor, mode, "", false) })
		}
	}
}

func TestMITBlockGrowthWire(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_GSS") != "1" {
		t.Skip("MIT fixture not enabled")
	}
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, tls := range []bool{false, true} {
				for _, mode := range []string{"cow", "gap", "empty", "gap-commit-error", "gap-recall", "commit-size"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%t/%s", minor, security, tls, mode), func(t *testing.T) { runBlockGrowthWire(t, minor, mode, security, tls) })
				}
			}
		}
	}
}

func runBlockGrowthWire(t *testing.T, minor uint32, mode, security string, secure bool) {
	t.Helper()
	transport := strings.HasPrefix(mode, "iscsi-")
	mode = strings.TrimPrefix(mode, "iscsi-")
	native4K := strings.HasPrefix(mode, "4kn-")
	mode = strings.TrimPrefix(mode, "4kn-")
	path := filepath.Join(t.TempDir(), "volume")
	image := make([]byte, 32768)
	for i := range image {
		image[i] = byte(i*31 + 17)
	}
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(image)
	oldSize, offset, blockSize := uint64(700), uint64(611), uint64(512)
	if strings.Contains(mode, "empty") {
		oldSize = 0
		offset = 0
	}
	if strings.Contains(mode, "gap") {
		offset = 2701
	}
	if mode == "large-block" {
		blockSize = 4096
	}
	patch := bytes.Repeat([]byte("new-extent"), 103)[:1025]
	end := offset + uint64(len(patch))
	rounded := ((end + blockSize - 1) / blockSize) * blockSize
	first := min(oldSize, offset) / blockSize * blockSize
	var storage *testiscsi.Target
	if transport {
		opts := testiscsi.Options{}
		if native4K {
			opts.SectorSize = 4096
		}
		if mode != "rw" {
			opts.InvalidStart = 8192
			opts.InvalidEnd = 8192 + rounded
		}
		storage = testiscsi.Start(t, path, opts)
	}
	currentSize := oldSize
	lockSID := bytes.Repeat([]byte{7}, 16)
	layoutSID := bytes.Repeat([]byte{8}, 16)
	binary.BigEndian.PutUint32(layoutSID, 1)
	var commits, returns, layouts atomic.Int32
	var v *v4Client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v = peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 9:
			bits := readBitmap4(d)
			if slices.Equal(bits, []uint32{65}) {
				return replacementTestReply(bits, map[uint32]encoder{65: replacementTestU32(uint32(blockSize))}), 0, nil
			}
			return replacementTestReply(bits, map[uint32]encoder{1: replacementTestU32(1), 4: replacementTestU64(currentSize)}), 0, nil
		case 34:
			if !bytes.Equal(d.take(16), lockSID) || !slices.Equal(readBitmap4(d), []uint32{63}) {
				return nil, 0, errors.New("bad block hint state")
			}
			value := &decoder{b: d.opaque(64)}
			if value.u32() != 3 || !bytes.Equal(value.opaque(16), bytes.Repeat([]byte{255}, 8)) || value.err != nil || len(value.b) != 0 {
				return nil, 0, errors.New("bad I/O deadline")
			}
			if mode == "hint-denied" {
				e.u32(0)
				return e, 22, nil
			}
			bitmap4(&e, 63)
		case 50:
			layouts.Add(1)
			if d.u32() != 0 || d.u32() != 3 || d.u32() != 2 || d.u64() != 0 || d.u64() != math.MaxUint64 || d.u64() != 1 || !bytes.Equal(d.take(16), lockSID) || d.u32() != 32768 {
				return nil, 0, errors.New("bad growth grant request")
			}
			e.u32(1)
			e = append(e, layoutSID...)
			e.u32(1)
			e.u64(0)
			e.u64(rounded)
			e.u32(2)
			e.u32(3)
			var body encoder
			state := uint32(2)
			if mode == "rw" {
				state = 0
			}
			n := uint32(1)
			if oldSize > 0 && mode != "invalid" && state == 2 {
				n = 2
			}
			body.u32(n)
			if n == 2 {
				body = append(body, blockExtentWire(0x45, 0, rounded, 1024, 1)...)
			}
			body = append(body, blockExtentWire(0x45, 0, rounded, 8192, state)...)
			e.opaque(body)
		case 47:
			d.take(16)
			if d.u32() != 3 || d.u32() != 32768 || d.u32() != 0 {
				return nil, 0, errors.New("bad growth device query")
			}
			var body encoder
			body.u32(1)
			body = append(body, simpleBlockVolume(-8, image[len(image)-8:])...)
			e.u32(3)
			e.opaque(body)
			e.u32(0)
		case 49:
			if storage != nil {
				events := storage.Events()
				if len(events) == 0 || events[len(events)-1] != 0x91 || bytes.Count(events, []byte{0x91}) != int(commits.Load())+1 {
					return nil, 0, errors.New("growth LAYOUTCOMMIT before cache sync")
				}
			}
			logical := first + uint64(commits.Add(1)-1)*blockSize
			stop := min(logical+blockSize, end)
			if d.u64() != logical || d.u64() != blockSize || d.boolean() || !bytes.Equal(d.take(16), layoutSID) || !d.boolean() || d.u64() != stop-1 || d.boolean() || d.u32() != 3 {
				return nil, 0, errors.New("bad extension commit header")
			}
			update := &decoder{b: d.opaque(128)}
			if mode == "rw" {
				if update.u32() != 0 {
					return nil, 0, errors.New("valid extent in initialization list")
				}
			} else {
				if update.u32() != 1 || !bytes.Equal(update.take(16), bytes.Repeat([]byte{0x45}, 16)) || update.u64() != logical || update.u64() != blockSize || update.u64() != 0 || update.u32() != 0 {
					return nil, 0, errors.New("bad growth initialization list")
				}
			}
			if update.err != nil || len(update.b) != 0 {
				return nil, 0, errors.New("trailing initialization list")
			}
			block := make([]byte, blockSize)
			for i := range block {
				pos := logical + uint64(i)
				if pos < oldSize && mode != "invalid" {
					base := uint64(1024)
					if mode == "rw" {
						base = 8192
					}
					block[i] = image[base+pos]
				}
			}
			for i := range block {
				pos := logical + uint64(i)
				if pos >= offset && pos < end {
					block[i] = patch[pos-offset]
				}
			}
			copy(want[8192+logical:8192+logical+blockSize], block)
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, want) {
				return nil, 0, fmt.Errorf("old prefix/gap/new EOF/unrelated image bytes differ: %v", err)
			}
			if strings.Contains(mode, "commit-error") {
				return nil, 5, nil
			}
			if mode == "commit-truncated" {
				return nil, 0, nil
			}
			currentSize = max(currentSize, stop)
			e.u32(1)
			replySize := currentSize
			if mode == "commit-size" {
				replySize++
			}
			e.u64(replySize)
			if mode == "gap-recall" {
				v.recall.mu.Lock()
				v.recall.recalled = true
				v.recall.mu.Unlock()
			}
		case 51:
			returns.Add(1)
			if d.u32() != 0 || d.u32() != 3 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != math.MaxUint64 || !bytes.Equal(d.take(16), layoutSID) || len(d.opaque(16)) != 0 {
				return nil, 0, errors.New("bad growth layout return")
			}
			if mode == "return-error" {
				return nil, 5, nil
			}
			e.u32(0)
		default:
			return nil, 0, fmt.Errorf("unexpected MDS op %d; no mutation replay or WRITE/SETATTR size fallback", code)
		}
		return e, 0, nil
	})
	v.recall = &layoutRecall{}
	v.c.config = &Config{PNFS: true, Timeout: time.Second}
	v.c.WriteSize = 129
	if security != "" {
		service := map[string]uint32{"krb5i": 2, "krb5p": 3}[security]
		if secure {
			policy, server := pnfsTLSFixture(t, "data")
			pnfsMITWrapClient(t, v.c, security, nil, mitTLSOptions{client: policy, server: server(0), expectedService: service})
		} else {
			pnfsMITWrapClient(t, v.c, security, nil, mitTLSOptions{expectedService: service})
		}
	}
	v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Write: true, Length: LockToEOF}, sid: lockSID, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}}}
	var input io.Reader = bytes.NewReader(patch)
	if mode == "short-source" {
		input = bytes.NewReader(patch[:414])
	}
	o := PNFSOptions{Layout: "block", BlockWrite: true, BlockVolumes: []string{path}, Extend: mode != "no-extend"}
	if storage != nil {
		o.BlockVolumes = nil
		o.BlockTargets = []string{storage.URL()}
		o.BlockInitiator = testiscsi.Initiator
	}
	var progress []uint64
	n, err := v.c.WritePNFSRangeFromProgress(ctx, []byte("file"), offset, uint64(len(patch)), input, o, func(n uint64) {
		if n == 0 {
			t.Fatal("gap zeroing reported as input progress")
		}
		progress = append(progress, n)
		switch mode {
		case "recall":
			v.recall.mu.Lock()
			v.recall.recalled = true
			v.recall.mu.Unlock()
		case "cancel":
			cancel()
		case "identity":
			v.c.Auth.GID++
		}
	})
	success := slices.Contains([]string{"cow", "rw", "invalid", "gap", "empty", "empty-gap", "large-block"}, mode)
	if success && (err != nil || n != int64(len(patch)) || currentSize != end || uint64(commits.Load()) != (rounded-first)/blockSize || returns.Load() != 1) {
		t.Fatal(n, err, currentSize, commits.Load(), returns.Load())
	}
	if !success && err == nil {
		t.Fatal("unsafe growth success")
	}
	unknown := strings.Contains(mode, "commit-error") || mode == "commit-truncated" || mode == "commit-size"
	if unknown && (n != 0 || len(progress) != 0 || commits.Load() != 1 || returns.Load() != 0 || !v.stateLost.Load()) {
		t.Fatal("unknown growth was acknowledged/replayed/returned", n, err)
	}
	if mode == "gap-recall" && (n != 0 || currentSize != 1024 || commits.Load() != 1 || len(progress) != 0) {
		t.Fatal("gap recall continued initialization", n, err, currentSize, progress)
	}
	if mode == "no-extend" && layouts.Load() != 0 {
		t.Fatal("implicit growth acquired a grant")
	}
	actual, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(actual, want) {
		t.Fatal("physical image mismatch", readErr)
	}
	t.Logf("BLOCK_GROWTH transport=%t platform=%s minor=%d mode=%s security=%s tls=%t durable=%d size=%d commits=%d verified", transport, runtime.GOOS, minor, mode, security, secure, n, currentSize, commits.Load())
}

func TestBlockNative4KnGrowth(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("4.%d", minor), func(t *testing.T) { runBlockGrowthWire(t, minor, "iscsi-4kn-large-block", "", false) })
	}
}
