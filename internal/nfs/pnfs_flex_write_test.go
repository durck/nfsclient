package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlexWriteWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, major := range []uint32{3, 4} {
			for _, mirrors := range []int{1, 2} {
				for _, width := range []int{1, 3} {
					for _, parallel := range []int{1, 3} {
						for _, mode := range []string{"stable", "short", "unstable", "data-sync", "no-layoutcommit", "one-mirror", "rw-no-read", "denied", "zero", "commit-error", "commit-verifier", "layout-error", "recall", "cancel", "reader", "unapproved", "drop", "bad-stability", "oversize", "bad-xdr"} {
							t.Run(fmt.Sprintf("mds%d/ds%d/m%d/w%d/p%d/%s", minor, major, mirrors, width, parallel, mode), func(t *testing.T) { runFlexWriteWire(t, minor, major, mirrors, width, parallel, mode) })
						}
					}
				}
			}
		}
	}
}

func runFlexWriteWire(t *testing.T, minor, major uint32, mirrors, width, parallel int, mode string, profiles ...*flexMITProfile) {
	t.Helper()
	profile := flexMITSelected(profiles)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var v *v4Client
	var writes, commits, layoutCommits, returns, reports atomic.Int32
	var deviceQueries atomic.Int32
	refreshMode := ""
	if profile != nil {
		refreshMode = profile.refreshMode
	}
	notify := func() {
		v.recall.mu.Lock()
		v.recall.minor, v.recall.session = minor, bytes.Repeat([]byte{3}, 16)
		seq := v.recall.sequence + 1
		v.recall.mu.Unlock()
		if _, err := v.recall.callback(deviceCallbackCall(v.recall, seq, bytes.Repeat([]byte{1}, 16), 1, true)); err != nil {
			t.Error(err)
		}
	}
	payload := make([]byte, 96)
	for i := range payload {
		payload[i] = byte(i + 17)
	}
	stored := make([]map[uint64]byte, mirrors*width)
	o := PNFSOptions{Layout: "flex", Parallelism: parallel, DataServers: map[string]string{}}
	o.RefreshDevices = refreshMode != ""
	for id := 1; id <= mirrors*width; id++ {
		stored[id-1] = map[uint64]byte{}
		service := func(code uint32, d *decoder) (encoder, Status, error) {
			var e encoder
			if major == 3 {
				if string(d.opaque(128)) != fmt.Sprintf("ds%d", id) {
					return nil, 0, errors.New("wrong Flex write handle")
				}
			} else if code == 38 && !bytes.Equal(d.take(16), make([]byte, 16)) {
				return nil, 0, errors.New("write did not use global DS state")
			}
			offset := d.u64()
			if code == 5 {
				n := d.u32()
				if n == 0 || offset < 16 || offset+uint64(n) > 112 {
					return nil, 0, errors.New("invalid Flex COMMIT range")
				}
				commits.Add(1)
				if mode == "commit-error" {
					return nil, 5, nil
				}
				verifier := byte(1)
				if mode == "commit-verifier" {
					verifier = 2
				}
				return bytes.Repeat([]byte{verifier}, 8), 0, nil
			}
			if code != 38 {
				return nil, 0, fmt.Errorf("unexpected DS op %d", code)
			}
			var requested uint32
			if major == 3 {
				requested = d.u32()
			}
			if d.u32() != 2 {
				return nil, 0, errors.New("Flex WRITE must request FILE_SYNC")
			}
			data := d.opaque(128)
			if major == 3 && requested != uint32(len(data)) {
				return nil, 0, errors.New("NFSv3 count mismatch")
			}
			if offset < 16 || offset+uint64(len(data)) > 112 || len(data) == 0 || width > 1 && (int(offset/64%uint64(width)) != (id-1)%width || uint64(len(data)) > 64-offset%64) {
				return nil, 0, errors.New("Flex write stripe/range mismatch")
			}
			if mode == "one-mirror" && id <= (mirrors-1)*width {
				return nil, 0, errors.New("lower efficiency mirror written")
			}
			writes.Add(1)
			if refreshMode == "inflight" && id == 1 {
				notify()
			}
			if mode == "denied" {
				return nil, 13, nil
			}
			accepted := uint32(len(data))
			if mode == "short" {
				accepted = min(accepted, 7)
			}
			if mode == "zero" {
				accepted = 0
			}
			for i, b := range data[:accepted] {
				stored[id-1][offset+uint64(i)] = b
			}
			if mode == "bad-xdr" {
				return nil, 0, nil
			}
			stable := uint32(2)
			if mode == "unstable" || mode == "commit-error" || mode == "commit-verifier" {
				stable = 0
			}
			if mode == "data-sync" {
				stable = 1
			}
			if mode == "bad-stability" {
				stable = 3
			}
			if mode == "oversize" {
				accepted++
			}
			e.u32(accepted)
			e.u32(stable)
			e = append(e, bytes.Repeat([]byte{1}, 8)...)
			if mode == "recall" {
				v.recall.mu.Lock()
				v.recall.recalled = true
				v.recall.mu.Unlock()
			}
			return e, 0, nil
		}
		var peer *v4Client
		if major == 4 {
			s := &createSequenceServer{next: 22, clientID: uint64(100 + id), owner: fmt.Sprintf("ds%d", id), scope: "scope"}
			peer = s.peer(t, 2, nil, 0x40000, service)
		} else {
			client := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
				if program != nfsProgram || proc != 7 && proc != 21 {
					return nil, errors.New("unexpected loose DS RPC")
				}
				code := uint32(38)
				if proc == 21 {
					code = 5
				}
				body, status, err := service(code, d)
				if err != nil {
					return nil, err
				}
				var e encoder
				e.u32(uint32(status))
				e.u32(0)
				e.u32(0)
				return append(e, body...), nil
			})
			peer = &v4Client{c: client}
		}
		drop := 0
		if mode == "drop" {
			drop = 1
			if major == 4 {
				drop = 3
			}
		}
		endpoint := ""
		if profile != nil {
			endpoint = profile.endpoint(t, peer, &o, drop)
		} else {
			endpoint = pnfsPeerEndpoint(t, peer, drop)
		}
		o.DataServers[fmt.Sprintf("192.0.2.%d:2049", id)] = endpoint
	}
	if mode == "unapproved" {
		o.DataServers["198.51.100.1:2049"] = o.DataServers[fmt.Sprintf("192.0.2.%d:2049", mirrors*width)]
		delete(o.DataServers, fmt.Sprintf("192.0.2.%d:2049", mirrors*width))
	}
	flags := uint32(0)
	if mode == "one-mirror" {
		flags = 8
	}
	if mode == "no-layoutcommit" {
		flags = 1
	}
	if mode == "rw-no-read" {
		flags = 4
	}
	sid := bytes.Repeat([]byte{7}, 16)
	layoutSID := bytes.Repeat([]byte{8}, 16)
	v = peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 9:
			return replacementTestReply(readBitmap4(d), map[uint32]encoder{1: replacementTestU32(1), 4: replacementTestU64(128)}), 0, nil
		case 50:
			if d.u32() != 0 || d.u32() != 4 || d.u32() != 2 || d.u64() != 0 || d.u64() != ^uint64(0) || d.u64() != 1 || !bytes.Equal(d.take(16), sid) || d.u32() != 32768 {
				return nil, 0, errors.New("expected Flex RW LAYOUTGET")
			}
			e.u32(1)
			e = append(e, layoutSID...)
			e.u32(1)
			e.u64(0)
			e.u64(^uint64(0))
			e.u32(2)
			e.u32(4)
			body := flexTestBody(mirrors, width)
			binary.BigEndian.PutUint32(body[len(body)-8:], flags)
			e.opaque(body)
		case 47:
			deviceQueries.Add(1)
			id := int(d.take(16)[0])
			if d.u32() != 4 || d.u32() != 32768 {
				return nil, 0, errors.New("wrong write device request")
			}
			bits := readBitmap4(d)
			if o.RefreshDevices && !slices.Equal(bits, []uint32{1, 2}) || !o.RefreshDevices && len(bits) != 0 {
				return nil, 0, errors.New("wrong write notifications")
			}
			body := flexTestDevice(id)
			if major == 4 && !(mode == "loose" && id == mirrors*width) {
				binary.BigEndian.PutUint32(body[len(body)-20:], 4)
				binary.BigEndian.PutUint32(body[len(body)-16:], 2)
				binary.BigEndian.PutUint32(body[len(body)-4:], 1)
			}
			e.u32(4)
			e.opaque(body)
			if o.RefreshDevices {
				bitmap4(&e, 1, 2)
			} else {
				e.u32(0)
			}
		case 49:
			layoutCommits.Add(1)
			offset, n := d.u64(), d.u64()
			if flags&1 != 0 || n == 0 || offset < 16 || offset+n > 112 || d.boolean() || !bytes.Equal(d.take(16), layoutSID) || !d.boolean() || d.u64() != offset+n-1 || d.boolean() || d.u32() != 4 || len(d.opaque(64)) != 0 {
				return nil, 0, errors.New("invalid Flex LAYOUTCOMMIT")
			}
			if mode == "layout-error" {
				return nil, 5, nil
			}
			e.u32(0)
		case 51:
			returns.Add(1)
			if d.u32() != 0 || d.u32() != 4 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != ^uint64(0) || !bytes.Equal(d.take(16), layoutSID) {
				return nil, 0, errors.New("invalid Flex write LAYOUTRETURN")
			}
			body := &decoder{b: d.opaque(4096)}
			for n := body.u32(); n > 0; n-- {
				offset, length := body.u64(), body.u64()
				if offset < 16 || offset+length > 112 || !bytes.Equal(body.take(16), layoutSID) || body.u32() != 1 {
					return nil, 0, errors.New("invalid Flex write error range/state")
				}
				body.take(16)
				status, op := body.u32(), body.u32()
				if status == 0 || op != 38 && op != 5 {
					return nil, 0, errors.New("invalid Flex write error status/op")
				}
				reports.Add(1)
			}
			if body.u32() != 0 || body.err != nil || len(body.b) != 0 {
				return nil, 0, errors.New("invalid Flex write return body")
			}
			e.u32(0)
		default:
			return nil, 0, fmt.Errorf("unexpected MDS op %d", code)
		}
		return e, 0, nil
	})
	v.clientNonce = bytes.Repeat([]byte{6}, 16)
	v.recall = &layoutRecall{}
	v.c.config = &Config{PNFS: true, Timeout: time.Second}
	if profile != nil {
		profile.wrap(t, v.c)
	}
	v.c.WriteSize = 64
	v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Write: true, Length: LockToEOF}, sid: sid, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}}}
	var input io.Reader = bytes.NewReader(payload)
	if mode == "reader" {
		input = bytes.NewReader(nil)
	}
	var progress []uint64
	n, err := v.c.WritePNFSRangeFromProgress(ctx, []byte("file"), 16, uint64(len(payload)), input, o, func(n uint64) {
		progress = append(progress, n)
		if refreshMode == "immediate" && len(progress) == 1 {
			notify()
		}
		if mode == "cancel" {
			cancel()
		}
	})
	if profile != nil && mode == "loose" && profile.connections.Load() != 0 {
		t.Fatal("DS contacted before all device security profiles were validated")
	}
	success := mode == "stable" || mode == "short" || mode == "unstable" || mode == "data-sync" || mode == "no-layoutcommit" || mode == "one-mirror" || mode == "rw-no-read"
	if refreshMode == "inflight" {
		success = false
	}
	if (err == nil) != success {
		t.Fatal(n, err, returns.Load(), reports.Load())
	}
	if returns.Load() != 1 {
		t.Fatal("missing layout return/error report", n, err, returns.Load())
	}
	if success {
		if refreshMode == "immediate" && deviceQueries.Load() != int32(mirrors*width+1) {
			t.Fatal("required mirror was not refreshed", deviceQueries.Load())
		}
		if n != 96 || len(progress) == 0 || progress[len(progress)-1] != 96 {
			t.Fatal(n, progress)
		}
		for id, actual := range stored {
			expected := map[uint64]byte{}
			for i, b := range payload {
				pos := uint64(i + 16)
				if mode == "one-mirror" && id < (mirrors-1)*width {
					continue
				}
				if width == 1 || int(pos/64%uint64(width)) == id%width {
					expected[pos] = b
				}
			}
			if len(actual) != len(expected) {
				t.Fatal("mirror byte count", id, len(actual), len(expected))
			}
			for pos, b := range expected {
				if actual[pos] != b {
					t.Fatal("mirror data", id, pos)
				}
			}
		}
		if (commits.Load() > 0) != (mode == "unstable" || mode == "data-sync") || (layoutCommits.Load() > 0) != (mode != "no-layoutcommit") || reports.Load() != 0 {
			t.Fatal(commits.Load(), layoutCommits.Load(), reports.Load())
		}
	} else if mode == "reader" || mode == "unapproved" || mode == "loose" {
		if writes.Load() != 0 || n != 0 || v.stateLost.Load() {
			t.Fatal("preflight modified data or lost MDS", n, err)
		}
	} else if mode != "recall" && mode != "cancel" {
		if n != 0 || !v.stateLost.Load() || reports.Load() == 0 || len(progress) != 0 {
			t.Fatal("failed fragment credited or not quarantined", n, err, reports.Load(), progress)
		}
	}
}
