package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlexReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mirrors := range []int{1, 2} {
			for _, width := range []int{1, 3} {
				for _, parallel := range []int{1, 3} {
					for _, mode := range []string{"data", "short", "holes", "denied", "bad-count", "zero", "recall", "writer", "return-failure", "unapproved", "rw-no-read"} {
						t.Run(fmt.Sprintf("4.%d/m%d/w%d/p%d/%s", minor, mirrors, width, parallel, mode), func(t *testing.T) { runFlexReadWire(t, minor, mirrors, width, parallel, mode) })
					}
				}
			}
		}
	}
}

func runFlexReadWire(t *testing.T, minor uint32, mirrors, width, parallel int, mode string, profiles ...*flexMITProfile) {
	t.Helper()
	profile := flexMITSelected(profiles)
	refreshMode := ""
	if profile != nil {
		refreshMode = profile.refreshMode
	}
	var refreshed atomic.Bool
	var refreshQueries, refreshedReads atomic.Int32
	mirrorRecovery := profile != nil && profile.mirrorFailover
	mirrorDrop := mirrorRecovery && (mode == "data" || mode == "short" || mode == "holes" || mode == "return-failure" || mode == "second-loss" || mode == "disabled")
	var alternateReads atomic.Int32
	readCtx, stopRead := context.WithCancel(context.Background())
	defer stopRead()
	if profile != nil {
		profile.allowDSReadAbort = mode == "denied" || mode == "bad-count" || mode == "zero" || mode == "recall" || mode == "cancel" || refreshMode == "midbatch"
	}
	const size = 389
	openSID, layoutSID := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
	var v *v4Client
	var reads, returned, closed, reported atomic.Int32
	var firstReads atomic.Int32
	firstBatch := make(chan struct{})
	options := PNFSOptions{Layout: "flex", Parallelism: parallel, DataServers: map[string]string{}}
	options.RefreshDevices = refreshMode != ""
	notifyDevice := func() {
		v.recall.mu.Lock()
		v.recall.session, v.recall.minor = bytes.Repeat([]byte{3}, 16), minor
		sequence := v.recall.sequence + 1
		v.recall.mu.Unlock()
		kind := uint32(1)
		if refreshMode == "delete" {
			kind = 2
		}
		if _, err := v.recall.callback(deviceCallbackCall(v.recall, sequence, bytes.Repeat([]byte{byte((mirrors-1)*width + 1)}, 16), kind, refreshMode == "immediate")); err != nil {
			t.Error(err)
		}
	}
	if profile != nil {
		options.ReadFailover = profile.failover
		options.MirrorFailover = mirrorRecovery && mode != "disabled"
	}
	for id := 1; id <= mirrors*width; id++ {
		if profile != nil {
			s := &createSequenceServer{next: 22, clientID: uint64(100 + id), owner: fmt.Sprintf("ds%d", id), scope: "scope"}
			if mirrorRecovery || options.RefreshDevices {
				s.checkHandle = func(fh []byte) error {
					if string(fh) != fmt.Sprintf("ds%d", id) {
						return errors.New("mirror handle changed")
					}
					return nil
				}
			}
			service := func(code uint32, d *decoder) (encoder, Status, error) {
				wantState := make([]byte, 16)
				if mirrorRecovery {
					wantState = bytes.Repeat([]byte{byte(id)}, 16)
				}
				if code != 25 || !bytes.Equal(d.take(16), wantState) {
					return nil, 0, errors.New("wrong Flex READ state")
				}
				offset, count := d.u64(), d.u32()
				if offset >= size || count == 0 || count > 128 || offset+uint64(count) > size || !mirrorRecovery && id <= (mirrors-1)*width || width > 1 && (int(offset/64%uint64(width)) != (id-1)%width || uint64(count) > 64-offset%64) {
					return nil, 0, errors.New("wrong protected mirror/stripe/range")
				}
				readNumber := reads.Add(1)
				if mirrorRecovery && id <= (mirrors-1)*width {
					alternateReads.Add(1)
					if count > 31 {
						return nil, 0, errors.New("alternate read size exceeded")
					}
				}
				// Inject the first parallel error only after all peers consumed
				// their complete protected requests. Cancellation then tests
				// interrupted reads, not a deliberately truncated TLS write.
				if profile.allowDSReadAbort && width > 1 {
					if firstReads.Add(1) == int32(width) {
						close(firstBatch)
					}
					select {
					case <-firstBatch:
					case <-time.After(5 * time.Second):
						return nil, 0, errors.New("parallel protected READ barrier timed out")
					}
				}
				if mode == "cancel" {
					stopRead()
				}
				if refreshMode == "midbatch" && readNumber == 1 {
					refreshed.Store(true)
					notifyDevice()
				}
				if mode == "denied" {
					return nil, 13, nil
				}
				if mode == "bad-count" {
					return nil, 0, nil
				}
				n := count
				if mode == "short" {
					n = min(n, 7)
				}
				if mode == "holes" || mode == "zero" {
					n = 0
				}
				var e encoder
				if mode == "holes" || offset+uint64(n) == size {
					e.u32(1)
				} else {
					e.u32(0)
				}
				data := make([]byte, n)
				for j := range data {
					data[j] = byte((offset + uint64(j)) % 251)
				}
				e.opaque(data)
				if mode == "recall" {
					v.recall.mu.Lock()
					v.recall.recalled = true
					v.recall.mu.Unlock()
				}
				return e, 0, nil
			}
			dsMinor := minor
			if mirrorRecovery && id <= (mirrors-1)*width {
				dsMinor = 3 - minor
			}
			peer := s.peer(t, dsMinor, nil, 0x40000, service)
			drop := 0
			if profile.failover || mirrorDrop && (id > (mirrors-1)*width || mode == "second-loss" || mode == "disabled") {
				drop = 3
				if mode == "short" {
					drop = 4
				}
			}
			endpoint := profile.endpoint(t, peer, &options, drop)
			options.DataServers[fmt.Sprintf("192.0.2.%d:2049", id)] = endpoint
			if mirrorRecovery && id <= (mirrors-1)*width {
				options.SPNs[endpoint] = "nfs/server.nfs.test"
			}
			if profile.failover {
				other := s.peer(t, minor, nil, 0x40000, service)
				options.DataServers[fmt.Sprintf("198.51.100.%d:2049", id)] = profile.endpoint(t, other, &options, 0)
			}
			if options.RefreshDevices {
				other := s.peer(t, minor, nil, 0x40000, func(code uint32, d *decoder) (encoder, Status, error) {
					refreshedReads.Add(1)
					return service(code, d)
				})
				endpoint := profile.endpoint(t, other, &options, 0)
				options.DataServers[fmt.Sprintf("198.51.100.%d:2049", id)] = endpoint
				options.SPNs[endpoint] = "nfs/server.nfs.test"
			}
			continue
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		options.DataServers[fmt.Sprintf("192.0.2.%d:2049", id)] = l.Addr().String()
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			for {
				raw, err := readRecord(conn)
				if err != nil {
					if !errors.Is(err, io.EOF) && mode == "data" {
						t.Error(err)
					}
					return
				}
				d := &decoder{b: raw}
				xid := d.u32()
				for _, want := range []uint32{0, 2, nfsProgram, 3, 6, 1} {
					if d.u32() != want {
						t.Error("unexpected DS RPC/version/auth")
						return
					}
				}
				auth := &decoder{b: d.opaque(400)}
				auth.u32()
				auth.str()
				if auth.u32() != uint32(100+id) || auth.u32() != uint32(200+id) || auth.u32() != 0 || auth.err != nil || len(auth.b) != 0 {
					t.Error("synthetic identity or groups changed")
					return
				}
				if d.u32() != 0 || len(d.opaque(400)) != 0 || string(d.opaque(64)) != fmt.Sprintf("ds%d", id) {
					t.Error("wrong DS handle or verifier")
					return
				}
				offset, count := d.u64(), d.u32()
				if d.err != nil || len(d.b) != 0 || offset >= size || count == 0 || count > 128 || offset+uint64(count) > size || id <= (mirrors-1)*width || width > 1 && (int(offset/64%uint64(width)) != (id-1)%width || uint64(count) > 64-offset%64) {
					t.Errorf("wrong mirror/stripe/range: %d/%d/%d", id, offset, count)
					return
				}
				reads.Add(1)
				var body encoder
				if mode == "denied" {
					body.u32(13)
					body.u32(0)
				} else {
					body.u32(0)
					body.u32(0)
					n := count
					if mode == "short" {
						n = min(n, 7)
					}
					if mode == "holes" || mode == "zero" {
						n = 0
					}
					if mode == "bad-count" {
						body.u32(n + 1)
					} else {
						body.u32(n)
					}
					if mode == "holes" || offset+uint64(n) == size {
						body.u32(1)
					} else {
						body.u32(0)
					}
					data := make([]byte, n)
					for j := range data {
						data[j] = byte((offset + uint64(j)) % 251)
					}
					body.opaque(data)
					if mode == "recall" {
						v.recall.mu.Lock()
						v.recall.recalled = true
						v.recall.mu.Unlock()
					}
				}
				var reply encoder
				for _, value := range []uint32{xid, 1, 0, 0, 0, 0} {
					reply.u32(value)
				}
				reply = append(reply, body...)
				if _, err := conn.Write(record(reply, true)); err != nil {
					if mode == "data" || mode == "short" || mode == "holes" {
						t.Error(err)
					}
					return
				}
			}
		}()
		t.Cleanup(func() { l.Close(); <-done })
	}
	if mode == "alternate-unapproved" {
		endpoint := options.DataServers["192.0.2.1:2049"]
		delete(options.SPNs, endpoint)
		delete(options.TLSNames, endpoint)
		delete(options.DataServers, "192.0.2.1:2049")
	}
	if mode == "unapproved" {
		options.DataServers["198.51.100.1:2049"] = options.DataServers[fmt.Sprintf("192.0.2.%d:2049", mirrors*width)]
		delete(options.DataServers, fmt.Sprintf("192.0.2.%d:2049", mirrors*width))
	}
	v = peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
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
		case 50:
			if d.u32() != 0 || d.u32() != 4 || d.u32() != 1 || d.u64() != 0 || d.u64() != mathMaxUint64 || d.u64() != 1 || !bytes.Equal(d.take(16), openSID) || d.u32() != 32768 {
				return nil, 0, errors.New("incorrect Flex Files LAYOUTGET")
			}
			e.u32(1)
			e = append(e, layoutSID...)
			e.u32(1)
			e.u64(0)
			e.u64(mathMaxUint64)
			if mode == "rw-no-read" {
				e.u32(2)
			} else {
				e.u32(1)
			}
			e.u32(4)
			body := flexTestBody(mirrors, width, mirrorRecovery)
			if mode == "rw-no-read" {
				body[len(body)-5] = 7
			}
			e.opaque(body)
		case 47:
			device := d.take(16)
			if len(device) != 16 || !mirrorRecovery && int(device[0]) <= (mirrors-1)*width || !bytes.Equal(device, bytes.Repeat(device[:1], 16)) || d.u32() != 4 || d.u32() != 32768 {
				return nil, 0, errors.New("incorrect Flex Files GETDEVICEINFO")
			}
			bits := readBitmap4(d)
			if options.RefreshDevices && !slices.Equal(bits, []uint32{1, 2}) || !options.RefreshDevices && len(bits) != 0 {
				return nil, 0, errors.New("incorrect Flex notification request")
			}
			refresh := options.RefreshDevices && refreshed.Load() && int(device[0]) == (mirrors-1)*width+1
			if refresh {
				refreshQueries.Add(1)
				if refreshMode == "denied" {
					return nil, 13, nil
				}
			}
			e.u32(4)
			body := flexTestDevice(int(device[0]))
			if profile != nil && profile.failover {
				var paths encoder
				paths.u32(2)
				for _, prefix := range []string{"192.0.2", "198.51.100"} {
					paths.str("tcp")
					paths.str(fmt.Sprintf("%s.%d.8.1", prefix, device[0]))
				}
				body = append(paths, body[len(body)-24:]...)
			}
			if profile != nil && !(mode == "loose" && int(device[0]) == mirrors*width || mode == "alternate-loose" && device[0] == 1) {
				binary.BigEndian.PutUint32(body[len(body)-20:], 4)
				dsMinor := minor
				if mirrorRecovery && int(device[0]) <= (mirrors-1)*width {
					dsMinor = 3 - minor
					binary.BigEndian.PutUint32(body[len(body)-12:], 31)
				}
				binary.BigEndian.PutUint32(body[len(body)-16:], dsMinor)
				binary.BigEndian.PutUint32(body[len(body)-4:], 1)
			}
			if refresh {
				var addresses encoder
				addresses.u32(1)
				addresses.str("tcp")
				if refreshMode == "unapproved" {
					addresses.str("203.0.113.250.8.1")
				} else {
					addresses.str(fmt.Sprintf("198.51.100.%d.8.1", device[0]))
				}
				body = append(addresses, body[len(body)-24:]...)
				if refreshMode == "version" {
					binary.BigEndian.PutUint32(body[len(body)-16:], 3-minor)
				}
				if refreshMode == "limits" {
					binary.BigEndian.PutUint32(body[len(body)-12:], 31)
				}
			}
			e.opaque(body)
			if options.RefreshDevices && refreshMode != "unsupported" {
				bitmap4(&e, 1, 2)
			} else {
				e.u32(0)
			}
			if refresh && (refreshMode == "race" && refreshQueries.Load() == 1 || refreshMode == "flood") || refreshMode == "initial" && !refreshed.Load() {
				refreshed.Store(true)
				notifyDevice()
			}
		case 51:
			returned.Add(1)
			if d.u32() != 0 || d.u32() != 4 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != mathMaxUint64 || !bytes.Equal(d.take(16), layoutSID) {
				return nil, 0, errors.New("incorrect Flex Files LAYOUTRETURN")
			}
			body := &decoder{b: d.opaque(4096)}
			n := body.u32()
			for i := uint32(0); i < n; i++ {
				offset, length := body.u64(), body.u64()
				state := body.take(16)
				if offset >= size || length == 0 || length > 128 || !bytes.Equal(state, layoutSID) || body.u32() != 1 {
					return nil, 0, errors.New("invalid error report range/state")
				}
				dev := body.take(16)
				status, op := body.u32(), body.u32()
				want := uint32(5)
				if profile != nil && (profile.failover || mirrorDrop) {
					want = 6
				}
				if mode == "denied" {
					want = 13
				}
				if len(dev) != 16 || !mirrorRecovery && int(dev[0]) <= (mirrors-1)*width || status != want || op != 25 {
					return nil, 0, errors.New("invalid mapped DS error")
				}
				reported.Add(1)
			}
			if body.u32() != 0 || body.err != nil || len(body.b) != 0 {
				return nil, 0, errors.New("invalid Flex Files return body")
			}
			if mode == "return-failure" {
				return nil, Status(10025), nil
			}
			e.u32(0)
		case 4:
			closed.Add(1)
			d.u32()
			d.take(16)
			e = append(e, openSID...)
		default:
			return nil, 0, fmt.Errorf("unexpected MDS operation %d", code)
		}
		return e, 0, nil
	})
	v.recall = &layoutRecall{}
	v.c.config = &Config{PNFS: true, Timeout: time.Second}
	v.clientNonce = bytes.Repeat([]byte{6}, 16)
	if profile != nil {
		profile.wrap(t, v.c)
	}
	v.c.ReadSize = 128
	var out bytes.Buffer
	var writer io.Writer = &out
	if mode == "writer" {
		writer = pnfsShortWriter{}
	}
	verified := false
	progressCalls := 0
	n, err := v.c.ReadPNFSToProgressVerified(readCtx, []byte("file"), size, writer, options, func(uint64) {
		progressCalls++
		if options.RefreshDevices && refreshMode != "initial" && refreshMode != "midbatch" && progressCalls == min(width, parallel) {
			refreshed.Store(true)
			notifyDevice()
		}
	}, func() error {
		verified = true
		if returned.Load() != 0 || closed.Load() != 0 || out.Len() != size {
			return errors.New("incorrect verification boundary")
		}
		return nil
	})
	if options.RefreshDevices {
		success := refreshMode == "change" || refreshMode == "race" || refreshMode == "initial" || refreshMode == "immediate" || refreshMode == "midbatch"
		if success {
			expected := make([]byte, size)
			if mode != "holes" {
				for i := range expected {
					expected[i] = byte(i % 251)
				}
			}
			wantQueries := int32(1)
			if refreshMode == "race" {
				wantQueries++
			}
			if err != nil || n != size || !bytes.Equal(out.Bytes(), expected) || !verified || refreshedReads.Load() == 0 || refreshQueries.Load() != wantQueries {
				t.Fatal("Flex refresh failed", n, err, refreshedReads.Load(), refreshQueries.Load())
			}
		} else if err == nil || verified || refreshedReads.Load() != 0 {
			t.Fatal("unsafe Flex refresh succeeded", n, err, refreshedReads.Load())
		}
		if refreshMode == "flood" && refreshQueries.Load() != 8 {
			t.Fatal("Flex refresh budget changed", refreshQueries.Load())
		}
		wantReturns := int32(1)
		if refreshMode == "delete" {
			wantReturns = 2
		}
		if returned.Load() != wantReturns || closed.Load() != 1 {
			t.Fatal("Flex refresh lost cleanup", returned.Load(), closed.Load())
		}
		return
	}
	if profile != nil && (mode == "loose" || mode == "alternate-loose" || mode == "alternate-unapproved") && profile.connections.Load() != 0 {
		t.Fatal("DS contacted before all device security profiles were validated")
	}
	success := mode == "data" || mode == "short" || mode == "holes"
	if success {
		expected := make([]byte, size)
		if mode != "holes" {
			for i := range expected {
				expected[i] = byte(i % 251)
			}
		}
		if err != nil || n != size || !bytes.Equal(out.Bytes(), expected) || !verified {
			t.Fatal(n, err, reads.Load())
		}
	} else if err == nil {
		t.Fatal("expected failure", mode)
	}
	if returned.Load() != 1 || mode != "return-failure" && closed.Load() != 1 {
		t.Fatal("cleanup", returned.Load(), closed.Load(), err)
	}
	wantReport := mode == "denied" || mode == "bad-count" || mode == "zero" || profile != nil && profile.failover || mirrorDrop
	if mirrorRecovery && success && alternateReads.Load() == 0 {
		t.Fatal("no alternate mirror READ")
	}
	if mirrorRecovery && (!mirrorDrop || mode == "disabled") && alternateReads.Load() != 0 {
		t.Fatal("non-transport failure switched mirrors")
	}
	if (reported.Load() > 0) != wantReport {
		t.Fatal("missing or spurious DS error report", reported.Load(), err)
	}
	if (mode == "unapproved" || mode == "rw-no-read" || mode == "loose") && reads.Load() != 0 {
		t.Fatal("DS contacted before complete approval")
	}
}

const mathMaxUint64 = ^uint64(0)
