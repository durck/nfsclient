package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These explicit destinations come from the four-stripe example in RFC 8881
// 13.4, rotated by first_stripe_index=2. The oracle never calls position().
func TestPNFSStripedReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, packing := range []string{"dense", "sparse-many", "sparse-one", "sparse-mds"} {
			for _, readSize := range []uint32{23, 128} {
				for _, mode := range []string{"data", "holes", "unapproved", "denied", "cancel-hole", "recall-hole", "writer-hole"} {
					t.Run(fmt.Sprintf("4.%d/%s/%d/%s", minor, packing, readSize, mode), func(t *testing.T) {
						runPNFSStripedRead(t, minor, packing, readSize, mode)
					})
				}
			}
		}
	}
}

func TestPNFSParallelReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, packing := range []string{"dense", "sparse-many", "sparse-one", "sparse-mds"} {
			for _, parallel := range []int{2, 3, 8} {
				for _, mode := range []string{"data", "holes", "unapproved", "denied", "cancel-hole", "recall-hole", "writer-hole"} {
					t.Run(fmt.Sprintf("4.%d/%s/%d/%s", minor, packing, parallel, mode), func(t *testing.T) {
						runPNFSStripedRead(t, minor, packing, 128, mode, parallel)
					})
				}
			}
		}
	}
}

func TestPNFSParallelRequestsOverlap(t *testing.T) {
	// The first DS withholds its reply until both other DS READs arrive.
	// Sequential I/O cannot pass this barrier; no timing speedup is assumed.
	runPNFSStripedRead(t, 1, "dense", 128, "overlap", 3)
}

func TestPNFSSegmentReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, packing := range []string{"dense", "sparse-many", "sparse-one", "sparse-mds"} {
			for _, parallel := range []int{1, 3, 8} {
				for _, mode := range []string{"data", "holes", "unapproved", "denied", "cancel-hole", "recall-hole", "writer-hole"} {
					t.Run(fmt.Sprintf("4.%d/%s/%d/%s", minor, packing, parallel, mode), func(t *testing.T) { runPNFSStripedRead(t, minor, "segments-"+packing, 128, mode, parallel) })
				}
			}
		}
	}
}

type pnfsStripeRequest struct {
	server int
	handle string
	offset uint64
	count  uint32
	data   []byte
	eof    bool
}

func runPNFSStripedRead(t *testing.T, minor uint32, packing string, readSize uint32, mode string, parallel ...int) {
	t.Helper()
	gssSecurity, packing := pnfsGSSPacking(packing)
	secure := strings.HasPrefix(packing, "tls-")
	packing = strings.TrimPrefix(packing, "tls-")
	trunking := strings.HasPrefix(packing, "trunk-")
	packing = strings.TrimPrefix(packing, "trunk-")
	refreshMode := ""
	if strings.HasPrefix(packing, "refresh-") {
		refreshMode, packing, _ = strings.Cut(strings.TrimPrefix(packing, "refresh-"), "-")
	}
	readFailover := strings.HasPrefix(packing, "failover-")
	packing = strings.TrimPrefix(packing, "failover-")
	incremental := strings.HasPrefix(packing, "acquire-")
	packing = strings.TrimPrefix(packing, "acquire-")
	multipath := strings.HasPrefix(packing, "paths-")
	packing = strings.TrimPrefix(packing, "paths-")
	segmented := strings.HasPrefix(packing, "segments-")
	segmented = segmented || refreshMode == "initial"
	packing = strings.TrimPrefix(packing, "segments-")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const size = 8*64 + 17
	nonce, sid, layoutSID := bytes.Repeat([]byte{6}, 16), bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
	destinations := []int{1, 0, 2, 0, 1, 0, 2, 0, 1}
	denseHandles := []string{"c", "d", "a", "b", "c", "d", "a", "b", "c"}
	denseOffsets := []uint64{0, 0, 0, 0, 64, 64, 64, 64, 128}
	holeLengths := []int{64, 21, 0, 0, 64, 61, 64, 64, 9}
	var requests []pnfsStripeRequest
	var expected []byte
	for stripe, server := range destinations {
		length := min(64, size-stripe*64)
		present := length
		if mode != "data" && mode != "overlap" && mode != "unapproved" && mode != "denied" {
			present = holeLengths[stripe]
		}
		component := bytes.Repeat([]byte{byte('A' + stripe)}, present)
		expected = append(expected, component...)
		expected = append(expected, make([]byte, length-present)...)
		handle, offset := denseHandles[stripe], denseOffsets[stripe]
		if packing != "dense" {
			offset = uint64(stripe * 64)
			handle = []string{"s0", "s1", "s2"}[server]
			if packing == "sparse-one" {
				handle = "shared"
			}
			if packing == "sparse-mds" {
				handle = "file"
			}
		}
		if segmented && stripe >= 4 {
			if packing == "dense" {
				offset -= 64
			}
			if packing != "sparse-mds" {
				handle += "next"
			}
		}
		for at := 0; at < length; {
			count := min(int(readSize), length-at)
			if segmented && stripe*64+at < 95 {
				count = min(count, 95-stripe*64-at)
			}
			data := component[min(at, present):min(at+count, present)]
			// Exercise EOF, short-without-EOF and zero-without-EOF responses.
			eof := at+count >= present && stripe != 2 && stripe != 5
			requests = append(requests, pnfsStripeRequest{server, handle, offset + uint64(at), uint32(count), data, eof})
			at += count
		}
	}
	var next atomic.Int32
	seen := make([]atomic.Bool, len(requests))
	entered := make(chan int, 3)
	var connects, destroys, returns, closes, devices, layoutRequests atomic.Int32
	var v *v4Client
	options := PNFSOptions{DataServers: map[string]string{}, ReadFailover: readFailover}
	options.RefreshDevices = refreshMode != ""
	options.SessionTrunking = trunking
	if gssSecurity != "" {
		pnfsMITConfig(t, gssSecurity, "nfs/server.nfs.test")
		options.SPNs = map[string]string{}
	}
	var tlsPolicy TLSConfig
	var tlsPeer func(int) *tls.Config
	if secure {
		tlsPolicy, tlsPeer = pnfsTLSFixture(t, mode)
		options.TLSNames = map[string]string{}
	}
	if len(parallel) != 0 {
		options.Parallelism = parallel[0]
	}
	var unusedPath atomic.Int32
	var refused string
	var refusedListener net.Listener
	trapPath := func(address string) string {
		trap, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				conn, err := trap.Accept()
				if err != nil {
					return
				}
				unusedPath.Add(1)
				conn.Close()
			}
		}()
		t.Cleanup(func() { trap.Close(); <-done })
		return trap.Addr().String()
	}
	if multipath {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		refused = listener.Addr().String()
		// Keep the port reserved while the other listeners are allocated.
		// Otherwise Linux may reuse it for a DS and the "refused" alternate
		// unexpectedly routes a stripe to a different scripted server.
		refusedListener = listener
		t.Cleanup(func() { listener.Close() })
		options.DataServers["192.0.2.200:2049"] = trapPath("127.0.0.1:0")
	}
	serverCount := 3
	if options.RefreshDevices || trunking {
		serverCount = 6
	}
	var trunkMu [3]sync.Mutex
	var trunkSlot [3]uint32
	var bindings atomic.Int32
	for physical := range serverCount {
		server := physical % 3
		var handle string
		peer := peer4WithHandle(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
			var e encoder
			switch code {
			case 42:
				connects.Add(1)
				if mode == "init-denied" {
					d.take(len(d.b))
					return nil, Status(13), nil
				}
				if !bytes.Equal(d.take(8), nonce[:8]) || d.str() != fmt.Sprintf("nfs-viewer-%x", nonce) || d.u32() != 0x40000 || d.u32() != 0 || d.u32() != 0 {
					return nil, 0, errors.New("incorrect DS identity")
				}
				e.u64(123)
				e.u32(2)
				flags := uint32(0x40000)
				if trunking && physical >= 3 {
					flags |= 0x80000000
				}
				e.u32(flags)
				e.u32(0)
				e.u64(1)
				identity := physical
				if trunking {
					identity = server
				}
				e.opaque([]byte(fmt.Sprint(identity)))
				e.opaque([]byte("scope"))
				e.u32(0)
			case 43:
				if trunking && physical >= 3 {
					return nil, 0, errors.New("trunk alias created a second session")
				}
				if trunking {
					trunkMu[server].Lock()
					trunkSlot[server] = 1
					trunkMu[server].Unlock()
				}
				d.u64()
				d.u32()
				d.u32()
				d.take(56)
				d.u32()
				d.u32()
				e = append(e, bytes.Repeat([]byte{byte(physical + 10)}, 16)...)
				e.u32(2)
				e.u32(0)
				for range 2 {
					e.u32(0)
					e.u32(1 << 20)
					e.u32(1 << 20)
					e.u32(65536)
					e.u32(16)
					e.u32(1)
					e.u32(0)
				}
			case 41:
				if !trunking || physical < 3 || !bytes.Equal(d.take(16), bytes.Repeat([]byte{byte(server + 10)}, 16)) || d.u32() != 1 || d.boolean() {
					return nil, 0, errors.New("invalid public trunk binding")
				}
				bindings.Add(1)
				e = append(e, bytes.Repeat([]byte{byte(server + 10)}, 16)...)
				e.u32(1)
				e.u32(0)
			case 53:
				id, seq := d.take(16), d.u32()
				if trunking {
					trunkMu[server].Lock()
					defer trunkMu[server].Unlock()
					if !bytes.Equal(id, bytes.Repeat([]byte{byte(server + 10)}, 16)) || seq != trunkSlot[server] {
						return nil, 0, errors.New("public trunk changed shared slot")
					}
					trunkSlot[server]++
				}
				e = append(e, id...)
				e.u32(seq)
				d.take(12)
				for range 4 {
					e.u32(0)
				}
			case 25:
				if d.u32() != 0 || !bytes.Equal(d.take(12), sid[4:]) {
					return nil, 0, errors.New("incorrect DS stateid")
				}
				offset, count := d.u64(), d.u32()
				number := next.Add(1)
				i := int(number - 1)
				if options.Parallelism > 1 || refreshMode == "midbatch" {
					i = -1
					for j, request := range requests {
						if request.server == server && request.handle == handle && request.offset == offset {
							i = j
							break
						}
					}
				}
				if i < 0 || i >= len(requests) || seen[i].Swap(true) && refreshMode != "midbatch" {
					return nil, 0, fmt.Errorf("unexpected or replayed DS read: DS%d/%s/%d/%d index=%d", server, handle, offset, count, i)
				}
				r := requests[i]
				if server != r.server || handle != r.handle || offset != r.offset || count != r.count {
					return nil, 0, fmt.Errorf("request %d: got DS%d/%s/%d/%d, want DS%d/%s/%d/%d", i, server, handle, offset, count, r.server, r.handle, r.offset, r.count)
				}
				if refreshMode == "midbatch" && number == 1 {
					v.recall.mu.Lock()
					v.recall.session, v.recall.minor = bytes.Repeat([]byte{3}, 16), minor
					v.recall.mu.Unlock()
					if _, err := v.recall.callback(deviceCallbackCall(v.recall, 1, make([]byte, 16), 1, false)); err != nil {
						return nil, 0, err
					}
				}
				if mode == "overlap" && i < 3 {
					entered <- server
					if i == 0 {
						for range 3 {
							select {
							case <-entered:
							case <-time.After(500 * time.Millisecond):
								return nil, 0, errors.New("DS reads did not overlap")
							}
						}
					}
				}
				if mode == "denied" && server == 2 {
					return nil, Status(13), nil
				}
				if mode == "recall-hole" && len(r.data) < int(r.count) {
					v.recall.mu.Lock()
					v.recall.recalled = true
					v.recall.mu.Unlock()
				}
				if r.eof {
					e.u32(1)
				} else {
					e.u32(0)
				}
				e.opaque(r.data)
			case 44:
				d.take(16)
				destroys.Add(1)
			default:
				return nil, 0, fmt.Errorf("unexpected DS operation %d", code)
			}
			return e, 0, nil
		}, func(fh []byte) error { handle = string(fh); return nil }, options.Parallelism > 1 && (mode == "denied" || mode == "recall-hole"))
		dropReply := map[string]int{"exchange-lost": 1, "create-lost": 2, "read-lost": 3}[mode]
		endpoint := ""
		if gssSecurity != "" {
			tlsOptions := []mitTLSOptions{{allowReadAbort: refreshMode == "midbatch"}}
			if secure {
				tlsOptions[0].server, tlsOptions[0].client = tlsPeer(server), tlsPolicy
			}
			endpoint = pnfsMITEndpoint(t, peer.c.nfs.conn, nil, tlsOptions...)
			options.SPNs[endpoint] = "nfs/ds.nfs.test"
		} else if secure {
			endpoint = pnfsTLSPeerEndpoint(t, peer, tlsPeer(server), mode)
			if mode == "tls-name" {
				options.TLSNames[endpoint] = fmt.Sprintf("ds-%d.test", server)
			}
			if mode == "tls-wrong-name" {
				options.TLSNames[endpoint] = "wrong.example.invalid"
			}
		} else {
			endpoint = pnfsPeerEndpoint(t, peer, dropReply)
		}
		options.DataServers[fmt.Sprintf("192.0.2.%d:2049", physical+10)] = endpoint
		if multipath {
			options.DataServers[fmt.Sprintf("192.0.2.%d:2049", server+100)] = refused
		}
	}
	if mode == "all-paths-failed" {
		for advertised := range options.DataServers {
			options.DataServers[advertised] = refused
		}
	}
	if mode == "paths-unapproved" {
		delete(options.DataServers, "192.0.2.12:2049")
		delete(options.DataServers, "192.0.2.102:2049")
		delete(options.DataServers, "192.0.2.200:2049")
	}
	if mode == "unapproved" && !segmented {
		delete(options.DataServers, "192.0.2.12:2049")
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
			e = append(e, sid...)
			e.u32(1)
			e.u64(1)
			e.u64(1)
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 10:
			e.opaque([]byte("file"))
		case 50:
			page := int(layoutRequests.Add(1) - 1)
			if page >= 3 || page != 0 && !incremental && refreshMode != "delete" {
				return nil, 0, errors.New("unexpected additional LAYOUTGET")
			}
			offset, state := uint64(0), sid
			if incremental && page != 0 {
				offset, state = []uint64{0, 95, 256}[page], layoutSID
			}
			if d.u32() != 0 || d.u32() != 1 || d.u32() != 1 || d.u64() != offset || d.u64() != ^uint64(0) || d.u64() != 1 || !bytes.Equal(d.take(16), state) || d.u32() != 32768 {
				return nil, 0, errors.New("incorrect LAYOUTGET")
			}
			if page != 0 {
				binary.BigEndian.PutUint32(layoutSID, binary.BigEndian.Uint32(layoutSID)+1)
			}
			e.u32(1)
			e = append(e, layoutSID...)
			segments := []layoutSegmentSpec{{0, ^uint64(0), 0, 1, 1}}
			if segmented {
				segments = []layoutSegmentSpec{{0, 95, 0, 1, 1}, {95, 161, 0, 1, 1}, {256, ^uint64(0), 256, 1, 1}}
			}
			if incremental {
				segments = segments[page : page+1]
			}
			e.u32(uint32(len(segments)))
			for i, segment := range segments {
				if incremental {
					i = page
				}
				e.u64(segment.offset)
				e.u64(segment.length)
				e.u32(1)
				e.u32(1)
				deviceNumber := byte(i)
				if refreshMode == "initial" {
					deviceNumber = 0
				}
				body := encoder(bytes.Repeat([]byte{deviceNumber}, 16))
				util := uint32(64)
				if packing == "dense" {
					util |= 1
				}
				body.u32(util)
				body.u32(2)
				body.u64(segment.pattern)
				handles := []string{"a", "b", "c", "d"}
				switch packing {
				case "sparse-many":
					handles = []string{"s0", "s1", "s2"}
				case "sparse-one":
					handles = []string{"shared"}
				case "sparse-mds":
					handles = nil
				}
				body.u32(uint32(len(handles)))
				for _, h := range handles {
					if segmented && i == 2 {
						h += "next"
					}
					body.opaque([]byte(h))
				}
				e.opaque(body)
			}
		case 47:
			deviceIndex := int(devices.Add(1) - 1)
			refresh := options.RefreshDevices && deviceIndex > 0
			if options.RefreshDevices {
				deviceIndex = 0
			}
			if !bytes.Equal(d.take(16), bytes.Repeat([]byte{byte(deviceIndex)}, 16)) {
				return nil, 0, errors.New("wrong segment device")
			}
			d.take(8)
			bits := readBitmap4(d)
			if options.RefreshDevices && !slices.Equal(bits, []uint32{1, 2}) || !options.RefreshDevices && len(bits) != 0 {
				return nil, 0, errors.New("unexpected device notifications requested")
			}
			if refresh && refreshMode == "denied" {
				return nil, Status(13), nil
			}
			var body encoder
			body.u32(4)
			indices := []uint32{2, 0, 1, 0}
			if refresh && refreshMode == "topology" {
				indices[0] = 0
			}
			for _, i := range indices {
				body.u32(i)
			}
			body.u32(3)
			for server := range 3 {
				if multipath || trunking {
					body.u32(3)
				} else {
					body.u32(2)
				}
				body.str("tcp")
				body.str(fmt.Sprintf("192.0.2.%d.8.1", server+100)) // Unapproved alternate.
				body.str("tcp")
				if segmented && mode == "unapproved" && deviceIndex == 2 && server == 2 {
					body.str("192.0.2.250.8.1")
				} else if refresh && refreshMode == "unapproved" {
					body.str("192.0.2.250.8.1")
				} else if refresh {
					body.str(fmt.Sprintf("192.0.2.%d.8.1", server+13))
				} else {
					body.str(fmt.Sprintf("192.0.2.%d.8.1", server+10))
				}
				if multipath {
					body.str("tcp")
					body.str("192.0.2.200.8.1")
				}
				if trunking {
					body.str("tcp")
					body.str(fmt.Sprintf("192.0.2.%d.8.1", server+13))
				}
			}
			e.u32(1)
			e.opaque(body)
			if options.RefreshDevices && refreshMode != "unsupported" {
				bitmap4(&e, 1, 2)
			} else {
				e.u32(0)
			}
			if refresh && (refreshMode == "race" && devices.Load() == 2 || refreshMode == "flood") || refreshMode == "initial" && devices.Load() == 1 {
				v.recall.mu.Lock()
				notice := v.recall.devices[string(make([]byte, 16))]
				notice.generation++
				v.recall.devices[string(make([]byte, 16))] = notice
				v.recall.mu.Unlock()
			}
		case 51:
			returns.Add(1)
			if d.u32() != 0 || d.u32() != 1 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != ^uint64(0) || !bytes.Equal(d.take(16), layoutSID) || len(d.opaque(64)) != 0 {
				return nil, 0, errors.New("incorrect LAYOUTRETURN")
			}
			e.u32(0)
		case 4:
			closes.Add(1)
			d.u32()
			d.take(16)
			e = append(e, sid...)
		default:
			return nil, 0, fmt.Errorf("unexpected MDS operation %d (including forbidden READ fallback)", code)
		}
		return e, 0, nil
	})
	v.clientNonce, v.recall = nonce, &layoutRecall{}
	v.c.config, v.c.ReadSize = &Config{Timeout: time.Second, PNFS: true}, readSize
	if gssSecurity != "" {
		var tlsOptions []mitTLSOptions
		if secure {
			tlsOptions = []mitTLSOptions{{server: tlsPeer(0), client: tlsPolicy}}
		}
		pnfsMITWrapClient(t, v.c, gssSecurity, nil, tlsOptions...)
	}
	if secure {
		v.c.config.TLS = tlsPolicy
		v.c.config.Transport = "tcp"
	}
	var out bytes.Buffer
	var writer io.Writer = &out
	if mode == "writer-hole" {
		writer = &pnfsHoleWriter{remaining: 64}
	}
	var progress []uint64
	if refusedListener != nil {
		refusedListener.Close()
	}
	n, err := v.c.ReadPNFSToProgress(ctx, []byte("file"), size, writer, options, func(n uint64) {
		progress = append(progress, n)
		if options.RefreshDevices && refreshMode != "initial" && refreshMode != "midbatch" && len(progress) == min(max(options.Parallelism, 1), 3) {
			v.recall.mu.Lock()
			v.recall.session = bytes.Repeat([]byte{3}, 16)
			v.recall.minor = minor
			v.recall.mu.Unlock()
			kind := uint32(1)
			if refreshMode == "delete" {
				kind = 2
			}
			if _, err := v.recall.callback(deviceCallbackCall(v.recall, 1, make([]byte, 16), kind, refreshMode == "immediate")); err != nil {
				t.Error(err)
			}
		}
		if mode == "paths-cache" && len(progress) == 1 {
			// The initially refused address becomes reachable. Later groups
			// and segments must retain the failed-path decision for this read.
			trapPath(refused)
		}
		if mode == "cancel-hole" && n > 64 {
			cancel()
		}
	})
	if options.RefreshDevices {
		if refreshMode == "change" || refreshMode == "race" || refreshMode == "initial" || refreshMode == "immediate" || refreshMode == "midbatch" {
			wantQueries := int32(2)
			wantConnects := int32(3 + min(max(options.Parallelism, 1), 3))
			if refreshMode == "race" {
				wantQueries++
			}
			if refreshMode == "initial" {
				wantQueries, wantConnects = 4, 3
			}
			readsOK := int(next.Load()) == len(requests)
			if refreshMode == "midbatch" {
				readsOK = int(next.Load()) > len(requests) && int(next.Load()) <= len(requests)+max(options.Parallelism, 1)
			}
			if err != nil || n != size || !bytes.Equal(out.Bytes(), expected) || !readsOK || connects.Load() != wantConnects || devices.Load() != wantQueries {
				t.Fatalf("refresh failed: n=%d err=%v reads=%d connects=%d devices=%d", n, err, next.Load(), connects.Load(), devices.Load())
			}
		} else if err == nil || connects.Load() > int32(min(max(options.Parallelism, 1), 3)) {
			t.Fatal("unsafe refresh opened replacement DS or succeeded", n, err, connects.Load())
		}
		if refreshMode == "flood" && devices.Load() != 9 {
			t.Fatal("refresh budget changed", devices.Load())
		}
		wantReturns := int32(1)
		if refreshMode == "delete" {
			wantReturns = 2
		}
		if returns.Load() != wantReturns || closes.Load() != 1 {
			t.Fatal("refresh cleanup lost", returns.Load(), closes.Load())
		}
		return
	}
	if mode == "data" || mode == "holes" || mode == "overlap" || mode == "paths-cache" || mode == "tls-name" || mode == "tls-client-cert" {
		wantConnects := int32(3)
		if trunking {
			wantConnects = 6
		}
		if err != nil || n != size || !bytes.Equal(out.Bytes(), expected) || int(next.Load()) != len(requests) || connects.Load() != wantConnects {
			t.Fatalf("n=%d error=%v reads=%d connects=%d bytes_match=%v", n, err, next.Load(), connects.Load(), bytes.Equal(out.Bytes(), expected))
		}
		if len(progress) != len(requests) || progress[len(progress)-1] != size {
			t.Fatal("incorrect progress", progress)
		}
	} else if err == nil {
		t.Fatal("expected failure", mode)
	}
	if mode == "unapproved" && (next.Load() != 0 || connects.Load() != 0) {
		t.Fatal("DS contacted before validating every endpoint")
	}
	if segmented && mode != "paths-unapproved" && devices.Load() != 3 {
		t.Fatal("not all segment devices validated", devices.Load())
	}
	if incremental && layoutRequests.Load() != 3 {
		t.Fatal("incomplete incremental acquisition", layoutRequests.Load())
	}
	if unusedPath.Load() != 0 {
		t.Fatal("unused alternate contacted after NFS exchange or READ")
	}
	if strings.HasPrefix(mode, "tls-") && mode != "tls-name" && mode != "tls-client-cert" {
		if n != 0 || next.Load() != 0 || connects.Load() != 0 || returns.Load() != 1 || closes.Load() != 1 {
			t.Fatal("TLS failure sent NFS, published bytes or lost cleanup", n, err, connects.Load())
		}
	}
	if mode == "paths-unapproved" || mode == "all-paths-failed" {
		if n != 0 || next.Load() != 0 || connects.Load() != 0 || returns.Load() != 1 || closes.Load() != 1 {
			t.Fatal("failed path selection contacted a DS or lost cleanup", n, err, connects.Load())
		}
		if mode == "all-paths-failed" && !strings.Contains(err.Error(), "all approved pNFS data-server paths failed") {
			t.Fatal("missing path failure diagnostic", err)
		}
	}
	if strings.HasSuffix(mode, "-lost") {
		wantReads := int32(0)
		if mode == "read-lost" {
			wantReads = 1
		}
		if n != 0 || next.Load() != wantReads || connects.Load() != 1 || destroys.Load() != 0 || returns.Load() != 1 || closes.Load() != 1 || !errors.Is(err, ErrConnectionLost) {
			t.Fatal("unknown result replayed or cleanup lost", n, err, connects.Load(), next.Load())
		}
		return
	}
	if mode == "init-denied" {
		if n != 0 || next.Load() != 0 || connects.Load() != 1 || destroys.Load() != 0 || returns.Load() != 1 || closes.Load() != 1 || !errors.Is(err, Status(13)) {
			t.Fatal("initialization failure replayed or cleanup lost", n, err, connects.Load())
		}
		return
	}
	if mode == "denied" && (n > 128 || options.Parallelism <= 1 && n != 128 || !errors.Is(err, Status(13))) {
		t.Fatal("server error zero-filled or reordered", n, err)
	}
	if mode == "cancel-hole" && (!errors.Is(err, context.Canceled) || n <= 64 || n > 128) {
		t.Fatal("cancelled hole continued", n, err)
	}
	if mode == "recall-hole" && (n > 64 || options.Parallelism <= 1 && n != 64) {
		t.Fatal("recalled hole was written", n, err)
	}
	if mode == "writer-hole" && !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short writer ignored", n, err)
	}
	if trunking {
		if returns.Load() != 1 || closes.Load() != 1 || destroys.Load() != 3 || bindings.Load() != 3 {
			t.Fatal("shared session cleanup", returns.Load(), closes.Load(), destroys.Load(), bindings.Load())
		}
		return
	}
	if returns.Load() != 1 || closes.Load() != 1 || destroys.Load() > connects.Load() || (err == nil || options.Parallelism <= 1) && destroys.Load() != connects.Load() {
		t.Fatal("state cleanup", returns.Load(), closes.Load(), destroys.Load(), connects.Load())
	}
}

type pnfsHoleWriter struct{ remaining int }

func (w *pnfsHoleWriter) Write(p []byte) (int, error) {
	if w.remaining > 0 {
		w.remaining -= len(p)
		return len(p), nil
	}
	return len(p) - 1, nil
}

// A real loopback TCP endpoint fronts one strict scripted protocol peer.
func pnfsPeerEndpoint(t *testing.T, peer *v4Client, dropReply ...int) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		defer peer.c.nfs.conn.Close()
		upDone := make(chan struct{})
		go func() { io.Copy(peer.c.nfs.conn, c); peer.c.nfs.conn.Close(); close(upDone) }()
		if len(dropReply) == 0 || dropReply[0] == 0 {
			io.Copy(c, peer.c.nfs.conn)
		} else {
			for n := 1; ; n++ {
				data, err := readRecord(peer.c.nfs.conn)
				if err != nil || n == dropReply[0] {
					break
				}
				if _, err := c.Write(record(data, true)); err != nil {
					break
				}
			}
		}
		c.Close()
		<-upDone
	}()
	t.Cleanup(func() { l.Close(); <-done })
	return l.Addr().String()
}
