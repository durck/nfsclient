package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// This test observer forwards original RPC records, including fragment markers.
// It never builds a server response or changes a request's NFS arguments.
type pnfsMultiReadEvent struct {
	ServerID                            int
	XID                                 uint32
	Opcode                              uint32
	PayloadSHA256                       string
	Offset                              uint64
	Count                               uint32
	RequestedAt, ForwardedAt, RepliedAt time.Time
	RequestedNS, ForwardedNS, RepliedNS int64
	WireStatus, ReturnedBytes           uint32
}

// JSON preserves wall-clock timestamps but drops time.Time's monotonic reading.
// Keep one process origin across observers and resets so serialized events can
// prove order across distinct relays even when the host wall clock steps back.
var pnfsMultiTimeOrigin = time.Now()

func pnfsMultiTimestamp() (time.Time, int64) {
	now := time.Now()
	return now, now.Sub(pnfsMultiTimeOrigin).Nanoseconds()
}

type pnfsMultiSnapshot struct {
	Connections                     map[int]int
	Reads                           []pnfsMultiReadEvent
	BarrierMatched, BarrierTimedOut bool
	Errors                          []string
}

type pnfsMultiBoundary struct {
	offset            uint64
	left, right       map[int]bool
	done              chan struct{}
	matched, timedOut bool
}

type pnfsMultiObserver struct {
	mu          sync.Mutex
	connections map[int]int
	reads       []*pnfsMultiReadEvent
	barrier     *pnfsMultiBoundary
	errors      []string
}

// Reset and arm are called between transfers. Old in-flight responses retain
// their own event pointers and cannot be mistaken for a new transfer's reads.
func (o *pnfsMultiObserver) reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if b := o.barrier; b != nil && !b.matched && !b.timedOut {
		close(b.done)
	}
	o.connections, o.reads, o.barrier, o.errors = nil, nil, nil, nil
}

func (o *pnfsMultiObserver) armBoundary(boundary uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if b := o.barrier; b != nil && !b.matched && !b.timedOut {
		close(b.done)
	}
	o.barrier = &pnfsMultiBoundary{offset: boundary, left: make(map[int]bool), right: make(map[int]bool), done: make(chan struct{})}
}

func (o *pnfsMultiObserver) snapshot() pnfsMultiSnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := pnfsMultiSnapshot{Connections: make(map[int]int), Errors: append([]string(nil), o.errors...)}
	for server, n := range o.connections {
		s.Connections[server] = n
	}
	for _, r := range o.reads {
		s.Reads = append(s.Reads, *r)
	}
	if o.barrier != nil {
		s.BarrierMatched, s.BarrierTimedOut = o.barrier.matched, o.barrier.timedOut
	}
	return s
}

func (o *pnfsMultiObserver) problem(server int, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.errors = append(o.errors, fmt.Sprintf("server %d: %v", server, err))
}

func (o *pnfsMultiObserver) observe(ctx context.Context, server int, r pnfsMultiReadEvent) *pnfsMultiReadEvent {
	o.mu.Lock()
	r.ServerID = server
	r.RequestedAt, r.RequestedNS = pnfsMultiTimestamp()
	o.reads = append(o.reads, &r)
	b := o.barrier
	wait := b != nil && !b.matched && !b.timedOut && r.Count != 0 &&
		(r.Offset == b.offset || (r.Offset < b.offset && uint64(r.Count) == b.offset-r.Offset))
	if wait {
		if r.Offset == b.offset {
			b.right[server] = true
		} else {
			b.left[server] = true
		}
		for left := range b.left {
			for right := range b.right {
				if left != right && !b.matched {
					b.matched = true
					close(b.done)
				}
			}
		}
	}
	o.mu.Unlock()
	if wait {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-b.done:
		case <-ctx.Done():
		case <-timer.C:
			o.mu.Lock()
			if o.barrier == b && !b.matched && !b.timedOut {
				b.timedOut = true
				close(b.done)
			}
			o.mu.Unlock()
		}
	}
	return &r
}

// cut closes current connections without removing the listener: a reconnect
// attempt remains observable, so the integration test can detect retries.
func newPNFSMultiRelay(t *testing.T, target string, serverID int, o *pnfsMultiObserver) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	var wg sync.WaitGroup
	cut := func() {
		mu.Lock()
		defer mu.Unlock()
		for c := range active {
			c.Close()
		}
	}
	wg.Add(1)
	t.Cleanup(func() { cancel(); l.Close(); cut(); wg.Wait() })
	go func() {
		defer wg.Done()
		for {
			down, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[down] = true
			mu.Unlock()
			o.mu.Lock()
			if o.connections == nil {
				o.connections = make(map[int]int)
			}
			o.connections[serverID]++
			o.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer down.Close()
				defer func() { mu.Lock(); delete(active, down); mu.Unlock() }()
				up, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", target)
				if err != nil {
					if ctx.Err() == nil {
						o.problem(serverID, err)
					}
					return
				}
				defer up.Close()
				mu.Lock()
				active[up] = true
				mu.Unlock()
				defer func() { mu.Lock(); delete(active, up); mu.Unlock() }()
				connCtx, connCancel := context.WithCancel(ctx)
				defer connCancel()
				closed := make(chan struct{})
				context.AfterFunc(connCtx, func() { down.Close(); up.Close(); close(closed) })
				defer func() { connCancel(); <-closed }()
				var pendingMu sync.Mutex
				pending := make(map[uint32]*pnfsMultiReadEvent)
				replied := make(chan struct{})
				go func() {
					defer close(replied)
					defer connCancel()
					for {
						record, wire, err := readPNFSMultiRecord(up)
						if err != nil {
							pnfsMultiRelayError(o, serverID, connCtx, err)
							return
						}
						if len(record) >= 8 && binary.BigEndian.Uint32(record[4:]) == 1 {
							xid := binary.BigEndian.Uint32(record)
							pendingMu.Lock()
							r := pending[xid]
							delete(pending, xid)
							pendingMu.Unlock()
							if r != nil {
								status, n, parseErr := parsePNFSMultiReply(record, r.Opcode)
								o.mu.Lock()
								r.RepliedAt, r.RepliedNS = pnfsMultiTimestamp()
								r.WireStatus, r.ReturnedBytes = status, n
								o.mu.Unlock()
								if parseErr != nil {
									o.problem(serverID, parseErr)
								}
							}
						}
						if _, err := io.Copy(down, bytes.NewReader(wire)); err != nil {
							pnfsMultiRelayError(o, serverID, connCtx, err)
							return
						}
					}
				}()
				defer func() { connCancel(); <-replied }()
				for {
					record, wire, err := readPNFSMultiRecord(down)
					if err != nil {
						pnfsMultiRelayError(o, serverID, connCtx, err)
						return
					}
					if call, ok := parsePNFSMultiCall(record); ok {
						r := o.observe(connCtx, serverID, call)
						if connCtx.Err() != nil {
							return
						}
						pendingMu.Lock()
						pending[r.XID] = r
						pendingMu.Unlock()
						o.mu.Lock()
						r.ForwardedAt, r.ForwardedNS = pnfsMultiTimestamp()
						o.mu.Unlock()
					}
					if _, err := io.Copy(up, bytes.NewReader(wire)); err != nil {
						pnfsMultiRelayError(o, serverID, connCtx, err)
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String(), cut
}

func pnfsMultiRelayError(o *pnfsMultiObserver, server int, ctx context.Context, err error) {
	if ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		o.problem(server, err)
	}
}

func readPNFSMultiRecord(r io.Reader) (record, wire []byte, err error) {
	for range 1024 {
		var prefix [4]byte
		if _, err := io.ReadFull(r, prefix[:]); err != nil {
			return nil, nil, err
		}
		marker := binary.BigEndian.Uint32(prefix[:])
		size := int(marker & 0x7fffffff)
		if size > (2<<20)-len(record) {
			return nil, nil, errors.New("pNFS observer RPC record exceeds 2 MiB")
		}
		start := len(record)
		record = append(record, make([]byte, size)...)
		if _, err := io.ReadFull(r, record[start:]); err != nil {
			return nil, nil, err
		}
		wire = append(wire, prefix[:]...)
		wire = append(wire, record[start:]...)
		if marker&0x80000000 != 0 {
			return record, wire, nil
		}
	}
	return nil, nil, errors.New("pNFS observer RPC fragment count exceeds 1024")
}

type pnfsMultiDecoder struct {
	b   []byte
	bad bool
}

func (d *pnfsMultiDecoder) take(n uint64) []byte {
	if n > uint64(len(d.b)) {
		d.bad = true
		return nil
	}
	b := d.b[:int(n)]
	d.b = d.b[int(n):]
	return b
}

func (d *pnfsMultiDecoder) u32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (d *pnfsMultiDecoder) opaque(limit uint32) []byte {
	n := d.u32()
	if n > limit {
		d.bad = true
		return nil
	}
	b := d.take(uint64(n))
	d.take(uint64((4 - n%4) % 4))
	return b
}

// Observe exact DS READ/WRITE compounds. Other compounds pass through untouched.
func parsePNFSMultiCall(record []byte) (pnfsMultiReadEvent, bool) {
	d := pnfsMultiDecoder{b: record}
	r := pnfsMultiReadEvent{XID: d.u32()}
	if d.u32() != 0 || d.u32() != 2 || d.u32() != 100003 || d.u32() != 4 || d.u32() != 1 || d.u32() != 1 {
		return r, false
	}
	d.opaque(400) // AUTH_SYS credential; do not record caller identity.
	d.u32()
	d.opaque(400) // RPC verifier.
	d.opaque(1024)
	minor := d.u32()
	if (minor != 1 && minor != 2) || d.u32() != 3 || d.u32() != 53 {
		return r, false
	}
	d.take(32) // SEQUENCE arguments.
	if d.u32() != 22 {
		return r, false
	}
	d.opaque(128) // PUTFH.
	r.Opcode = d.u32()
	if r.Opcode != 25 && r.Opcode != 38 {
		return r, false
	}
	d.take(16) // READ/WRITE stateid.
	r.Offset = uint64(d.u32())<<32 | uint64(d.u32())
	if r.Opcode == 25 {
		r.Count = d.u32()
	} else {
		if d.u32() > 2 {
			return r, false
		}
		data := d.opaque(1 << 20)
		r.Count = uint32(len(data))
		r.PayloadSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	return r, !d.bad && len(d.b) == 0
}

func parsePNFSMultiReply(record []byte, wanted ...uint32) (status, returned uint32, err error) {
	opcode := uint32(25)
	if len(wanted) > 0 {
		opcode = wanted[0]
	}
	if opcode != 25 && opcode != 38 {
		return 0, 0, errors.New("unsupported observed operation")
	}
	fail := func() (uint32, uint32, error) { return ^uint32(0), 0, errors.New("invalid observed pNFS READ reply") }
	d := pnfsMultiDecoder{b: record}
	d.u32()
	if d.u32() != 1 || d.u32() != 0 {
		return fail()
	}
	d.u32()
	d.opaque(400)
	if d.u32() != 0 {
		return fail()
	}
	status = d.u32()
	d.opaque(1024)
	n := d.u32()
	if n < 1 || n > 3 {
		return fail()
	}
	for i, op := range []uint32{53, 22, opcode} {
		if uint32(i) >= n || d.u32() != op {
			return fail()
		}
		opStatus := d.u32()
		if opStatus != 0 {
			if !d.bad && uint32(i)+1 == n && opStatus == status && len(d.b) == 0 {
				return status, 0, nil
			}
			return fail()
		}
		switch op {
		case 53:
			d.take(36)
		case 38:
			returned = d.u32()
			if d.u32() > 2 {
				return fail()
			}
			d.take(8)
		case 25:
			if d.u32() > 1 {
				return fail()
			}
			returned = uint32(len(d.opaque(2 << 20)))
		}
	}
	if d.bad || status != 0 || len(d.b) != 0 {
		return fail()
	}
	return status, returned, nil
}

// Synthetic records below test only the observer; integration tests connect
// this relay to real Ganesha/LizardFS and never use these packet builders.
func pnfsMultiUnitRecords() (call, reply []byte) {
	for _, n := range []uint32{7, 0, 2, 100003, 4, 1, 1, 20, 0, 0, 25001, 25000, 0, 0, 0, 0, 2, 3, 53} {
		call = binary.BigEndian.AppendUint32(call, n)
	}
	call = append(call, make([]byte, 32)...)
	for _, n := range []uint32{22, 3} {
		call = binary.BigEndian.AppendUint32(call, n)
	}
	call = append(call, 'f', 'h', '1', 0)
	call = binary.BigEndian.AppendUint32(call, 25)
	call = append(call, make([]byte, 16)...)
	call = binary.BigEndian.AppendUint64(call, (1<<32)+1024)
	call = binary.BigEndian.AppendUint32(call, 5)
	for _, n := range []uint32{7, 1, 0, 0, 0, 0, 0, 0, 3, 53, 0} {
		reply = binary.BigEndian.AppendUint32(reply, n)
	}
	reply = append(reply, make([]byte, 36)...)
	for _, n := range []uint32{22, 0, 25, 0, 0, 5} {
		reply = binary.BigEndian.AppendUint32(reply, n)
	}
	reply = append(reply, 'h', 'e', 'l', 'l', 'o', 0, 0, 0)
	return
}

func pnfsMultiUnitWire(record []byte) []byte {
	wire := binary.BigEndian.AppendUint32(nil, 13)
	wire = append(wire, record[:13]...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(record)-13)|0x80000000)
	return append(wire, record[13:]...)
}

func TestPNFSMultiObserverProtocol(t *testing.T) {
	call, reply := pnfsMultiUnitRecords()
	r, ok := parsePNFSMultiCall(call)
	if !ok || r.XID != 7 || r.Offset != (1<<32)+1024 || r.Count != 5 {
		t.Fatalf("READ arguments not observed: %+v, %t", r, ok)
	}
	if status, n, err := parsePNFSMultiReply(reply); err != nil || status != 0 || n != 5 {
		t.Fatalf("READ payload not observed: %d, %d, %v", status, n, err)
	}
	for end := range len(call) {
		if _, ok := parsePNFSMultiCall(call[:end]); ok {
			t.Fatalf("accepted truncated call ending at %d", end)
		}
	}
	for end := range len(reply) {
		if _, _, err := parsePNFSMultiReply(reply[:end]); err == nil {
			t.Fatalf("accepted truncated reply ending at %d", end)
		}
	}
	for _, index := range []int{4, 8, 12, 16, 20, 24, 64, 68, 72, 108, 120} {
		other := append([]byte(nil), call...)
		binary.BigEndian.PutUint32(other[index:], 999)
		if _, ok := parsePNFSMultiCall(other); ok {
			t.Fatalf("observed a different RPC/compound at word offset %d", index)
		}
	}
	if _, ok := parsePNFSMultiCall(append(append([]byte(nil), call...), 0)); ok {
		t.Fatal("accepted trailing call data")
	}
	if _, _, err := parsePNFSMultiReply(append(append([]byte(nil), reply...), 0)); err == nil {
		t.Fatal("accepted trailing reply data")
	}
	// The compound can stop at SEQUENCE, PUTFH, or READ with an NFS error.
	for i, end := range []int{44, 88, 96} {
		failed := append([]byte(nil), reply[:end]...)
		binary.BigEndian.PutUint32(failed[24:], 10001)
		binary.BigEndian.PutUint32(failed[32:], uint32(i+1))
		binary.BigEndian.PutUint32(failed[end-4:], 10001)
		if status, n, err := parsePNFSMultiReply(failed); err != nil || status != 10001 || n != 0 {
			t.Fatalf("failed operation %d not observed: %d, %d, %v", i, status, n, err)
		}
	}
	for _, record := range [][]byte{call, reply} {
		wire := pnfsMultiUnitWire(record)
		got, forwarded, err := readPNFSMultiRecord(bytes.NewReader(wire))
		if err != nil || !bytes.Equal(got, record) || !bytes.Equal(forwarded, wire) {
			t.Fatalf("changed record fragments: %v", err)
		}
		if _, _, err := readPNFSMultiRecord(bytes.NewReader(wire[:len(wire)-1])); err == nil {
			t.Fatal("accepted truncated fragment")
		}
	}
	for _, bad := range [][]byte{binary.BigEndian.AppendUint32(nil, 0x80200001), make([]byte, 4*1024)} {
		if _, _, err := readPNFSMultiRecord(bytes.NewReader(bad)); err == nil {
			t.Fatal("accepted excessive record size or fragment count")
		}
	}
}

func TestPNFSMultiObserverTransparentRelay(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	call, reply := pnfsMultiUnitRecords()
	wireCall, wireReply := pnfsMultiUnitWire(call), pnfsMultiUnitWire(reply)
	// An unrelated compound must also cross the relay without observation.
	other := append([]byte(nil), call...)
	binary.BigEndian.PutUint32(other[120:], 9) // GETATTR instead of READ.
	wireOther := pnfsMultiUnitWire(other)
	done := make(chan error, 1)
	serverDone := make(chan struct{})
	t.Cleanup(func() { upstream.Close(); <-serverDone })
	go func() {
		defer close(serverDone)
		c, err := upstream.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		for _, want := range [][]byte{wireOther, wireCall} {
			_, got, err := readPNFSMultiRecord(c)
			if err != nil || !bytes.Equal(got, want) {
				done <- fmt.Errorf("upstream original record differs: %v", err)
				return
			}
			if _, err := io.Copy(c, bytes.NewReader(wireReply)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	o := &pnfsMultiObserver{}
	endpoint, _ := newPNFSMultiRelay(t, upstream.Addr().String(), 2, o)
	c, err := net.DialTimeout("tcp4", endpoint, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for _, send := range [][]byte{wireOther, wireCall} {
		if _, err := io.Copy(c, bytes.NewReader(send)); err != nil {
			t.Fatal(err)
		}
		_, got, err := readPNFSMultiRecord(c)
		if err != nil || !bytes.Equal(got, wireReply) {
			t.Fatalf("downstream original reply differs: %v", err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s := o.snapshot()
	if len(s.Errors) != 0 || s.Connections[2] != 1 || len(s.Reads) != 1 {
		t.Fatalf("relay observations: %+v", s)
	}
	r := s.Reads[0]
	if r.ServerID != 2 || r.ReturnedBytes != 5 || r.WireStatus != 0 || r.ForwardedAt.Before(r.RequestedAt) || r.RepliedAt.Before(r.ForwardedAt) {
		t.Fatalf("reply correlation: %+v", r)
	}
	if r.RequestedNS <= 0 || r.ForwardedNS < r.RequestedNS || r.RepliedNS < r.ForwardedNS ||
		r.RequestedNS != r.RequestedAt.Sub(pnfsMultiTimeOrigin).Nanoseconds() ||
		r.ForwardedNS != r.ForwardedAt.Sub(pnfsMultiTimeOrigin).Nanoseconds() ||
		r.RepliedNS != r.RepliedAt.Sub(pnfsMultiTimeOrigin).Nanoseconds() {
		t.Fatalf("relay capture lost its monotonic elapsed time: %+v", r)
	}
	o.reset()
	if s := o.snapshot(); len(s.Connections) != 0 || len(s.Reads) != 0 || len(s.Errors) != 0 || s.BarrierMatched || s.BarrierTimedOut {
		t.Fatalf("observer did not reset: %+v", s)
	}
}

func TestPNFSMultiObserverMonotonicJSON(t *testing.T) {
	var r pnfsMultiReadEvent
	r.RequestedAt, r.RequestedNS = pnfsMultiTimestamp()
	r.ForwardedAt, r.ForwardedNS = pnfsMultiTimestamp()
	r.RepliedAt, r.RepliedNS = pnfsMultiTimestamp()
	if r.RequestedNS <= 0 || r.ForwardedNS < r.RequestedNS || r.RepliedNS < r.ForwardedNS {
		t.Fatalf("captures are not positive and causal: %+v", r)
	}
	// Model the observed host wall-clock correction without changing the
	// actual elapsed captures. This diagnostic must not invalidate causal NS.
	r.RepliedAt = r.RequestedAt.Add(-2 * time.Millisecond).UTC()
	encoded, err := json.Marshal(pnfsMultiSnapshot{Reads: []pnfsMultiReadEvent{r}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded pnfsMultiSnapshot
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Reads) != 1 {
		t.Fatal("lost serialized READ event")
	}
	got := decoded.Reads[0]
	if got.RequestedNS != r.RequestedNS || got.ForwardedNS != r.ForwardedNS || got.RepliedNS != r.RepliedNS ||
		got.RequestedNS <= 0 || got.ForwardedNS < got.RequestedNS || got.RepliedNS < got.ForwardedNS ||
		!got.RequestedAt.Equal(r.RequestedAt) || !got.ForwardedAt.Equal(r.ForwardedAt) || !got.RepliedAt.Equal(r.RepliedAt) ||
		!got.RepliedAt.Before(got.RequestedAt) {
		t.Fatalf("JSON changed elapsed evidence or wall-clock diagnostics: %+v", got)
	}
}

func TestPNFSMultiObserverBoundary(t *testing.T) {
	const boundary = 64 << 20
	for _, sameServer := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_server_%t", sameServer), func(t *testing.T) {
			o := &pnfsMultiObserver{}
			o.armBoundary(boundary)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			done := make(chan struct{}, 2)
			go func() {
				o.observe(ctx, 1, pnfsMultiReadEvent{Offset: boundary - 1024, Count: 1024})
				done <- struct{}{}
			}()
			// The first boundary request must stay held until a distinct DS
			// request arrives; sequential use therefore cannot pass the gate.
			select {
			case <-done:
				t.Fatal("boundary request escaped before a second server")
			case <-time.After(20 * time.Millisecond):
			}
			server := 2
			if sameServer {
				server = 1
			}
			go func() {
				o.observe(ctx, server, pnfsMultiReadEvent{Offset: boundary, Count: 1024})
				done <- struct{}{}
			}()
			for range 2 {
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("boundary wait failed to terminate")
				}
			}
			s := o.snapshot()
			if s.BarrierMatched == sameServer || s.BarrierTimedOut != sameServer || len(s.Reads) != 2 {
				t.Fatalf("boundary gate observations: %+v", s)
			}
		})
	}
	t.Run("sequential", func(t *testing.T) {
		o := &pnfsMultiObserver{}
		o.armBoundary(boundary)
		// A second server arriving only after the first has been forwarded
		// must not retroactively satisfy the overlap assertion.
		o.observe(context.Background(), 1, pnfsMultiReadEvent{Offset: boundary - 1024, Count: 1024})
		o.observe(context.Background(), 2, pnfsMultiReadEvent{Offset: boundary, Count: 1024})
		if s := o.snapshot(); s.BarrierMatched || !s.BarrierTimedOut || len(s.Reads) != 2 {
			t.Fatalf("sequential requests satisfied overlap: %+v", s)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		o := &pnfsMultiObserver{}
		o.armBoundary(boundary)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			o.observe(ctx, 1, pnfsMultiReadEvent{Offset: boundary - 1024, Count: 1024})
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("cancelled boundary request remained blocked")
			<-done
		}
		if s := o.snapshot(); s.BarrierMatched || s.BarrierTimedOut {
			t.Fatalf("cancel was recorded as overlap or timeout: %+v", s)
		}
	})
}

func TestPNFSMultiObserverWriteProtocol(t *testing.T) {
	call, reply := pnfsMultiUnitRecords()
	// The final READ opcode/state/range becomes a literal WRITE with five bytes.
	at := len(call) - 32
	binary.BigEndian.PutUint32(call[at:], 38)
	call = call[:len(call)-4]
	call = binary.BigEndian.AppendUint32(call, 0)
	call = binary.BigEndian.AppendUint32(call, 5)
	call = append(call, []byte("hello\x00\x00\x00")...)
	r, ok := parsePNFSMultiCall(call)
	if !ok || r.Opcode != 38 || r.Count != 5 || r.PayloadSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("hello"))) {
		t.Fatal("WRITE not decoded", r, ok)
	}
	reply = reply[:len(reply)-24]
	reply = binary.BigEndian.AppendUint32(reply, 38)
	reply = binary.BigEndian.AppendUint32(reply, 0)
	reply = binary.BigEndian.AppendUint32(reply, 5)
	reply = binary.BigEndian.AppendUint32(reply, 0)
	reply = append(reply, make([]byte, 8)...)
	status, n, err := parsePNFSMultiReply(reply, 38)
	if err != nil || status != 0 || n != 5 {
		t.Fatal(status, n, err)
	}
	for _, cut := range []int{1, 4, 7} {
		if _, ok := parsePNFSMultiCall(call[:len(call)-cut]); ok {
			t.Fatal("truncated WRITE accepted")
		}
		if _, _, err := parsePNFSMultiReply(reply[:len(reply)-cut], 38); err == nil {
			t.Fatal("truncated reply accepted")
		}
	}
	if _, _, err := parsePNFSMultiReply(reply, 25); err == nil {
		t.Fatal("WRITE accepted as READ")
	}
}
