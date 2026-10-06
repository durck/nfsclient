package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// The natural-recall observer only copies original RPC records. RawCall and
// RawReply retain the original TCP record markers for independent inspection.
type pnfsNaturalEvent struct {
	Role, Kind                             string
	Connection                             int
	XID, Minor, Status                     uint32
	Sequence, Slot, HighestSlot, CacheThis uint32
	Session, FH, State                     []byte
	LayoutType, RecallKind, IOMode         uint32
	Offset, Length                         uint64
	ReceivedNS, ForwardedNS, ReplyNS       int64
	RawCall, RawReply                      []byte
}

type pnfsNaturalSnapshot struct {
	Events []pnfsNaturalEvent
	Errors []string
}

type pnfsNaturalObserver struct {
	mu      sync.Mutex
	events  []*pnfsNaturalEvent
	errors  []string
	changed chan struct{}
}

func (o *pnfsNaturalObserver) wakeLocked() {
	if o.changed != nil {
		close(o.changed)
	}
	o.changed = make(chan struct{})
}

func (o *pnfsNaturalObserver) snapshot() (pnfsNaturalSnapshot, <-chan struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.changed == nil {
		o.changed = make(chan struct{})
	}
	s := pnfsNaturalSnapshot{Errors: append([]string(nil), o.errors...)}
	for _, e := range o.events {
		s.Events = append(s.Events, *e)
	}
	return s, o.changed
}

func (o *pnfsNaturalObserver) problem(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.errors = append(o.errors, err.Error())
	o.wakeLocked()
}

func naturalU64(d *pnfsMultiDecoder) uint64 { return uint64(d.u32())<<32 | uint64(d.u32()) }

func naturalRPC(record []byte, call bool) (*pnfsMultiDecoder, uint32, uint32, error) {
	d := &pnfsMultiDecoder{b: record}
	xid := d.u32()
	if call {
		if d.u32() != 0 || d.u32() != 2 {
			return nil, 0, 0, errors.New("invalid RPC call")
		}
		program := d.u32()
		version, proc := d.u32(), d.u32()
		if !((program == 100003 && version == 4) || (program == 0x40000001 && version == 1)) || proc > 1 {
			return nil, 0, 0, errors.New("unexpected RPC program/version/procedure")
		}
		d.u32()
		d.opaque(400)
		d.u32()
		d.opaque(400)
		if d.bad {
			return nil, 0, 0, errors.New("truncated RPC authentication")
		}
		if proc == 0 {
			return nil, xid, program, nil
		}
		return d, xid, program, nil
	}
	if d.u32() != 1 || d.u32() != 0 {
		return nil, 0, 0, errors.New("unaccepted RPC reply")
	}
	d.u32()
	d.opaque(400)
	if d.u32() != 0 || d.bad {
		return nil, 0, 0, errors.New("unsuccessful RPC reply")
	}
	return d, xid, 0, nil
}

func parsePNFSNaturalCall(record []byte) (*pnfsNaturalEvent, error) {
	d, xid, program, err := naturalRPC(record, true)
	if err != nil || d == nil {
		return nil, err
	}
	e := &pnfsNaturalEvent{XID: xid}
	d.opaque(1024)
	e.Minor = d.u32()
	if e.Minor != 1 && e.Minor != 2 {
		return nil, errors.New("unexpected compound minor version")
	}
	if program == 0x40000001 {
		d.u32() // callback_ident
		if d.u32() != 2 || d.u32() != 11 {
			return nil, errors.New("expected CB_SEQUENCE and CB_LAYOUTRECALL")
		}
		e.Session = append([]byte(nil), d.take(16)...)
		e.Sequence, e.Slot, e.HighestSlot, e.CacheThis = d.u32(), d.u32(), d.u32(), d.u32()
		if e.CacheThis > 1 {
			return nil, errors.New("invalid callback cache boolean")
		}
		refs := d.u32()
		if refs > 8 {
			return nil, errors.New("excessive callback reference lists")
		}
		for range refs {
			d.take(16)
			n := d.u32()
			if n > 32 {
				return nil, errors.New("excessive callback references")
			}
			d.take(uint64(n) * 8)
		}
		if d.u32() != 5 {
			return nil, errors.New("expected CB_LAYOUTRECALL")
		}
		e.Kind = "recall"
		e.LayoutType = d.u32()
		e.IOMode = d.u32()
		if d.u32() > 1 {
			return nil, errors.New("invalid recall changed boolean")
		}
		e.RecallKind = d.u32()
		if e.RecallKind != 1 {
			return nil, errors.New("expected FILE recall")
		}
		e.FH = append([]byte(nil), d.opaque(128)...)
		e.Offset = naturalU64(d)
		e.Length = naturalU64(d)
		e.State = append([]byte(nil), d.take(16)...)
	} else {
		if d.u32() != 3 || d.u32() != 53 {
			return nil, nil
		}
		e.Session = append([]byte(nil), d.take(16)...)
		e.Sequence, e.Slot, e.HighestSlot, e.CacheThis = d.u32(), d.u32(), d.u32(), d.u32()
		if e.CacheThis > 1 {
			return nil, errors.New("invalid forechannel cache boolean")
		}
		if d.u32() != 22 {
			return nil, nil
		}
		e.FH = append([]byte(nil), d.opaque(128)...)
		switch d.u32() {
		case 50:
			e.Kind = "layoutget"
			if d.u32() > 1 {
				return nil, errors.New("invalid layoutget boolean")
			}
			e.LayoutType = d.u32()
			e.IOMode = d.u32()
			e.Offset = naturalU64(d)
			e.Length = naturalU64(d)
			d.take(8 + 16 + 4)
		case 51:
			e.Kind = "layoutreturn"
			if d.u32() > 1 {
				return nil, errors.New("invalid layoutreturn boolean")
			}
			e.LayoutType = d.u32()
			e.IOMode = d.u32()
			e.RecallKind = d.u32()
			if e.RecallKind != 1 {
				return nil, errors.New("expected FILE return")
			}
			e.Offset = naturalU64(d)
			e.Length = naturalU64(d)
			e.State = append([]byte(nil), d.take(16)...)
			d.opaque(32768)
		case 25:
			e.Kind = "read"
			d.take(16)
			e.Offset = naturalU64(d)
			e.Length = uint64(d.u32())
		default:
			return nil, nil
		}
	}
	if d.bad || len(d.b) != 0 {
		return nil, errors.New("malformed observed NFS compound")
	}
	return e, nil
}

func parsePNFSNaturalReply(record []byte, e *pnfsNaturalEvent) (uint32, []byte, error) {
	d, xid, _, err := naturalRPC(record, false)
	if err != nil {
		return 0, nil, err
	}
	if xid != e.XID {
		return 0, nil, errors.New("reply XID differs")
	}
	status := d.u32()
	d.opaque(1024)
	count := d.u32()
	ops := []uint32{53, 22, 50}
	switch e.Kind {
	case "recall":
		ops = []uint32{11, 5}
	case "layoutreturn":
		ops[2] = 51
	case "read":
		ops[2] = 25
	}
	if count == 0 || count > uint32(len(ops)) {
		return 0, nil, errors.New("invalid observed reply count")
	}
	var state []byte
	for i := uint32(0); i < count; i++ {
		if d.u32() != ops[i] {
			return 0, nil, errors.New("unexpected reply operation")
		}
		s := d.u32()
		if s != 0 {
			if s == status && i+1 == count && !d.bad && len(d.b) == 0 {
				return status, nil, nil
			}
			return 0, nil, errors.New("invalid failed reply")
		}
		switch ops[i] {
		case 53, 11:
			if !bytes.Equal(d.take(16), e.Session) || d.u32() != e.Sequence || d.u32() != e.Slot {
				return 0, nil, errors.New("reply sequence/session differs")
			}
			d.take(8)
			if ops[i] == 53 {
				d.take(4)
			}
		case 50:
			if d.u32() > 1 {
				return 0, nil, errors.New("invalid layoutget reply boolean")
			}
			state = append([]byte(nil), d.take(16)...)
			if d.u32() != 1 {
				return 0, nil, errors.New("expected one layout segment")
			}
			off, length, mode, kind := naturalU64(d), naturalU64(d), d.u32(), d.u32()
			if off != 0 || length == 0 || (mode != 1 && mode != 2) || kind != 1 {
				return 0, nil, errors.New("non-FILE or incomplete layout")
			}
			d.opaque(32768)
		case 51:
			present := d.u32()
			if present > 1 {
				return 0, nil, errors.New("invalid layoutreturn reply boolean")
			}
			if present == 1 {
				d.take(16)
			}
		case 25:
			if d.u32() > 1 {
				return 0, nil, errors.New("invalid READ reply boolean")
			}
			d.opaque(2 << 20)
		}
	}
	if status != 0 || count != uint32(len(ops)) || d.bad || len(d.b) != 0 {
		return 0, nil, errors.New("malformed observed NFS reply")
	}
	return status, state, nil
}

func newPNFSNaturalRelay(t *testing.T, target, role string, o *pnfsNaturalObserver) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	var wg sync.WaitGroup
	wg.Add(1)
	t.Cleanup(func() {
		cancel()
		l.Close()
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	go func() {
		defer wg.Done()
		for connection := 1; ; connection++ {
			down, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[down] = true
			mu.Unlock()
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				defer down.Close()
				defer func() { mu.Lock(); delete(active, down); mu.Unlock() }()
				up, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
				if err != nil {
					if ctx.Err() == nil {
						o.problem(err)
					}
					return
				}
				defer up.Close()
				mu.Lock()
				active[up] = true
				mu.Unlock()
				defer func() { mu.Lock(); delete(active, up); mu.Unlock() }()
				var pendingMu sync.Mutex
				fore, back := map[uint32]*pnfsNaturalEvent{}, map[uint32]*pnfsNaturalEvent{}
				copyRecords := func(dst, src net.Conn, server bool) {
					defer down.Close()
					defer up.Close()
					for {
						record, wire, err := readPNFSMultiRecord(src)
						if err != nil {
							if ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
								o.problem(err)
							}
							return
						}
						if len(record) < 8 {
							o.problem(errors.New("short observed RPC"))
							return
						}
						call := binary.BigEndian.Uint32(record[4:]) == 0
						var event *pnfsNaturalEvent
						var status uint32
						var state []byte
						pending := fore
						if (server && call) || (!server && !call) {
							pending = back
						}
						if call {
							event, err = parsePNFSNaturalCall(record)
							if event != nil {
								event.Role, event.Connection = role, id
								_, event.ReceivedNS = pnfsMultiTimestamp()
								if len(wire) > 65536 {
									err = errors.New("observed call raw evidence exceeds 64 KiB")
								} else {
									event.RawCall = append([]byte(nil), wire...)
								}
								pendingMu.Lock()
								if pending[event.XID] != nil {
									err = errors.New("duplicate pending observed XID")
								}
								pending[event.XID] = event
								pendingMu.Unlock()
								o.mu.Lock()
								o.events = append(o.events, event)
								o.wakeLocked()
								o.mu.Unlock()
							}
						} else {
							pendingMu.Lock()
							event = pending[binary.BigEndian.Uint32(record)]
							delete(pending, binary.BigEndian.Uint32(record))
							pendingMu.Unlock()
							if event != nil {
								status, state, err = parsePNFSNaturalReply(record, event)
							}
						}
						if err != nil {
							o.problem(fmt.Errorf("%s: %w", role, err))
						}
						if event != nil && call {
							o.mu.Lock()
							_, event.ForwardedNS = pnfsMultiTimestamp()
							o.mu.Unlock()
						}
						if _, err = io.Copy(dst, bytes.NewReader(wire)); err != nil {
							return
						}
						if event != nil {
							o.mu.Lock()
							if !call {
								_, event.ReplyNS = pnfsMultiTimestamp()
								event.Status = status
								if state != nil {
									event.State = state
								}
								if len(wire) <= 65536 {
									event.RawReply = append([]byte(nil), wire...)
								} else {
									o.errors = append(o.errors, "observed reply raw evidence exceeds 64 KiB")
								}
							}
							o.wakeLocked()
							o.mu.Unlock()
						}
					}
				}
				done := make(chan struct{})
				go func() { defer close(done); copyRecords(down, up, true) }()
				copyRecords(up, down, false)
				<-done
			}(connection)
		}
	}()
	return l.Addr().String()
}

func naturalUnitCallback() (call, reply []byte) {
	words := func(dst []byte, values ...uint32) []byte {
		for _, v := range values {
			dst = binary.BigEndian.AppendUint32(dst, v)
		}
		return dst
	}
	call = words(call, 91, 0, 2, 0x40000001, 1, 1, 0, 0, 0, 0, 0, 1, 0, 2, 11)
	call = append(call, bytes.Repeat([]byte{1}, 16)...)
	call = words(call, 1, 0, 0, 1, 0, 5, 1, 3, 0, 1, 3)
	call = append(call, 'f', 'h', 'a', 0)
	call = binary.BigEndian.AppendUint64(call, 0)
	call = binary.BigEndian.AppendUint64(call, ^uint64(0))
	call = append(call, bytes.Repeat([]byte{2}, 16)...)
	reply = words(reply, 91, 1, 0, 0, 0, 0, 0, 0, 2, 11, 0)
	reply = append(reply, bytes.Repeat([]byte{1}, 16)...)
	reply = words(reply, 1, 0, 0, 0, 5, 0)
	return
}

func TestPNFSNaturalObserverProtocol(t *testing.T) {
	call, reply := naturalUnitCallback()
	e, err := parsePNFSNaturalCall(call)
	if err != nil || e == nil || e.Kind != "recall" || e.LayoutType != 1 || e.RecallKind != 1 || string(e.FH) != "fha" || e.Length != ^uint64(0) {
		t.Fatalf("callback decode: %+v %v", e, err)
	}
	if status, _, err := parsePNFSNaturalReply(reply, e); err != nil || status != 0 {
		t.Fatal(status, err)
	}
	for end := range len(call) {
		if got, err := parsePNFSNaturalCall(call[:end]); err == nil && got != nil {
			t.Fatalf("accepted truncated callback %d", end)
		}
	}
	for end := range len(reply) {
		if _, _, err := parsePNFSNaturalReply(reply[:end], e); err == nil {
			t.Fatalf("accepted truncated callback reply %d", end)
		}
	}
	if _, err := parsePNFSNaturalCall(append(append([]byte(nil), call...), 0)); err == nil {
		t.Fatal("accepted trailing callback bytes")
	}
	if _, _, err := parsePNFSNaturalReply(append(append([]byte(nil), reply...), 0), e); err == nil {
		t.Fatal("accepted trailing callback reply bytes")
	}
	for _, offset := range []int{8, 12, 16, 20, 44, 52, 56, 108} {
		bad := append([]byte(nil), call...)
		binary.BigEndian.PutUint32(bad[offset:], 999)
		if _, err := parsePNFSNaturalCall(bad); err == nil {
			t.Fatalf("accepted invalid callback field at %d", offset)
		}
	}
	bad := append([]byte(nil), reply...)
	binary.BigEndian.PutUint32(bad, 92)
	if _, _, err := parsePNFSNaturalReply(bad, e); err == nil {
		t.Fatal("accepted mismatched reply XID")
	}
	bad = append([]byte(nil), reply...)
	bad[44] ^= 1
	if _, _, err := parsePNFSNaturalReply(bad, e); err == nil {
		t.Fatal("accepted mismatched callback session")
	}
}

func TestPNFSNaturalObserverLayouts(t *testing.T) {
	read, readReply := pnfsMultiUnitRecords()
	words := func(dst []byte, values ...uint32) []byte {
		for _, v := range values {
			dst = binary.BigEndian.AppendUint32(dst, v)
		}
		return dst
	}
	state := bytes.Repeat([]byte{7}, 16)
	for _, op := range []uint32{50, 51} {
		call := words(append([]byte(nil), read[:120]...), op, 0, 1)
		if op == 50 {
			call = words(call, 1)
		} else {
			call = words(call, 3, 1)
		}
		call = binary.BigEndian.AppendUint64(call, 0)
		call = binary.BigEndian.AppendUint64(call, ^uint64(0))
		if op == 50 {
			call = binary.BigEndian.AppendUint64(call, 1024)
		}
		call = append(call, state...)
		if op == 50 {
			call = words(call, 32768)
		} else {
			call = words(call, 0)
		}
		reply := words(append([]byte(nil), readReply[:88]...), op, 0)
		if op == 50 {
			reply = words(reply, 1)
			reply = append(reply, state...)
			reply = words(reply, 1)
			reply = binary.BigEndian.AppendUint64(reply, 0)
			reply = binary.BigEndian.AppendUint64(reply, ^uint64(0))
			reply = words(reply, 1, 1, 4, 42)
		} else {
			reply = words(reply, 0)
		}
		e, err := parsePNFSNaturalCall(call)
		if err != nil || e == nil || e.LayoutType != 1 || e.Length != ^uint64(0) {
			t.Fatalf("layout call %d: %+v %v", op, e, err)
		}
		status, gotState, err := parsePNFSNaturalReply(reply, e)
		if err != nil || status != 0 || op == 50 && !bytes.Equal(gotState, state) || op == 51 && !bytes.Equal(e.State, state) {
			t.Fatalf("layout reply %d: %d %x %v", op, status, gotState, err)
		}
		for end := range len(call) {
			if got, err := parsePNFSNaturalCall(call[:end]); err == nil && got != nil {
				t.Fatalf("accepted truncated layout call %d at %d", op, end)
			}
		}
		for end := range len(reply) {
			if _, _, err := parsePNFSNaturalReply(reply[:end], e); err == nil {
				t.Fatalf("accepted truncated layout reply %d at %d", op, end)
			}
		}
		failed := append([]byte(nil), reply[:96]...)
		binary.BigEndian.PutUint32(failed[24:], 10025)
		binary.BigEndian.PutUint32(failed[92:], 10025)
		if status, _, err := parsePNFSNaturalReply(failed, e); err != nil || status != 10025 {
			t.Fatal("failed layout operation lost", status, err)
		}
	}
}

func TestPNFSNaturalObserverTransparentDuplex(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	callback, ack := naturalUnitCallback()
	fore, foreReply := pnfsMultiUnitRecords()
	// Colliding XIDs must remain distinct across the two RPC directions.
	binary.BigEndian.PutUint32(fore, 91)
	binary.BigEndian.PutUint32(foreReply, 91)
	callbackWire, ackWire := pnfsMultiUnitWire(callback), pnfsMultiUnitWire(ack)
	foreWire, replyWire := pnfsMultiUnitWire(fore), pnfsMultiUnitWire(foreReply)
	serverDone := make(chan error, 1)
	go func() {
		c, err := upstream.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, got, err := readPNFSMultiRecord(c)
		if err != nil || !bytes.Equal(got, foreWire) {
			serverDone <- fmt.Errorf("changed foreground call: %v", err)
			return
		}
		if _, err = io.Copy(c, bytes.NewReader(callbackWire)); err != nil {
			serverDone <- err
			return
		}
		_, got, err = readPNFSMultiRecord(c)
		if err != nil || !bytes.Equal(got, ackWire) {
			serverDone <- fmt.Errorf("changed callback ACK: %v", err)
			return
		}
		_, err = io.Copy(c, bytes.NewReader(replyWire))
		serverDone <- err
	}()
	o := &pnfsNaturalObserver{}
	endpoint := newPNFSNaturalRelay(t, upstream.Addr().String(), "A", o)
	c, err := net.DialTimeout("tcp4", endpoint, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(c, bytes.NewReader(foreWire)); err != nil {
		t.Fatal(err)
	}
	_, got, err := readPNFSMultiRecord(c)
	if err != nil || !bytes.Equal(got, callbackWire) {
		t.Fatal("changed server callback", err)
	}
	if _, err := io.Copy(c, bytes.NewReader(ackWire)); err != nil {
		t.Fatal(err)
	}
	_, got, err = readPNFSMultiRecord(c)
	if err != nil || !bytes.Equal(got, replyWire) {
		t.Fatal("changed foreground reply", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		s, changed := o.snapshot()
		if len(s.Errors) > 0 {
			t.Fatal(s.Errors)
		}
		if len(s.Events) == 2 && s.Events[0].ReplyNS > 0 && s.Events[1].ReplyNS > 0 {
			for _, e := range s.Events {
				if e.Status != 0 || e.ReceivedNS <= 0 || e.ForwardedNS < e.ReceivedNS || e.ReplyNS < e.ForwardedNS {
					t.Fatalf("invalid causal observation: %+v", e)
				}
				wantCall, wantReply := foreWire, replyWire
				if e.Kind == "recall" {
					wantCall, wantReply = callbackWire, ackWire
				}
				if !bytes.Equal(e.RawCall, wantCall) || !bytes.Equal(e.RawReply, wantReply) {
					t.Fatal("raw evidence differs")
				}
			}
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("missing completed wire evidence")
		}
	}
}
