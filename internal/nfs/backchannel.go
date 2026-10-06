package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// rpcDuplex is opt-in for pNFS TCP connections. One reader dispatches server
// calls even while no foreground RPC is outstanding. Foreground calls remain
// serialized by rpcClient.mu; callback replies use a separate write mutex.
type rpcDuplex struct {
	conn     net.Conn
	timeout  time.Duration
	writeMu  sync.Mutex
	replies  chan []byte
	done     chan struct{}
	err      error // published by closing done
	callback func([]byte) ([]byte, error)
}

func startDuplex(c *rpcClient, callback func([]byte) ([]byte, error)) *rpcDuplex {
	m := &rpcDuplex{conn: c.conn, timeout: c.timeout, replies: make(chan []byte, 1), done: make(chan struct{}), callback: callback}
	go m.readLoop()
	return m
}
func (m *rpcDuplex) readLoop() {
	defer close(m.done)
	defer m.conn.Close()
	for {
		b, err := readRecord(m.conn)
		if err != nil {
			m.err = err
			return
		}
		if len(b) < 8 {
			m.err = errors.New("truncated duplex RPC header")
			return
		}
		switch binary.BigEndian.Uint32(b[4:8]) {
		case 0:
			if len(b) > pnfsCallbackSize {
				m.err = errors.New("oversized backchannel call")
				return
			}
			reply, err := m.callback(b)
			if err == nil {
				err = m.write(reply, time.Now().Add(m.timeout))
			}
			if err != nil {
				m.err = err
				return
			}
		case 1:
			select {
			case m.replies <- b:
			default:
				m.err = errors.New("unexpected duplex reply")
				return
			}
		default:
			m.err = errors.New("invalid duplex RPC direction")
			return
		}
	}
}
func (m *rpcDuplex) write(b []byte, deadline time.Time) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if err := m.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(b))|0x80000000)
	packet = append(packet, b...)
	for len(packet) > 0 {
		n, err := m.conn.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		packet = packet[n:]
	}
	return nil
}
func (m *rpcDuplex) exchange(ctx context.Context, b []byte, deadline time.Time) ([]byte, error) {
	if err := m.write(b, deadline); err != nil {
		return nil, err
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case b := <-m.replies:
		return b, nil
	case <-m.done:
		return nil, m.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, context.DeadlineExceeded
	}
}

const (
	pnfsCallbackProgram = 0x40000001
	pnfsCallbackSize    = 65536
	pnfsCallbackOps     = 8
)

type layoutRecall struct {
	gss                 *gssBackchannel
	mu                  sync.Mutex
	session             []byte
	minor               uint32
	sequence            uint32
	request, reply      []byte
	uncached            bool
	active              bool
	recalled            bool
	fh, state           []byte
	layoutType          uint32
	flexErrors          []flexIOError
	objectError         []byte
	deviceNotifications bool
	devices             map[string]deviceNotice
	deletedDevices      map[string]bool // Client-ID lifetime tombstones; never reused.
	writeDevices        bool
	// Latest completed fore-channel sequence, used for referring calls.
	completed                               uint32
	requestLimit, responseLimit, cacheLimit uint32
	offloadEnabled                          bool
	offload                                 *offloadPending
}

func (r *layoutRecall) callback(b []byte) ([]byte, error) {
	return r.callbackFramed(b, 0, len(b))
}

func (r *layoutRecall) callbackFramed(b []byte, overhead, requestBytes int) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	requestLimit, responseLimit, cacheLimit := r.requestLimit, r.responseLimit, r.cacheLimit
	if requestLimit == 0 {
		requestLimit = pnfsCallbackSize
	}
	if responseLimit == 0 {
		responseLimit = pnfsCallbackSize
	}
	if cacheLimit == 0 && r.requestLimit == 0 {
		cacheLimit = pnfsCallbackSize
	}
	if len(b) > pnfsCallbackSize {
		return nil, errors.New("oversized backchannel call")
	}
	// Decode into local state: malformed or oversized replies must not
	// acknowledge a recall or advance its slot before validation completes.
	recalled, state := r.recalled, r.state
	var offloadResult *offloadReply
	var deviceChanges map[string]deviceNotice
	d := &decoder{b: b}
	xid := d.u32()
	if d.u32() != 0 || d.u32() != 2 || d.u32() != pnfsCallbackProgram || d.u32() != 1 {
		return nil, errors.New("invalid pNFS callback RPC header")
	}
	proc := d.u32()
	flavor := d.u32()
	cred := d.opaque(400)
	vf := d.u32()
	verifier := d.opaque(400)
	if vf != 0 || len(verifier) != 0 || (flavor != 0 && flavor != 1) {
		return nil, errors.New("unsupported callback authentication")
	}
	if flavor == 0 && len(cred) != 0 {
		return nil, errors.New("invalid callback AUTH_NONE")
	}
	if flavor == 1 {
		a := &decoder{b: cred}
		a.u32()
		a.opaque(255)
		a.u32()
		a.u32()
		n := a.u32()
		if n > 16 {
			return nil, errors.New("callback group limit")
		}
		for i := uint32(0); i < n; i++ {
			a.u32()
		}
		if a.err != nil || len(a.b) != 0 {
			return nil, errors.New("invalid callback AUTH_SYS")
		}
	}
	var rpc encoder
	rpc.u32(xid)
	rpc.u32(1)
	rpc.u32(0)
	rpc.u32(0)
	rpc.u32(0)
	rpc.u32(0)
	if proc == 0 {
		if d.err != nil || len(d.b) != 0 {
			return nil, errors.New("invalid CB_NULL")
		}
		return rpc, nil
	}
	if proc != 1 {
		return nil, errors.New("unsupported callback procedure")
	}
	body := append([]byte(nil), d.b...)
	tag := d.str()
	compoundReply := func(status, count uint32, ops []byte) encoder {
		var response encoder
		response.u32(status)
		response.str(tag)
		response.u32(count)
		return append(response, ops...)
	}
	minor := d.u32()
	d.u32()
	n := d.u32()
	if minor != 1 && minor != 2 || r.minor != 0 && minor != r.minor || n < 1 || n > pnfsCallbackOps || d.u32() != 11 {
		return nil, errors.New("invalid callback compound")
	}
	sid := d.take(16)
	seq := d.u32()
	slot := d.u32()
	highest := d.u32()
	cacheThis := d.boolean()
	refs := d.u32()
	if refs > 8 {
		return nil, errors.New("callback reference limit")
	}
	pending := false
	for i := uint32(0); i < refs; i++ {
		rs := d.take(16)
		nr := d.u32()
		if nr > 32 {
			return nil, errors.New("callback referring-call limit")
		}
		for j := uint32(0); j < nr; j++ {
			s := d.u32()
			sl := d.u32()
			if !bytes.Equal(rs, r.session) || sl != 0 || int32(s-r.completed) > 0 {
				pending = true
			}
		}
	}
	status := uint32(0)
	switch {
	case requestBytes > int(requestLimit):
		status = 10065 // NFS4ERR_REQ_TOO_BIG.
	case !bytes.Equal(sid, r.session) || len(r.session) != 16:
		status = 10052
	case slot != 0 || highest != 0:
		status = 10053
	case pending:
		status = 10008
	case seq == r.sequence && r.reply != nil:
		if !bytes.Equal(body, r.request) {
			return nil, errors.New("changed callback retransmission")
		}
		if r.uncached {
			status, count := uint32(0), uint32(1)
			if n > 1 {
				status, count = binary.BigEndian.Uint32(r.reply[44:48]), 2
			}
			return append(rpc, compoundReply(status, count, r.reply)...), nil
		}
		return append(rpc, r.reply...), nil
	case seq != r.sequence+1:
		status = 10063
	}
	sequenceAccepted := status == 0
	var ops encoder
	ops.u32(11)
	ops.u32(status)
	count := uint32(1)
	if status == 0 {
		ops = append(ops, sid...)
		ops.u32(seq)
		ops.u32(0)
		ops.u32(0)
		ops.u32(0)
		for i := uint32(1); i < n && status == 0; i++ {
			code := d.u32()
			count++
			ops.u32(code)
			if code == 14 && r.deviceNotifications {
				if deviceChanges == nil {
					deviceChanges = cloneDeviceNotices(r.devices)
				}
				decodeDeviceNotices(d, deviceChanges, r.layoutKind())
				ops.u32(0)
				continue
			}
			if code == 15 && minor == 2 && r.offloadEnabled {
				fh, id := d.opaque(128), d.take(16)
				result := &offloadReply{status: Status(d.u32())}
				if result.status == 0 {
					*result = decodeOffloadReply(d)
					if len(result.id) != 0 {
						d.err = errors.New("CB_OFFLOAD must not contain another callback ID")
					}
				} else {
					result.count = d.u64()
				}
				switch {
				case r.offload == nil || !bytes.Equal(fh, r.offload.fh):
					status = 10025
				case len(r.offload.id) == 0:
					status = 10008 // Retry after the foreground reply binds the operation ID.
				case !bytes.Equal(id, r.offload.id):
					status = 10025
				case result.count > r.offload.length:
					d.err = errors.New("offload callback exceeds requested length")
				default:
					if r.offload.result != nil && !sameOffloadReply(*r.offload.result, *result) {
						d.err = errors.New("conflicting offload completion")
					}
					if offloadResult != nil && !sameOffloadReply(*offloadResult, *result) {
						d.err = errors.New("conflicting compound offload completion")
					}
					offloadResult = result
				}
				ops.u32(status)
				continue
			}
			if code != 5 {
				status = 10004
				ops.u32(status)
				break
			}
			layoutType := d.u32()
			mode := d.u32()
			d.boolean()
			kind := d.u32()
			matching := r.active && layoutType == r.layoutKind() && mode >= 1 && mode <= 3
			var newState []byte
			switch kind {
			case 1:
				fh := d.opaque(128)
				d.u64()
				length := d.u64()
				newState = append([]byte(nil), d.take(16)...)
				matching = matching && length != 0 && bytes.Equal(fh, r.fh) && len(state) == 16 && len(newState) == 16 && bytes.Equal(newState[4:], state[4:])
			case 2:
				d.take(16) // Conservatively return our sole active layout for any FSID.
			case 3:
			default:
				d.err = errors.New("invalid layout recall type")
			}
			if matching {
				recalled = true
				if newState != nil {
					state = newState
				}
			} else {
				status = 10060
			}
			ops.u32(status)
		}
	}
	if d.err != nil || status == 0 && len(d.b) != 0 {
		return nil, errors.New("malformed pNFS callback")
	}
	response := compoundReply(status, count, ops)
	sizeError := uint32(0)
	if len(rpc)+len(response)+overhead > int(responseLimit) {
		sizeError = 10066 // NFS4ERR_REP_TOO_BIG.
	} else if sequenceAccepted && cacheThis && len(rpc)+len(response)+overhead > int(cacheLimit) {
		sizeError = 10067 // NFS4ERR_REP_TOO_BIG_TO_CACHE.
	}
	if sizeError != 0 {
		// CB_SEQUENCE errors neither consume a sequence nor enter the cache.
		// RFC 8881 2.10.6.4 permits REP_TOO_BIG even if the echoed tag makes
		// this error response larger than the negotiated response limit.
		var failure encoder
		failure.u32(11)
		failure.u32(sizeError)
		return append(rpc, compoundReply(sizeError, 1, failure)...), nil
	}
	if sequenceAccepted {
		if offloadResult != nil && r.offload.journal != nil {
			if err := r.offload.journal.recordCallback(offloadResult); err != nil {
				return nil, err
			}
		}
		if deviceChanges != nil {
			r.devices = deviceChanges
			if r.deletedDevices == nil {
				r.deletedDevices = map[string]bool{}
			}
			for id, notice := range deviceChanges {
				if notice.deleted {
					r.deletedDevices[id] = true
				}
			}
		}
		if offloadResult != nil {
			r.offload.result = offloadResult
		}
		r.recalled, r.state = recalled, state
		r.sequence = seq
		r.request = body
		r.uncached = len(rpc)+len(response)+overhead > int(cacheLimit)
		if r.uncached {
			// Keep only the successful CB_SEQUENCE result and a second-op
			// error (RFC 8881 2.10.6.1.3). Rebuild the tag from the
			// identical, request-bounded retransmission rather than caching it.
			r.reply = append([]byte(nil), ops[:40]...)
			if count > 1 {
				r.reply = append(r.reply, ops[40:48]...)
				// Preserve errors such as NOTSUPP; only a successful second
				// operation becomes NFS4ERR_RETRY_UNCACHED_REP on replay.
				if binary.BigEndian.Uint32(r.reply[44:48]) == 0 {
					binary.BigEndian.PutUint32(r.reply[44:48], 10068)
				}
			}
		} else {
			r.reply = append([]byte(nil), response...)
		}
	}
	return append(rpc, response...), nil
}
