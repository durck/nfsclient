package nfs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// RFC 8881 18.36: limits include the RPC message, but not transport framing.
// Keep these separate from per-operation payload hints and persist all four.
type sessionChannelLimits struct {
	Request, Response, Cached, Operations uint32
}

type channelLimitError struct{ message string }

func (e *channelLimitError) Error() string { return e.message + "; request not sent" }
func channelRefusal(format string, args ...any) error {
	return &channelLimitError{fmt.Sprintf(format, args...)}
}
func channelNotSent(err error) bool { var e *channelLimitError; return errors.As(err, &e) }

type sessionWireBudget struct{ request, response uint32 }
type sessionWireBudgetKey struct{}

func readOnlyCompound4(ops []v4Op) bool {
	for _, op := range ops {
		switch op.code {
		case 3, 9, 10, 15, 16, 22, 23, 24, 25, 26, 27, 31, 32, 33, 47, 52, 68, 69, 72, 74:
		default:
			return false
		}
	}
	return true
}

func pad4(n uint64) uint64 { return (n + 3) &^ 3 }

// rpcSizes is side-effect-free: signing a dummy message would consume GSS
// mechanism sequence numbers. The final wire guard also covers renewal and
// child-context changes between this snapshot and the serialized RPC call.
func rpcSizes(auth Auth, g *rpcGSS) (request, response, protection uint64, err error) {
	if g == nil {
		var a encoder
		auth.encode(&a)
		return 24 + uint64(len(a)) + 8, 24, 0, nil
	}
	ctx := g.context
	if shared, ok := ctx.(*sharedGSSContext); ok {
		shared.mu.Lock()
		defer shared.mu.Unlock()
		ctx = shared.context
	}
	sizer, ok := ctx.(interface{ TokenSizes() (int, int, error) })
	if !ok {
		return 0, 0, 0, channelRefusal("GSS mechanism does not expose session token sizes")
	}
	mic, seal, err := sizer.TokenSizes()
	if err != nil {
		return 0, 0, 0, err
	}
	if mic < 0 || mic > 400 {
		return 0, 0, 0, channelRefusal("invalid GSS MIC size")
	}
	request = 24 + 8 + 20 + pad4(uint64(len(g.handle))) + 8 + pad4(uint64(mic))
	response = 24 + pad4(uint64(mic))
	switch g.service {
	case 2:
		protection = 12 + pad4(uint64(mic))
	case 3:
		if seal <= 0 {
			return 0, 0, 0, channelRefusal("GSS mechanism does not expose privacy token size")
		}
		protection = 4 + pad4(4+uint64(seal))
	}
	return
}

func (v *v4Client) channelSizes(auth Auth, rpc *rpcClient, child *rpcGSS) (uint64, uint64, uint64, error) {
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	g := rpc.gss
	if child != nil {
		g = child
	}
	return rpcSizes(auth, g)
}

func payloadAfter(limit uint32, overhead uint64) uint32 {
	if uint64(limit) <= overhead {
		return 0
	}
	return uint32((uint64(limit) - overhead) &^ 3)
}

func (v *v4Client) setChannel(limits sessionChannelLimits) error {
	req, resp, protection, err := v.channelSizes(v.c.Auth, v.c.nfs, nil)
	if err != nil {
		return err
	}
	// Initialization needs SEQUENCE+RECLAIM_COMPLETE and
	// SEQUENCE+PUTROOTFH+GETFH (a nonempty handle is at least four padded bytes).
	minimumRequest, minimumResponse, minimumCached, minimumOperations := req+protection+56, resp+protection+80, resp+protection+64, uint32(3)
	if v.exchangeRole == 0x40000 {
		// A DS-only session has no namespace or RECLAIM_COMPLETE setup.
		minimumRequest, minimumResponse, minimumCached, minimumOperations = req+protection+48, resp+protection+56, 0, 1
	}
	if uint64(limits.Request) < minimumRequest || uint64(limits.Response) < minimumResponse || uint64(limits.Cached) < minimumCached || limits.Operations < minimumOperations {
		return fmt.Errorf("NFSv4 session limits too small for initialization (request=%d response=%d cached=%d operations=%d)", limits.Request, limits.Response, limits.Cached, limits.Operations)
	}
	v.channel = limits
	// READ result: COMPOUND(12), SEQUENCE(44), PUTFH(8), READ(16).
	v.maxReplyPayload = payloadAfter(limits.Response, resp+protection+80)
	// WRITE request: COMPOUND(12), SEQUENCE(36), maximum PUTFH(136),
	// WRITE fixed fields(36). Shorter handles are budgeted per operation too.
	v.maxRequestPayload = payloadAfter(limits.Request, req+protection+220)
	if v.maxReplyPayload > 0 {
		v.c.ReadSize = min(v.c.ReadSize, v.maxReplyPayload)
	}
	if v.maxRequestPayload > 0 {
		v.c.WriteSize = min(v.c.WriteSize, v.maxRequestPayload)
	}
	return nil
}

// knownReplyBody budgets successful mutation results and bounded reads. A
// variable result without a protocol count remains server-enforced: RFC 8881
// 2.10.6.4 requires REP_TOO_BIG(_TO_CACHE), and cachethis stays true for every
// compound containing a mutation. Never turn caching off to make a mutation fit.
func knownReplyBody(op v4Op) uint64 {
	switch op.code {
	case 53:
		return 44
	case 3, 5:
		return 16
	case 4, 12, 14, 20, 21, 38:
		return 24
	case 6:
		return 44 // change_info4 + up to three bitmap words
	case 10:
		return 140 // nfs_fh4<128>
	case 11, 28, 73, 75:
		return 28
	case 29:
		return 48
	case 34:
		if len(op.args) >= 20 {
			n := binary.BigEndian.Uint32(op.args[16:])
			if n <= 3 {
				return 12 + uint64(n)*4
			}
		}
		return 24 // bitmap4 supported by this client
	case 18:
		return 76 // OPEN fixed fields and supported bitmap; delegation is server-bounded
	case 49:
		return 20 // newsize4 optional uint64
	case 51:
		return 28 // optional stateid
	case 60:
		return 56 // one optional callback stateid and write_response4
	case 63:
		return 44 // client-supported advice bitmap
	case 67:
		return 24 // count plus optional completion status
	case 69:
		return 20
	case 70:
		return 48 // one callback stateid and write_response4
	case 25:
		if len(op.args) >= 28 {
			return 16 + pad4(uint64(binary.BigEndian.Uint32(op.args[24:])))
		}
	case 26:
		if len(op.args) >= 24 {
			return 4 + uint64(binary.BigEndian.Uint32(op.args[20:]))
		}
	case 74:
		if len(op.args) >= 12 {
			return 8 + uint64(binary.BigEndian.Uint32(op.args[8:]))
		}
	}
	return 8
}

func (v *v4Client) checkChannel(auth Auth, rpc *rpcClient, child *rpcGSS, ops []v4Op, cache bool) error {
	if v.channel.Request == 0 || len(v.session) == 0 {
		return nil
	}
	if uint64(len(ops)+1) > uint64(v.channel.Operations) {
		return channelRefusal("NFSv4 compound needs %d operations, channel permits %d", len(ops)+1, v.channel.Operations)
	}
	req, resp, protection, err := v.channelSizes(auth, rpc, child)
	if err != nil {
		return err
	}
	request, reply := req+protection+48, resp+protection+56
	for _, op := range ops {
		request += 4 + uint64(len(op.args))
		// GETFH in a read-only compound may fit with a shorter handle;
		// mutation compounds must reserve the full protocol maximum.
		if op.code == 10 && !cache {
			reply += 16
		} else {
			reply += knownReplyBody(op)
		}
	}
	if request > uint64(v.channel.Request) {
		return channelRefusal("NFSv4 request needs %d bytes, channel permits %d", request, v.channel.Request)
	}
	limit := v.channel.Response
	if cache {
		limit = min(limit, v.channel.Cached)
	}
	if reply > uint64(limit) {
		return channelRefusal("NFSv4 reply needs %d bytes, channel permits %d (cached=%t)", reply, limit, cache)
	}
	return nil
}

// Clamp counted data operations using the actual compound and handle sizes.
// The callers already handle short READ/WRITE results; never split a stateful
// compound (SAVEFH/OPEN/RENAME) or change the requested mutation semantics.
func (v *v4Client) fitChannel(auth Auth, rpc *rpcClient, child *rpcGSS, input []v4Op, cache bool) ([]v4Op, error) {
	if v.channel.Request == 0 || len(v.session) == 0 {
		return input, nil
	}
	req, resp, protection, err := v.channelSizes(auth, rpc, child)
	if err != nil {
		return nil, err
	}
	ops := append([]v4Op(nil), input...)
	request := req + protection + 48
	for _, op := range ops {
		request += 4 + uint64(len(op.args))
	}
	for i, op := range ops {
		if op.code != 38 || len(op.args) < 32 {
			continue
		}
		n := uint64(binary.BigEndian.Uint32(op.args[28:]))
		if n > uint64(len(op.args)-32) {
			continue
		}
		fixed := request - pad4(n)
		available := payloadAfter(v.channel.Request, fixed)
		if n > uint64(available) && available != 0 {
			a := append(encoder(nil), op.args[:32+int(available)]...)
			binary.BigEndian.PutUint32(a[28:], available)
			ops[i].args = a
			request = fixed + uint64(available)
		}
	}
	limit := v.channel.Response
	if cache {
		limit = min(limit, v.channel.Cached)
	}
	for i, op := range ops {
		var offset int
		var body uint64
		switch op.code {
		case 25:
			offset, body = 24, 16
		case 26:
			offset, body = 20, 4 // maxcount includes READDIR4res, excluding opcode
		case 74:
			offset, body = 8, 8 // LISTXATTRS maxcount covers resok, excluding opcode/status.
		case 50:
			offset, body = 52, 8 // bound returned layout body by available slot space
		default:
			continue
		}
		if len(op.args) < offset+4 {
			continue
		}
		fixed := resp + protection + 56 + body
		for j, other := range ops {
			if i != j {
				fixed += knownReplyBody(other)
			}
		}
		available := payloadAfter(limit, fixed)
		if available == 0 || op.code == 26 && available < 20 || op.code == 74 && available < 16 {
			return nil, channelRefusal("NFSv4 channel has no space for operation %d data", op.code)
		}
		count := binary.BigEndian.Uint32(op.args[offset:])
		if count > available {
			a := append(encoder(nil), op.args...)
			binary.BigEndian.PutUint32(a[offset:], available)
			if op.code == 26 && binary.BigEndian.Uint32(a[16:]) > available {
				binary.BigEndian.PutUint32(a[16:], available)
			}
			ops[i].args = a
		}
	}
	return ops, nil
}
