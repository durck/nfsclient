// Package nfs implements the NFS protocol subsets used by the interactive client.
package nfs

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"nfsclient/internal/resolve"
)

const maxRecord = 8 << 20

// ErrConnectionLost distinguishes a closed transport from malformed RPC/XDR.
// It never authorizes replay of the RPC that may have closed the connection.
var ErrConnectionLost = errors.New("RPC session closed; reconnect (no request replay)")

// ConnectionLostError marks an incomplete transport record, preserving its
// cause. A complete record with truncated XDR is a protocol error instead.
type ConnectionLostError struct{ Err error }

func (e *ConnectionLostError) Error() string        { return fmt.Sprintf("%v: %v", ErrConnectionLost, e.Err) }
func (e *ConnectionLostError) Unwrap() error        { return e.Err }
func (e *ConnectionLostError) Is(target error) bool { return target == ErrConnectionLost }

// RPCStatus identifies protocol errors without matching human-readable text.
type RPCStatus uint32

type RPCDenied uint32

func (s RPCDenied) Error() string { return fmt.Sprintf("RPC request denied (code %d)", s) }

func (s RPCStatus) Error() string {
	return fmt.Sprintf("RPC accept status %d (1=program unavailable, 2=version mismatch, 3=procedure unavailable)", s)
}

func unsupported(err error) bool {
	return errors.Is(err, Status(10004)) || errors.Is(err, RPCStatus(3))
}

type encoder []byte

func (e *encoder) u32(v uint32) { *e = binary.BigEndian.AppendUint32(*e, v) }
func (e *encoder) u64(v uint64) { *e = binary.BigEndian.AppendUint64(*e, v) }
func (e *encoder) opaque(v []byte) {
	e.u32(uint32(len(v)))
	*e = append(*e, v...)
	*e = append(*e, make([]byte, (4-len(v)%4)%4)...)
}
func (e *encoder) str(v string) { e.opaque([]byte(v)) }

type decoder struct {
	b              []byte
	err            error
	verifierFlavor uint32
	verifier       []byte
}

func (d *decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.err = io.ErrUnexpectedEOF
		return nil
	}
	b := d.b[:n]
	d.b = d.b[n:]
	return b
}
func (d *decoder) u32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (d *decoder) u64() uint64 {
	b := d.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (d *decoder) boolean() bool {
	v := d.u32()
	if v > 1 {
		d.err = errors.New("invalid XDR boolean")
	}
	return v == 1
}
func (d *decoder) opaque(limit uint32) []byte {
	n := d.u32()
	if n > limit {
		d.err = fmt.Errorf("XDR length %d exceeds %d", n, limit)
		return nil
	}
	b := d.take(int(n))
	d.take(int((4 - n%4) % 4))
	return b
}
func (d *decoder) str() string { return string(d.opaque(4096)) }

type Auth struct {
	UID    uint32   `json:"uid"`
	GID    uint32   `json:"gid"`
	Groups []uint32 `json:"groups"`
}

func (a Auth) encode(e *encoder) {
	var body encoder
	body.u32(uint32(time.Now().Unix()))
	body.str("nfs-viewer")
	body.u32(a.UID)
	body.u32(a.GID)
	body.u32(uint32(len(a.Groups)))
	for _, g := range a.Groups {
		body.u32(g)
	}
	e.u32(1)
	e.opaque(body)
}

type rpcClient struct {
	conn                 net.Conn
	tlsVerifiedChains    [][]*x509.Certificate
	timeout              time.Duration
	mu                   sync.Mutex
	xid                  uint32
	udp                  bool
	iwarp                *iwarpTransport
	duplex               *rpcDuplex
	udpRetryDelay        time.Duration // zero selects the conservative one-second default
	gss                  *rpcGSS
	kerberos             *kerberosSession
	pinnedBackchannelGSS bool
	backchannel          *gssBackchannelSet
	copyParentPins       uint32
	copyOriginalPin      bool
	backchannelRenewing  bool
	closed               bool
	closing              bool
}

// Called with mu held. A failed authenticated connection must never initiate
// fresh credentials or revive an operation with an uncertain outcome.
func (c *rpcClient) closeLocked() {
	c.closed = true
	c.conn.Close()
}

func dialRPC(ctx context.Context, host string, port int, timeout time.Duration, reserved bool) (*rpcClient, error) {
	return dialRPCTransport(ctx, host, port, timeout, reserved, "tcp")
}

func dialRPCTransport(ctx context.Context, host string, port int, timeout time.Duration, reserved bool, transport string) (*rpcClient, error) {
	return dialRPCResolved(ctx, host, port, timeout, reserved, transport, resolve.Config{})
}

func dialRPCResolved(ctx context.Context, host string, port int, timeout time.Duration, reserved bool, transport string, dns resolve.Config) (*rpcClient, error) {
	if transport != "tcp" && transport != "udp" {
		return nil, errors.New("transport must be tcp or udp")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resolver, err := resolve.New(ctx, dns)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout, Resolver: resolver}
	var conn net.Conn
	if reserved {
		for p := 1023; p >= 900; p-- {
			d.LocalAddr = &net.TCPAddr{Port: p}
			if transport == "udp" {
				d.LocalAddr = &net.UDPAddr{Port: p}
			}
			conn, err = d.DialContext(ctx, transport, addr)
			if err == nil {
				break
			}
			var op *net.OpError
			if !errors.As(err, &op) || op.Op != "dial" || ctx.Err() != nil {
				break
			}
			// Only retry a local bind collision, never a remote failure.
			if !isAddressInUse(err) {
				break
			}
		}
	} else {
		conn, err = d.DialContext(ctx, transport, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		conn.Close()
		return nil, err
	}
	return &rpcClient{conn: conn, timeout: timeout, udp: transport == "udp", xid: binary.BigEndian.Uint32(seed[:])}, nil
}

func readRecord(r io.Reader) ([]byte, error) {
	var all []byte
	for fragments := 0; fragments < 1024; fragments++ {
		var h [4]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(h[:])
		size := int(n & 0x7fffffff)
		if size > maxRecord-len(all) {
			return nil, errors.New("RPC record exceeds 8 MiB")
		}
		start := len(all)
		all = append(all, make([]byte, size)...)
		if _, err := io.ReadFull(r, all[start:]); err != nil {
			return nil, err
		}
		if n&0x80000000 != 0 {
			return all, nil
		}
	}
	return nil, errors.New("too many RPC fragments")
}

func (c *rpcClient) call(ctx context.Context, prog, vers, proc uint32, auth *Auth, args encoder) (*decoder, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrConnectionLost
	}
	if c.kerberos != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
		if err := c.renewKerberosLocked(ctx); err != nil {
			return nil, err
		}
	}
	if c.udp && c.gss != nil && udpReadOnly(prog, vers, proc) {
		return c.callGSSUDPLocked(ctx, prog, vers, proc, auth, args)
	}
	return c.callLocked(ctx, prog, vers, proc, auth, args, 0)
}

func (c *rpcClient) callLocked(ctx context.Context, prog, vers, proc uint32, auth *Auth, args encoder, gssProc uint32) (*decoder, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.xid++
	var e encoder
	e.u32(c.xid)
	e.u32(0)
	e.u32(2)
	e.u32(prog)
	e.u32(vers)
	e.u32(proc)
	if c.gss != nil {
		if err := c.gss.encode(&e, gssProc); err != nil {
			c.closeLocked()
			return nil, err
		}
	} else {
		if auth == nil {
			e.u32(0)
			e.u32(0)
		} else {
			auth.encode(&e)
		}
		e.u32(0)
		e.u32(0)
	}
	if c.gss != nil && (gssProc == 0 || gssProc == 5 || gssProc == 6) {
		var err error
		args, err = c.gss.protect(args)
		if err != nil {
			c.closeLocked()
			return nil, err
		}
	}
	e = append(e, args...)
	if budget, ok := ctx.Value(sessionWireBudgetKey{}).(sessionWireBudget); ok && gssProc == 0 {
		if uint64(len(e)) > uint64(budget.request) {
			return nil, channelRefusal("encoded NFSv4 RPC request needs %d bytes, channel permits %d", len(e), budget.request)
		}
	}
	if len(e) > maxRecord {
		return nil, errors.New("RPC request exceeds 8 MiB")
	}
	if c.iwarp != nil && len(e) > iwarpRPCSize {
		return nil, errors.New("RPC exceeds software iWARP inline limit (4068 bytes); request not sent")
	}
	deadline := time.Now().Add(c.timeout)
	if c.gss != nil && !c.gss.expiry.IsZero() && c.gss.expiry.Before(deadline) {
		deadline = c.gss.expiry
	}
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	if c.duplex == nil {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Now()); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	if c.udp {
		readOnly := udpReadOnly(prog, vers, proc) && gssProc == 0
		d, err := c.callUDP(ctx, e, deadline, readOnly)
		if c.gss == nil {
			return d, err
		}
		// Only the serialized read retry loop may retain a socket after a timeout.
		if err != nil {
			if expiryErr := c.gss.checkExpiry(time.Now()); expiryErr != nil {
				err = fmt.Errorf("%w; in-flight request outcome may be unknown", expiryErr)
			} else if readOnly && isRPCTimeout(err) {
				return nil, err
			}
		}
		d, err = c.acceptGSSReply(d, err, gssProc)
		if err != nil {
			c.closeLocked()
			if gssProc == 0 && !readOnly {
				err = fmt.Errorf("UDP authenticated mutation outcome unknown; request not replayed: %w", err)
			}
		}
		return d, err
	}
	var b []byte
	var err error
	if c.duplex != nil {
		b, err = c.duplex.exchange(ctx, e, deadline)
	} else if c.iwarp != nil {
		if err = c.iwarp.send(e, c.xid); err == nil {
			b, err = c.iwarp.receive(c.xid)
		}
	} else {
		packet := binary.BigEndian.AppendUint32(nil, uint32(len(e))|0x80000000)
		packet = append(packet, e...)
		for len(packet) > 0 {
			n, err := c.conn.Write(packet)
			if err != nil {
				c.closeLocked()
				if c.gss != nil {
					if expiryErr := c.gss.checkExpiry(time.Now()); expiryErr != nil {
						return nil, fmt.Errorf("%w; in-flight request outcome may be unknown", expiryErr)
					}
				}
				if gssProc != 0 {
					return nil, err
				}
				return nil, markRPCTransportFailure(err)
			}
			if n == 0 {
				c.closeLocked()
				return nil, io.ErrNoProgress
			}
			packet = packet[n:]
		}
		b, err = readRecord(c.conn)
	}
	if err != nil {
		c.closeLocked()
		if c.gss != nil {
			if expiryErr := c.gss.checkExpiry(time.Now()); expiryErr != nil {
				return nil, fmt.Errorf("%w; in-flight request outcome may be unknown", expiryErr)
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			if gssProc != 0 {
				return nil, &ConnectionLostError{Err: err}
			}
			return nil, &rpcTransportFailure{&ConnectionLostError{Err: err}}
		}
		if gssProc != 0 {
			return nil, fmt.Errorf("RPC context exchange failed: %w", err)
		}
		return nil, fmt.Errorf("RPC reply (session closed; reconnect): %w", markRPCTransportFailure(err))
	}
	if budget, ok := ctx.Value(sessionWireBudgetKey{}).(sessionWireBudget); ok && gssProc == 0 && uint64(len(b)) > uint64(budget.response) {
		c.closeLocked()
		return nil, errors.New("NFSv4 RPC reply exceeds negotiated channel limit; session closed")
	}
	d, err := c.decodeReply(b)
	return c.acceptGSSReply(d, err, gssProc)
}

func (c *rpcClient) acceptGSSReply(d *decoder, err error, gssProc uint32) (*decoder, error) {
	if c.gss != nil && gssProc != 1 && gssProc != 2 {
		if err == nil {
			err = c.gss.verify(d, c.gss.seq)
		}
		if err == nil && (gssProc == 0 || gssProc == 5 || gssProc == 6) {
			err = c.gss.unprotect(d)
		}
		if err != nil {
			c.closeLocked()
			return nil, fmt.Errorf("authenticated RPC failed (session closed; reconnect): %w", err)
		}
	}
	return d, err
}

func (c *rpcClient) decodeReply(b []byte) (*decoder, error) {
	d := &decoder{b: b}
	if d.u32() != c.xid || d.u32() != 1 {
		c.closeLocked()
		return nil, errors.New("invalid RPC reply header")
	}
	replyState := d.u32()
	if replyState == 1 {
		reason := d.u32()
		switch reason {
		case 0:
			d.take(8) // RPC version range
		case 1:
			d.u32() // authentication failure
		default:
			return nil, errors.New("invalid RPC rejection status")
		}
		if d.err != nil {
			return nil, d.err
		}
		return nil, RPCDenied(reason)
	}
	if replyState != 0 {
		return nil, errors.New("invalid RPC reply status")
	}
	d.verifierFlavor = d.u32()
	d.verifier = d.opaque(400)
	status := d.u32()
	if status == 2 {
		d.take(8)
	} // program version range
	if d.err != nil {
		return nil, d.err
	}
	if status > 5 {
		return nil, errors.New("invalid RPC accept status")
	}
	if status != 0 {
		return nil, RPCStatus(status)
	}
	return d, nil
}
