package nfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const udpTransferMax = 4096
const udpPayloadMax = 65507

func (c *Client) udpSize() uint32 {
	if c.config != nil && c.config.UDPSize != 0 {
		return c.config.UDPSize
	}
	return udpTransferMax
}

// Allowlist observations, not merely traditionally idempotent operations.
// Replaying WRITE/SETATTR can overwrite a concurrent writer even with the same XID.
func udpReadOnly(prog, vers, proc uint32) bool {
	if prog == nlmProgram && (vers == 1 || vers == 4) {
		return proc == 1 // TEST only; lock mutations and callbacks never retry.
	}
	if prog == 100000 && vers == 2 {
		return proc == 0 || proc == 3
	}
	if prog == mountProgram && (vers == 1 || vers == 3) {
		return proc == 0 || proc == 5
	}
	if prog == nfsACLProgram && (vers == 2 || vers == 3) {
		return proc == 1 // GETACL only; SETACL and unknown procedures never retry.
	}
	if prog != nfsProgram {
		return false
	}
	if vers == 2 {
		switch proc {
		case 0, 1, 4, 5, 6, 16, 17:
			return true
		}
	}
	if vers == 3 {
		switch proc {
		case 0, 1, 3, 4, 5, 6, 16, 17, 18, 19, 20:
			return true
		}
	}
	return false
}

// One outstanding RPC per connected UDP socket; the OS filters the source peer.
// Ignore late/duplicate XIDs without extending an attempt's absolute deadline.
// AUTH_SYS retransmissions retain the whole packet. GSS retries are rebuilt by
// callGSSUDPLocked; each invocation here sends its GSS request exactly once.
func (c *rpcClient) callUDP(ctx context.Context, request []byte, deadline time.Time, readOnly bool) (reply *decoder, resultErr error) {
	if len(request) > udpPayloadMax {
		return nil, errors.New("RPC request exceeds UDP datagram limit; use TCP")
	}
	sent := false
	defer func() {
		var accepted RPCStatus
		var denied RPCDenied
		if sent && !readOnly && resultErr != nil && !errors.As(resultErr, &accepted) && !errors.As(resultErr, &denied) {
			resultErr = fmt.Errorf("UDP mutation outcome unknown; request not replayed; inspect server state before retrying: %w", resultErr)
		}
	}()
	delay := c.udpRetryDelay
	if delay <= 0 {
		delay = time.Second
	}
	attempts := 1
	if readOnly && c.gss == nil {
		attempts = 3
	}
	buffer := make([]byte, 65536)
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			return nil, os.ErrDeadlineExceeded
		}
		if err := c.conn.SetWriteDeadline(deadline); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sent = true // A failed send can still leave delivery ambiguous.
		n, err := c.conn.Write(request)
		if err != nil {
			return nil, err
		}
		if n != len(request) {
			return nil, io.ErrShortWrite
		}
		until := deadline
		if readOnly && c.gss == nil {
			until = minTime(deadline, time.Now().Add(delay))
		}
		if err := c.conn.SetReadDeadline(until); err != nil {
			return nil, err
		}
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !time.Now().Before(until) {
				err = os.ErrDeadlineExceeded
				break
			}
			var count int
			count, err = c.conn.Read(buffer)
			if err != nil {
				break
			}
			if count < 4 || binary.BigEndian.Uint32(buffer[:4]) != c.xid {
				continue
			}
			if count > udpPayloadMax {
				return nil, errors.New("oversized RPC UDP reply")
			}
			return c.decodeReply(buffer[:count])
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			return nil, err
		}
		if attempt+1 == attempts || !time.Now().Before(deadline) {
			return nil, fmt.Errorf("UDP RPC timed out after %d attempt(s): %w", attempt+1, err)
		}
		delay = min(delay*2, 4*time.Second)
	}
	return nil, os.ErrDeadlineExceeded
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// RFC 2203 section 5.3.3.1 requires a fresh GSS sequence on every retry.
// Rebuild read-only calls with a fresh XID too: late replies are filtered by XID.
// Never enter this loop for INIT, DESTROY or filesystem mutations.
func (c *rpcClient) callGSSUDPLocked(ctx context.Context, prog, vers, proc uint32, auth *Auth, args encoder) (*decoder, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	delay := c.udpRetryDelay
	if delay <= 0 {
		delay = time.Second
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		attemptCtx, stop := context.WithTimeout(ctx, delay)
		var d *decoder
		d, err = c.callLocked(attemptCtx, prog, vers, proc, auth, args, 0)
		stop()
		if err == nil {
			return d, nil
		}
		if !isRPCTimeout(err) || ctx.Err() != nil {
			break
		}
		delay = min(delay*2, 4*time.Second)
	}
	c.closeLocked()
	return nil, fmt.Errorf("authenticated UDP read failed (session closed; reconnect): %w", err)
}

func isRPCTimeout(err error) bool {
	var timeout net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout())
}
