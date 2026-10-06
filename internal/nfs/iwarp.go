package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"time"
)

// Software iWARP implements only untagged SEND/RECEIVE. No memory regions or
// RPC/RDMA chunks are advertised. It does not provide hardware RDMA offload.
const iwarpInline = 4096
const iwarpRPCSize = iwarpInline - 28

var mpaCRC = crc32.MakeTable(crc32.Castagnoli)

type iwarpTransport struct {
	conn             net.Conn
	sendMSN, recvMSN uint32
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) != 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		b = b[n:]
	}
	return nil
}

// RFC 6581 enhanced MPA, without peer-to-peer RTR. One inbound read slot is
// negotiated for Linux CM compatibility, but no STags are exposed to the peer.
func (c *rpcClient) startIWARP(ctx context.Context) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := c.conn.SetDeadline(deadline); err != nil {
		return err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		if resultErr == nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
		if resultErr != nil {
			c.conn.Close()
		}
	}()
	req := make([]byte, 32)
	copy(req, "MPA ID Req Frame")
	req[16], req[17], req[19] = 0x50, 2, 12 // CRC, enhanced, revision, private length
	req[21] = 1                             // IRD=1, ORD=0, no peer-to-peer mode
	copy(req[24:], []byte{0xf6, 0xab, 0x0e, 0x18, 1, 0, 3, 3})
	if err := writeFull(c.conn, req); err != nil {
		return err
	}
	h := make([]byte, 20)
	if _, err := io.ReadFull(c.conn, h); err != nil {
		return err
	}
	if string(h[:16]) != "MPA ID Rep Frame" || h[16] != 0x50 || h[17] != 2 || binary.BigEndian.Uint16(h[18:]) != 12 {
		return errors.New("iWARP requires MPA v2, CRC32C, no markers/RTR and RFC 8797 negotiation; connection rejected")
	}
	p := make([]byte, 12)
	if _, err := io.ReadFull(c.conn, p); err != nil {
		return err
	}
	if binary.BigEndian.Uint16(p) != 0 || binary.BigEndian.Uint16(p[2:]) > 1 || !bytes.Equal(p[4:9], []byte{0xf6, 0xab, 0x0e, 0x18, 1}) || p[9] != 0 || p[10] < 3 || p[11] < 3 {
		return errors.New("unsupported iWARP negotiation: requires inline buffers >=4096, no remote invalidation or RDMA reads by client")
	}
	c.iwarp = &iwarpTransport{conn: c.conn, sendMSN: 1, recvMSN: 1}
	return c.conn.SetDeadline(time.Time{})
}

func (r *iwarpTransport) send(rpc []byte, xid uint32) error {
	if len(rpc) > iwarpRPCSize {
		return errors.New("RPC exceeds software iWARP inline limit (4068 bytes); request not sent")
	}
	var msg encoder
	for _, v := range []uint32{xid, 1, 1, 0, 0, 0, 0} {
		msg.u32(v)
	}
	msg = append(msg, rpc...)
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet, uint16(18+len(msg)))
	packet[2], packet[3] = 0x41, 0x43 // untagged, last, DDP v1, RDMAP SEND v1
	binary.BigEndian.PutUint32(packet[12:], r.sendMSN)
	packet = append(packet, msg...)
	packet = append(packet, make([]byte, (4-len(packet)%4)%4)...)
	packet = binary.LittleEndian.AppendUint32(packet, crc32.Checksum(packet, mpaCRC))
	if err := writeFull(r.conn, packet); err != nil {
		return err
	}
	r.sendMSN++
	return nil
}

func (r *iwarpTransport) receive(xid uint32) ([]byte, error) {
	var msg []byte
	for fragments := 0; fragments < 128; fragments++ {
		var length [2]byte
		if _, err := io.ReadFull(r.conn, length[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n <= 18 || n > 18+iwarpInline-len(msg) {
			return nil, errors.New("invalid or oversized iWARP DDP segment")
		}
		pad := (4 - (n+2)%4) % 4
		frame := make([]byte, 2+n+pad+4)
		copy(frame, length[:])
		if _, err := io.ReadFull(r.conn, frame[2:]); err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(frame[len(frame)-4:]) != crc32.Checksum(frame[:len(frame)-4], mpaCRC) {
			return nil, errors.New("iWARP CRC32C mismatch")
		}
		h := frame[2:]
		if (h[0] != 1 && h[0] != 0x41) || (h[1] != 0x43 && h[1] != 0x45) || binary.BigEndian.Uint32(h[2:]) != 0 || binary.BigEndian.Uint32(h[6:]) != 0 || binary.BigEndian.Uint32(h[10:]) != r.recvMSN || binary.BigEndian.Uint32(h[14:]) != uint32(len(msg)) {
			return nil, errors.New("unsupported or out-of-order iWARP DDP/RDMAP header")
		}
		msg = append(msg, h[18:n]...)
		if h[0]&0x40 == 0 {
			continue
		}
		r.recvMSN++
		if len(msg) < 52 || binary.BigEndian.Uint32(msg) != xid || binary.BigEndian.Uint32(msg[4:]) != 1 || binary.BigEndian.Uint32(msg[8:]) == 0 || binary.BigEndian.Uint32(msg[12:]) != 0 || !bytes.Equal(msg[16:28], make([]byte, 12)) || binary.BigEndian.Uint32(msg[28:]) != xid {
			return nil, fmt.Errorf("unsupported RPC/RDMA response (chunks, errors and callbacks are unsupported)")
		}
		return msg[28:], nil
	}
	return nil, errors.New("too many iWARP DDP fragments")
}
