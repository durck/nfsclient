package iscsi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Volume retains one TCP session. Protocol/SCSI errors and uncertain writes
// poison it permanently; read transport recovery requires explicit approval.
type Volume struct {
	mu                             sync.Mutex
	conn                           net.Conn
	ctx                            context.Context
	stop                           func() bool
	target                         Target
	timeout                        time.Duration
	write                          bool
	lost                           error
	cmd, stat, tag, maxCmd, expCmd uint32
	recv                           int
	id                             []byte
	headerDigest, dataDigest       bool
	size                           int64
	sector                         int64
	initiator                      string
	policy                         Security
	securityProof                  [32]byte
	recovery                       *readRecovery
}

func Open(ctx context.Context, target Target, initiator string, timeout time.Duration, writable bool) (v *Volume, resultErr error) {
	return OpenWithSecurity(ctx, target, initiator, timeout, writable, Security{})
}

func OpenWithSecurity(ctx context.Context, target Target, initiator string, timeout time.Duration, writable bool, policy Security) (v *Volume, resultErr error) {
	v, err := openSessionSecurity(ctx, target, initiator, timeout, writable, policy)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			v.Close()
			v = nil
		}
	}()
	return probeVolume(v)
}

func openSessionSecurity(ctx context.Context, target Target, initiator string, timeout time.Duration, writable bool, policy Security) (v *Volume, resultErr error) {
	return openSessionSecurityChecked(ctx, target, initiator, timeout, writable, policy, nil)
}

func openSessionSecurityChecked(ctx context.Context, target Target, initiator string, timeout time.Duration, writable bool, policy Security, expected *[32]byte) (v *Volume, resultErr error) {
	secret, targetSecret, err := policy.secrets()
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	defer clear(targetSecret)
	proof := securityProof(secret, targetSecret)
	if expected != nil && proof != *expected {
		return nil, errors.New("iSCSI authentication material changed before read recovery")
	}
	if !ValidName(initiator) {
		return nil, errors.New("iSCSI needs an explicit normalized initiator IQN")
	}
	approved, err := ParseTarget("iscsi://" + target.Endpoint + "/" + target.Name + "/" + strconv.Itoa(int(target.LUN)))
	if err != nil || approved != target {
		return nil, errors.New("invalid iSCSI target approval")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", target.Endpoint)
	if err != nil {
		return nil, err
	}
	v = &Volume{conn: conn, ctx: ctx, target: target, timeout: timeout, write: writable, cmd: 1, tag: 1, recv: 8192, initiator: initiator, policy: policy, securityProof: proof}
	v.stop = context.AfterFunc(ctx, func() { conn.Close() })
	defer func() {
		if resultErr != nil {
			v.Close()
			v = nil
		}
	}()
	if err = v.loginSecurity(initiator, policy, secret, targetSecret); err != nil {
		return v, err
	}
	return v, nil
}

func probeVolume(v *Volume) (*Volume, error) {
	var inquiry [16]byte
	inquiry[0] = 0x12
	inquiry[1] = 1
	inquiry[2] = 0x83
	inquiry[4] = 252
	data := make([]byte, 252)
	n, err := v.command(inquiry, data, nil, true)
	if err != nil {
		return v, err
	}
	v.id, err = decodeNAA(data[:n])
	if err != nil {
		return v, err
	}
	var capacity [16]byte
	capacity[0] = 0x9e
	capacity[1] = 0x10
	binary.BigEndian.PutUint32(capacity[10:14], 32)
	data = make([]byte, 32)
	if _, err = v.command(capacity, data, nil, false); err != nil {
		return v, err
	}
	v.size, v.sector, err = decodeCapacity(data)
	if err != nil {
		return v, err
	}
	return v, nil
}

func (v *Volume) deadline() error {
	if v.lost != nil {
		return v.lost
	}
	if err := v.ctx.Err(); err != nil {
		return err
	}
	d := time.Now().Add(v.timeout)
	if cd, ok := v.ctx.Deadline(); ok && cd.Before(d) {
		d = cd
	}
	return v.conn.SetDeadline(d)
}
func (v *Volume) poison(err error) error {
	if err != nil && v.lost == nil {
		v.lost = fmt.Errorf("iSCSI session lost: %w", err)
		v.conn.Close()
	}
	return v.lost
}

func loginText(data []byte) (map[string]string, error) {
	if len(data) == 0 || data[len(data)-1] != 0 {
		return nil, errors.New("unterminated iSCSI login text")
	}
	keys := map[string]string{}
	for _, pair := range strings.Split(string(data[:len(data)-1]), "\x00") {
		k, value, ok := strings.Cut(pair, "=")
		if !ok || k == "" || value == "" || keys[k] != "" {
			return nil, errors.New("invalid or duplicate login key")
		}
		for _, c := range pair {
			if c < 32 || c > 126 {
				return nil, errors.New("non-ASCII login text")
			}
		}
		keys[k] = value
	}
	return keys, nil
}

// The command window uses RFC 7143 serial arithmetic and permits a closed
// window, but never issues a command outside it or waits indefinitely for it.
func (v *Volume) window(p pdu) error {
	exp, maxCmd := p.word(28), p.word(32)
	if int32(exp-v.cmd) > 0 || int32(exp-v.expCmd) < 0 || int32(maxCmd-(exp-1)) < 0 {
		return errors.New("invalid iSCSI command window")
	}
	v.expCmd, v.maxCmd = exp, maxCmd
	return nil
}

func (v *Volume) command(cdb [16]byte, in, out []byte, short bool) (count int, resultErr error) {
	return v.commandBytes(cdb[:], in, out, short)
}

func (v *Volume) commandBytes(cdb []byte, in, out []byte, short bool) (count int, resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = v.poison(resultErr)
		}
	}()
	if err := v.deadline(); err != nil {
		return 0, err
	}
	if int32(v.cmd-v.maxCmd) > 0 {
		return 0, errors.New("iSCSI command window closed")
	}
	bidi := len(in) != 0 && len(out) != 0
	if len(in) > maxSegment || len(out) > maxSegment || len(cdb) != 16 && len(cdb) != 200 || bidi && (len(cdb) != 200 || short) {
		return 0, errors.New("unsupported SCSI transfer size/direction")
	}
	v.tag++
	if v.tag == math.MaxUint32 {
		v.tag = 2
	}
	var req pdu
	req.h[0] = 1
	req.h[1] = 0x81
	req.h[9] = v.target.LUN
	req.set(16, v.tag)
	expected := len(in)
	if len(out) > 0 {
		expected = len(out)
	}
	req.set(20, uint32(expected))
	req.set(24, v.cmd)
	req.set(28, v.stat)
	copy(req.h[32:], cdb[:])
	if len(cdb) > 16 {
		req.ahs = make([]byte, 4+len(cdb)-16)
		binary.BigEndian.PutUint16(req.ahs[:2], uint16(len(cdb)-15))
		req.ahs[2] = 1
		copy(req.ahs[4:], cdb[16:])
	}
	if bidi {
		a := make([]byte, 8)
		binary.BigEndian.PutUint16(a[:2], 5)
		a[2] = 2
		binary.BigEndian.PutUint32(a[4:], uint32(len(in)))
		req.ahs = append(req.ahs, a...)
	}
	if len(in) > 0 {
		req.h[1] |= 0x40
	}
	if len(out) > 0 {
		req.h[1] |= 0x20
	}
	if err := writeDigestPDU(v.conn, req, v.headerDigest, v.dataDigest); err != nil {
		return 0, err
	}
	v.cmd++
	// RFC 7143 section 4.2.2.4 gives bidirectional R2T and Data-In one
	// incoming sequence. Count Data-In PDUs separately to retain their bound.
	var inputSN, dataPDUs uint32
	sent, received, controls := 0, 0, 0
	dataSequenceOpen := false
	for {
		p, err := readDigestPDU(v.conn, v.headerDigest, v.dataDigest)
		if err != nil {
			return 0, err
		}
		if err = v.window(p); err != nil {
			return 0, err
		}
		if p.h[0] == 0x20 { // Unsolicited target ping; it does not advance StatSN.
			controls++
			if controls > 8 || p.h[1] != 0x80 || p.word(16) != math.MaxUint32 || p.word(24) != v.stat {
				return 0, errors.New("invalid or excessive target NOP-In")
			}
			if p.word(20) != math.MaxUint32 {
				var pong pdu
				pong.h[0] = 0x40
				pong.h[1] = 0x80
				copy(pong.h[8:16], p.h[8:16])
				pong.set(16, math.MaxUint32)
				pong.set(20, p.word(20))
				pong.set(24, v.cmd)
				pong.set(28, v.stat)
				pong.data = p.data
				if err = writeDigestPDU(v.conn, pong, v.headerDigest, v.dataDigest); err != nil {
					return 0, err
				}
			}
			continue
		}
		if p.word(16) != v.tag {
			return 0, errors.New("mismatched iSCSI task tag")
		}
		switch p.h[0] {
		case 0x31:
			n := int(p.word(44))
			ttt := p.word(20)
			if len(out) == 0 || len(p.data) != 0 || p.h[1] != 0x80 || !bytes.Equal(p.h[8:16], req.h[8:16]) || p.word(24) != v.stat || p.word(36) != inputSN || int(p.word(40)) != sent || n == 0 || n > maxSegment || n > len(out)-sent || ttt == math.MaxUint32 {
				return 0, errors.New("invalid/overlapping iSCSI R2T; replay refused")
			}
			inputSN++
			var sn uint32
			for left := n; left > 0; {
				size := min(left, v.recv)
				var data pdu
				data.h[0] = 5
				if size == left {
					data.h[1] = 0x80
				}
				copy(data.h[8:16], p.h[8:16])
				data.set(16, v.tag)
				data.set(20, ttt)
				data.set(28, v.stat)
				data.set(36, sn)
				data.set(40, uint32(sent))
				data.data = out[sent : sent+size]
				if err = writeDigestPDU(v.conn, data, v.headerDigest, v.dataDigest); err != nil {
					return 0, err
				}
				sn++
				sent += size
				left -= size
			}
		case 0x25:
			if len(in) == 0 || dataPDUs >= 1024 || p.h[1]&^byte(0x83) != 0 || p.word(36) != inputSN || int(p.word(40)) != received || len(p.data) > len(in)-received || p.h[1]&1 != 0 && p.h[1]&0x80 == 0 || p.h[1]&2 != 0 && p.h[1]&1 == 0 {
				return 0, errors.New("invalid/out-of-order SCSI Data-In")
			}
			inputSN++
			dataPDUs++
			copy(in[received:], p.data)
			received += len(p.data)
			// F ends this data sequence, not the command. Only S or a separate
			// SCSI response completes it (RFC 7143 section 11.7.1).
			dataSequenceOpen = p.h[1]&0x80 == 0
			if p.h[1]&1 == 0 {
				continue
			}
			if p.word(24) != v.stat || p.h[3] != 0 || bidi {
				return 0, errors.New("invalid SCSI Data-In status")
			}
			v.stat++
			if err := transferResult(received, len(in), p.h[1]&2 != 0, p.word(44), short); err != nil {
				return 0, err
			}
			return received, nil
		case 0x21:
			if p.h[1]&^byte(0x82) != 0 || p.h[1]&0x80 == 0 || p.word(24) != v.stat || p.h[2] != 0 || p.h[3] != 0 || len(p.data) != 0 || len(in) > 0 && (p.word(36) != inputSN || dataSequenceOpen) {
				return 0, fmt.Errorf("SCSI response refused (response=%d status=%d)", p.h[2], p.h[3])
			}
			v.stat++
			if bidi {
				if p.h[1] != 0x80 || p.word(40) != 0 || p.word(44) != 0 || sent != len(out) || received != len(in) {
					return 0, errors.New("bidirectional OSD transfer length/residual mismatch")
				}
				return received, nil
			}
			n, expected := received, len(in)
			if len(out) > 0 {
				n, expected = sent, len(out)
			}
			if err := transferResult(n, expected, p.h[1]&2 != 0, p.word(44), short); err != nil {
				return 0, err
			}
			return n, nil
		default:
			return 0, fmt.Errorf("unsupported iSCSI target PDU %#x", p.h[0])
		}
	}
}

func transferResult(n, want int, under bool, residual uint32, short bool) error {
	if n > want || !under && (n != want || residual != 0) || under && (!short || residual == 0 || uint64(n)+uint64(residual) != uint64(want)) {
		return errors.New("SCSI transfer length/residual mismatch")
	}
	return nil
}

func (v *Volume) ReadAt(b []byte, off int64) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sector != 512 && v.sector != 4096 {
		return 0, errors.New("unknown iSCSI sector size")
	}
	if off < 0 || off > v.size || int64(len(b)) > v.size-off {
		return 0, io.EOF
	}
	done := 0
	for done < len(b) {
		if v.recovery != nil {
			if err := v.recovery.guard(); err != nil {
				return done, v.poison(err)
			}
		}
		start := (off + int64(done)) / v.sector * v.sector
		skip := int(off + int64(done) - start)
		n := min(len(b)-done, maxSegment-skip)
		data := make([]byte, (n+skip+int(v.sector)-1)/int(v.sector)*int(v.sector))
		var cdb [16]byte
		cdb[0] = 0x88
		binary.BigEndian.PutUint64(cdb[2:10], uint64(start/v.sector))
		binary.BigEndian.PutUint32(cdb[10:14], uint32(len(data)/int(v.sector)))
		if _, err := v.command(cdb, data, nil, false); err != nil {
			if err = v.recoverRead(cdb, data, err); err != nil {
				return done, err
			}
		}
		if v.recovery != nil {
			if err := v.recovery.guard(); err != nil {
				return done, v.poison(err)
			}
		}
		copy(b[done:done+n], data[skip:skip+n])
		done += n
	}
	return done, nil
}

func (v *Volume) WriteAt(b []byte, off int64) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sector != 512 && v.sector != 4096 {
		return 0, errors.New("unknown iSCSI sector size")
	}
	if !v.write || off < 0 || off%v.sector != 0 || len(b)%int(v.sector) != 0 || off > v.size || int64(len(b)) > v.size-off {
		return 0, errors.New("iSCSI writes require approval and complete aligned sectors")
	}
	done := 0
	for done < len(b) {
		n := min(len(b)-done, maxSegment)
		var cdb [16]byte
		cdb[0] = 0x8a
		binary.BigEndian.PutUint64(cdb[2:10], uint64((off+int64(done))/v.sector))
		binary.BigEndian.PutUint32(cdb[10:14], uint32(n/int(v.sector)))
		if _, err := v.command(cdb, nil, b[done:done+n], false); err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

func (v *Volume) Sync() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.write {
		return errors.New("read-only iSCSI volume")
	}
	var cdb [16]byte
	cdb[0] = 0x91
	_, err := v.command(cdb, nil, nil, false)
	return err
}
func (v *Volume) Check() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return errors.Join(v.lost, v.ctx.Err())
}
func (v *Volume) SectorSize() int64 { return v.sector }
func (v *Volume) Identity() string  { return string(v.id) }
func (v *Volume) Stat() (os.FileInfo, error) {
	if err := v.Check(); err != nil {
		return nil, err
	}
	return volumeInfo{v.target.Name, v.size}, nil
}
func (v *Volume) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.recovery != nil {
		v.recovery.failed = true
	}
	v.stop()
	if v.lost == nil {
		v.lost = net.ErrClosed
	}
	return v.conn.Close()
}

type volumeInfo struct {
	name string
	size int64
}

func (i volumeInfo) Name() string       { return i.name }
func (i volumeInfo) Size() int64        { return i.size }
func (i volumeInfo) Mode() os.FileMode  { return 0 }
func (i volumeInfo) ModTime() time.Time { return time.Time{} }
func (i volumeInfo) IsDir() bool        { return false }
func (i volumeInfo) Sys() any           { return nil }
