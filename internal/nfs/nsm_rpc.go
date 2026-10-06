package nfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

func readNSMRecord(r io.Reader) ([]byte, error) {
	var out []byte
	for i := 0; i < 16; i++ {
		var header [4]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, err
		}
		mark := binary.BigEndian.Uint32(header[:])
		size := int(mark & 0x7fffffff)
		if size > 4096-len(out) {
			return nil, errors.New("NSM RPC exceeds 4096 bytes")
		}
		pos := len(out)
		out = append(out, make([]byte, size)...)
		if _, err := io.ReadFull(r, out[pos:]); err != nil {
			return nil, err
		}
		if mark&0x80000000 != 0 {
			return out, nil
		}
	}
	return nil, errors.New("too many NSM record fragments")
}

func nsmRecordBytes(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))|0x80000000), b...)
}

func (n *nsmMonitor) respond(b []byte, send func([]byte) error) {
	reply, sent := n.dispatch(b)
	if reply == nil {
		return
	}
	err := send(reply)
	if sent != nil {
		sent(err)
	}
}

// The completion hook is mandatory for matched synchronous grants, including
// failed writes. It releases the grant/cancel serialization lock.
func (n *nsmMonitor) dispatch(b []byte) ([]byte, func(error)) {
	if len(b) > 4096 {
		return nil, nil
	}
	d := &decoder{b: b}
	xid, direction, rpcVersion := d.u32(), d.u32(), d.u32()
	program, version, procedure := d.u32(), d.u32(), d.u32()
	flavor, credentials := d.u32(), d.opaque(400)
	verifier, signature := d.u32(), d.opaque(400)
	if d.err != nil || direction != 0 || rpcVersion != 2 {
		return nil, nil
	}
	var result encoder
	var sent func(error)
	status := uint32(0)
	if (flavor != 0 && flavor != 1) || flavor == 0 && len(credentials) != 0 || verifier != 0 || len(signature) != 0 {
		return nil, nil
	}
	switch program {
	case 100000:
		if version < 2 || version > 4 {
			status = 2
			result.u32(2)
			result.u32(4)
			break
		}
		if procedure == 0 {
			break
		}
		if procedure != 3 {
			status = 3
			break
		}
		prog, vers := d.u32(), d.u32()
		if version == 2 {
			protocol := d.u32()
			d.u32()
			port := uint32(0)
			if n.callbackProgram(prog, vers) && (protocol == 6 || protocol == 17) {
				port = uint32(n.port)
			}
			result.u32(port)
		} else {
			netid := string(d.opaque(16))
			d.opaque(1024)
			d.opaque(1024)
			address := ""
			if n.callbackProgram(prog, vers) && (netid == "tcp" || netid == "udp") {
				address = fmt.Sprintf("%s.%d.%d", n.cfg.NLMClientIP, n.port/256, n.port%256)
			}
			result.str(address)
		}
	case nlmProgram:
		cb := n.callbacks.Load()
		if cb == nil {
			status = 1
			break
		}
		if version != cb.version {
			status = 2
			result.u32(cb.version)
			result.u32(cb.version)
			break
		}
		if procedure == 5 {
			result, status, sent = cb.synchronousGrant(d)
		} else {
			status = cb.dispatch(procedure, d)
		}
	case nsmProgram:
		if version != 1 {
			status = 2
			result.u32(1)
			result.u32(1)
			break
		}
		switch procedure {
		case 0:
		case 1:
			name := string(d.opaque(1024))
			if name == n.peer || name == n.cfg.NLMClientIP {
				result.u32(0)
			} else {
				result.u32(1)
			}
			result.u32(n.localEpoch.Load())
		case 6:
			name, state := string(d.opaque(1024)), d.u32()
			if name == "" || strings.ContainsAny(name, "\x00\r\n") {
				status = 4
				break
			}
			if d.err == nil && len(d.b) == 0 && state != n.peerState {
				n.invalidate()
			}
		default:
			status = 3 // No external MON/UNMON or simulated-crash service.
		}
	default:
		status = 1
	}
	if status == 0 && (d.err != nil || len(d.b) != 0) {
		status = 4
		result = nil
	}
	var reply encoder
	for _, value := range []uint32{xid, 1, 0, 0, 0, status} {
		reply.u32(value)
	}
	if status == 0 || status == 2 {
		reply = append(reply, result...)
	}
	return reply, sent
}

func (n *nsmMonitor) callbackProgram(program, version uint32) bool {
	if program == nsmProgram && version == 1 {
		return true
	}
	cb := n.callbacks.Load()
	return cb != nil && program == nlmProgram && version == cb.version
}
