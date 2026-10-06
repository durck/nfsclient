package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func iwarpReply(xid uint32) []byte {
	var e encoder
	for _, v := range []uint32{xid, 1, 1, 0, 0, 0, 0, xid, 1, 0, 0, 0, 0} {
		e.u32(v)
	}
	return e
}

func ddpFixture(b []byte, msn, offset uint32, last bool) []byte {
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p, uint16(18+len(b)))
	p[2], p[3] = 1, 0x43
	if last {
		p[2] |= 0x40
	}
	binary.BigEndian.PutUint32(p[12:], msn)
	binary.BigEndian.PutUint32(p[16:], offset)
	p = append(p, b...)
	p = append(p, make([]byte, (4-len(p)%4)%4)...)
	return binary.LittleEndian.AppendUint32(p, crc32.Checksum(p, mpaCRC))
}

func TestIWARPReceive(t *testing.T) {
	for _, tc := range []string{"single", "segmented", "crc", "offset", "msn", "chunk", "credit", "xid", "oversize", "truncate", "opcode"} {
		t.Run(tc, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			msg := iwarpReply(7)
			if tc == "chunk" {
				msg[19] = 1
			}
			if tc == "credit" {
				msg[11] = 0
			}
			if tc == "xid" {
				msg[3] = 8
			}
			packet := ddpFixture(msg, 1, 0, true)
			switch tc {
			case "segmented":
				packet = append(ddpFixture(msg[:13], 1, 0, false), ddpFixture(msg[13:], 1, 13, true)...)
			case "crc":
				packet[len(packet)-1] ^= 1
			case "offset":
				packet = ddpFixture(msg, 1, 1, true)
			case "msn":
				packet = ddpFixture(msg, 2, 0, true)
			case "oversize":
				binary.BigEndian.PutUint16(packet, 65535)
			case "truncate":
				packet = packet[:len(packet)-1]
			case "opcode":
				packet[3] = 0x40
				binary.LittleEndian.PutUint32(packet[len(packet)-4:], crc32.Checksum(packet[:len(packet)-4], mpaCRC))
			}
			go func() { defer b.Close(); writeFull(b, packet) }()
			r := &iwarpTransport{conn: a, recvMSN: 1}
			got, err := r.receive(7)
			if tc == "single" || tc == "segmented" {
				if err != nil || !bytes.Equal(got, msg[28:]) || r.recvMSN != 2 {
					t.Fatal(got, err, r.recvMSN)
				}
			} else if err == nil {
				t.Fatal("malformed frame accepted")
			}
		})
	}
}

func TestIWARPHandshake(t *testing.T) {
	for _, tc := range []string{"valid", "reject", "crc-off", "markers", "small-buffer", "invalidation", "rtr", "cancel"} {
		t.Run(tc, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan struct{})
			defer close(finished)
			go func() {
				defer b.Close()
				req := make([]byte, 32)
				if _, err := io.ReadFull(b, req); err != nil {
					return
				}
				if string(req[:16]) != "MPA ID Req Frame" || req[16] != 0x50 || req[17] != 2 {
					t.Error("bad MPA request")
				}
				copy(req, "MPA ID Rep Frame")
				req[21], req[23] = 0, 1
				switch tc {
				case "reject":
					req[16] |= 0x20
				case "crc-off":
					req[16] &^= 0x40
				case "markers":
					req[16] |= 0x80
				case "small-buffer":
					req[31] = 0
				case "invalidation":
					req[29] = 1
				case "rtr":
					req[22] = 0x80
				case "cancel":
					cancel()
					return
				}
				writeFull(b, req)
				if tc == "valid" {
					<-finished
				}
			}()
			c := &rpcClient{conn: a, timeout: time.Second}
			err := c.startIWARP(ctx)
			if tc == "valid" {
				if err != nil || c.iwarp == nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsupported handshake accepted")
			}
		})
	}
}

func TestIWARPOversizedRequestNotSent(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &rpcClient{conn: a, timeout: time.Second, iwarp: &iwarpTransport{conn: a, sendMSN: 1, recvMSN: 1}}
	_, err := c.call(context.Background(), nfsProgram, 4, 1, nil, make([]byte, iwarpRPCSize))
	if err == nil || !strings.Contains(err.Error(), "request not sent") || c.closed || c.iwarp.sendMSN != 1 {
		t.Fatal(err, c.closed, c.iwarp.sendMSN)
	}
	b.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	var p [1]byte
	if n, _ := b.Read(p[:]); n != 0 {
		t.Fatal("oversized request wrote bytes")
	}
}

func TestIWARPProfileRefusals(t *testing.T) {
	for _, cfg := range []Config{
		{Version: "auto"}, {Version: "3"}, {Version: "4.2", Security: "krb5p"},
		{Version: "4.2", TLS: TLSConfig{Enabled: true}}, {Version: "4.2", UDPSize: 1024},
	} {
		cfg.Transport = "iwarp"
		cfg.Host = "invalid.invalid"
		cfg.Timeout = time.Second
		if _, err := Connect(context.Background(), cfg); err == nil {
			t.Fatal("unsupported profile accepted", cfg)
		}
	}
}

func TestIWARPCorruptionClosesWithoutReplay(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		var size [2]byte
		if _, err := io.ReadFull(b, size[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		frame := make([]byte, n+(4-(n+2)%4)%4+4)
		if _, err := io.ReadFull(b, frame); err != nil {
			return
		}
		if crc32.Checksum(append(size[:], frame[:len(frame)-4]...), mpaCRC) != binary.LittleEndian.Uint32(frame[len(frame)-4:]) {
			t.Error("outgoing CRC")
		}
		reply := ddpFixture(iwarpReply(1), 1, 0, true)
		reply[len(reply)-1] ^= 1
		writeFull(b, reply)
		var extra [1]byte
		b.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := b.Read(extra[:]); n != 0 {
			t.Error("request replayed")
		}
	}()
	c := &rpcClient{conn: a, timeout: time.Second, iwarp: &iwarpTransport{conn: a, sendMSN: 1, recvMSN: 1}}
	if _, err := c.call(context.Background(), nfsProgram, 4, 1, nil, nil); err == nil || !strings.Contains(err.Error(), "CRC32C") || !c.closed {
		t.Fatal(err, c.closed)
	}
	if _, err := c.call(context.Background(), nfsProgram, 4, 1, nil, nil); err != ErrConnectionLost {
		t.Fatal("closed connection reused", err)
	}
	<-done
}
