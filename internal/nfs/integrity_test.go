package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func integrityEnvelope(sequence uint32, payload []byte) encoder {
	body := binary.BigEndian.AppendUint32(nil, sequence)
	body = append(body, payload...)
	mic, _ := (testMIC{}).MakeSignature(body)
	var out encoder
	out.opaque(body)
	out.opaque(mic)
	return out
}

func TestIntegrityFraming(t *testing.T) {
	g := &rpcGSS{context: testMIC{}, seq: 7, service: 2, established: true}
	for _, args := range []encoder{nil, {0, 0, 0, 42}, bytes.Repeat([]byte{0, 1, 2, 3}, 8192)} {
		wrapped, err := g.protect(args)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wrapped, integrityEnvelope(7, args)) {
			t.Fatal("incorrect signed sequence/body framing")
		}
		d := &decoder{b: wrapped}
		if err := g.unprotect(d); err != nil || !bytes.Equal(d.b, args) {
			t.Fatalf("round trip: %v", err)
		}
	}
	if _, err := g.protect(make(encoder, maxRecord)); err == nil {
		t.Fatal("oversized request accepted")
	}
	for _, mode := range []string{"payload", "mic", "replay", "truncated", "oversize", "trailing", "short", "unaligned", "plain"} {
		t.Run(mode, func(t *testing.T) {
			wire := integrityEnvelope(7, []byte{0, 0, 0, 42})
			switch mode {
			case "payload":
				wire[11] ^= 1
			case "mic":
				wire[len(wire)-1] ^= 1
			case "replay":
				wire = integrityEnvelope(6, []byte{0, 0, 0, 42})
			case "truncated":
				wire = wire[:len(wire)-1]
			case "oversize":
				binary.BigEndian.PutUint32(wire, maxRecord+1)
			case "trailing":
				wire = append(wire, 0, 0, 0, 0)
			case "short":
				wire = nil
				wire.opaque([]byte{1, 2})
				wire.opaque(nil)
			case "unaligned":
				wire = integrityEnvelope(7, []byte{42})
			case "plain":
				wire = []byte{0, 0, 0, 42}
			}
			d := &decoder{b: wire}
			if err := g.unprotect(d); err == nil {
				t.Fatal("invalid integrity body accepted")
			}
		})
	}
	g.service = 1
	args := encoder{0, 0, 0, 42}
	if got, err := g.protect(args); err != nil || !bytes.Equal(got, args) {
		t.Fatal("krb5 plaintext framing changed")
	}
}

func TestIntegrityRPCRejectsBeforeReturningResults(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "tampered"}[corrupt], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			c := &rpcClient{conn: client, timeout: time.Second, gss: &rpcGSS{context: testMIC{}, handle: []byte("ctx"), service: 2, established: true}}
			peerErr := make(chan error, 1)
			go func() {
				raw, err := readRecord(server)
				if err != nil {
					peerErr <- err
					return
				}
				d := &decoder{b: raw}
				xid := d.u32()
				d.take(20)
				if d.u32() != 6 {
					peerErr <- errors.New("wrong auth flavor")
					return
				}
				cred := &decoder{b: d.opaque(400)}
				cred.take(8)
				seq, svc := cred.u32(), cred.u32()
				if seq != 1 || svc != 2 {
					peerErr <- errors.New("wrong sequence/service")
					return
				}
				signed := len(raw) - len(d.b)
				if d.u32() != 6 {
					peerErr <- errors.New("missing verifier")
					return
				}
				if err := (testMIC{}).VerifySignature(raw[:signed], d.opaque(400)); err != nil {
					peerErr <- err
					return
				}
				body := d.opaque(maxRecord)
				mic := d.opaque(400)
				if d.err != nil || len(d.b) != 0 || !bytes.Equal(body, []byte{0, 0, 0, 1, 0, 0, 0, 99}) {
					peerErr <- errors.New("incorrect integrity arguments")
					return
				}
				if err := (testMIC{}).VerifySignature(body, mic); err != nil {
					peerErr <- err
					return
				}
				var reply encoder
				reply.u32(xid)
				reply.u32(1)
				reply.u32(0)
				reply.u32(6)
				headerMIC, _ := (testMIC{}).MakeSignature(binary.BigEndian.AppendUint32(nil, seq))
				reply.opaque(headerMIC)
				reply.u32(0)
				result := integrityEnvelope(seq, []byte{0, 0, 0, 42})
				if corrupt {
					result[11] ^= 1
				}
				reply = append(reply, result...)
				_, err = server.Write(record(reply, true))
				peerErr <- err
			}()
			var args encoder
			args.u32(99)
			d, err := c.call(context.Background(), nfsProgram, 3, 1, nil, args)
			if corrupt {
				if err == nil || d != nil {
					t.Fatal("unverified result exposed")
				}
				if _, err := c.call(context.Background(), nfsProgram, 3, 1, nil, args); err == nil {
					t.Fatal("failed integrity session reused")
				}
			} else if err != nil || d.u32() != 42 {
				t.Fatalf("valid protected result rejected: %v", err)
			}
			if err := <-peerErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}
