package nfs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These are independent RFC 2203 envelope peers, not native NFS/Kerberos
// interoperability evidence. AES-GCM supplies real confidentiality/tamper
// detection for the synthetic mechanism; the production wrap/unwrap routines
// are never used by the server side.
type v2GSSMechanism struct{ testMIC }

func (v2GSSMechanism) aead() cipher.AEAD {
	block, _ := aes.NewCipher([]byte("v2-fixture-key!!"))
	aead, _ := cipher.NewGCM(block)
	return aead
}
func (m v2GSSMechanism) Seal(body []byte) ([]byte, error) {
	aead := m.aead()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, body, nil), nil
}
func (m v2GSSMechanism) Unseal(token []byte) ([]byte, error) {
	aead := m.aead()
	if len(token) < aead.NonceSize() {
		return nil, errors.New("short fixture token")
	}
	return aead.Open(nil, token[:aead.NonceSize()], token[aead.NonceSize():], nil)
}

// One serial socket, with independent RPC header, credential and argument
// validation. A nil reply deliberately drops the packet/record.
func v2GSSPeer(t *testing.T, transport string, serve func([]byte) ([]byte, error)) *rpcClient {
	t.Helper()
	if transport == "udp" {
		_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
			reply, err := serve(b)
			if err != nil {
				t.Error(err)
				return
			}
			if reply != nil {
				if _, err := s.WriteToUDP(reply, a); err != nil {
					t.Error(err)
				}
			}
		})
		return udpClient(t, port)
	}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		for {
			var marker [4]byte
			if _, err := io.ReadFull(server, marker[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(marker[:])
			if n&0x80000000 == 0 || n&0x7fffffff > 65536 {
				t.Error("unexpected request record")
				return
			}
			b := make([]byte, n&0x7fffffff)
			if _, err := io.ReadFull(server, b); err != nil {
				t.Error(err)
				return
			}
			reply, err := serve(b)
			if err != nil {
				t.Error(err)
				return
			}
			if reply == nil {
				continue
			}
			packet := binary.BigEndian.AppendUint32(nil, uint32(len(reply))|0x80000000)
			if _, err := server.Write(append(packet, reply...)); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { client.Close(); server.Close(); <-done })
	return &rpcClient{conn: client, timeout: 150 * time.Millisecond}
}

type v2GSSCall struct {
	xid, program, version, proc, sequence, service uint32
	args                                           *decoder
}

func v2GSSDecode(raw []byte, service uint32) (*v2GSSCall, error) {
	d := &decoder{b: raw}
	c := &v2GSSCall{xid: d.u32()}
	if d.u32() != 0 || d.u32() != 2 {
		return nil, errors.New("incorrect RPC call header")
	}
	c.program, c.version, c.proc = d.u32(), d.u32(), d.u32()
	if d.u32() != 6 {
		return nil, errors.New("NFSv2 request downgraded authentication")
	}
	cred := &decoder{b: d.opaque(400)}
	if cred.u32() != 1 || cred.u32() != 0 {
		return nil, errors.New("incorrect GSS version/control procedure")
	}
	c.sequence, c.service = cred.u32(), cred.u32()
	if c.sequence == 0 || c.service != service || string(cred.opaque(380)) != "v2-context" || cred.err != nil || len(cred.b) != 0 {
		return nil, errors.New("incorrect GSS sequence/service/handle")
	}
	signed := raw[:len(raw)-len(d.b)]
	if d.u32() != 6 || (testMIC{}).VerifySignature(signed, d.opaque(400)) != nil {
		return nil, errors.New("incorrect call header signature")
	}
	body := d.b
	if service > 1 {
		body = d.opaque(65536)
		if service == 2 {
			if err := (testMIC{}).VerifySignature(body, d.opaque(400)); err != nil {
				return nil, err
			}
		} else {
			var err error
			body, err = (v2GSSMechanism{}).Unseal(body)
			if err != nil {
				return nil, err
			}
		}
		if d.err != nil || len(d.b) != 0 || len(body) < 4 || binary.BigEndian.Uint32(body) != c.sequence {
			return nil, errors.New("incorrect argument protection")
		}
		body = body[4:]
	}
	if d.err != nil {
		return nil, d.err
	}
	c.args = &decoder{b: body}
	return c, nil
}

func v2GSSResponse(c *v2GSSCall, result []byte, fault string) []byte {
	var reply encoder
	for _, n := range []uint32{c.xid, 1, 0, 6} {
		reply.u32(n)
	}
	sequence := c.sequence
	if fault == "replayed-verifier" {
		sequence--
	}
	mic, _ := (testMIC{}).MakeSignature(binary.BigEndian.AppendUint32(nil, sequence))
	if fault == "tampered-verifier" {
		mic[0] ^= 1
	}
	if fault == "sys-reply" {
		reply = reply[:12]
		reply.u32(0)
		mic = nil
	}
	reply.opaque(mic)
	reply.u32(0)
	if c.service == 1 {
		return append(reply, result...)
	}
	sequence = c.sequence
	if fault == "wrong-body-sequence" {
		sequence++
	}
	body := append(binary.BigEndian.AppendUint32(nil, sequence), result...)
	if c.service == 2 {
		mic, _ := (testMIC{}).MakeSignature(body)
		if fault == "tampered-body" {
			body[len(body)-1] ^= 1
		}
		reply.opaque(body)
		reply.opaque(mic)
	} else {
		token, _ := (v2GSSMechanism{}).Seal(body)
		if fault == "tampered-body" {
			token[len(token)-1] ^= 1
		}
		reply.opaque(token)
	}
	if fault == "trailing-envelope" {
		reply.u32(0)
	}
	if fault == "truncated-envelope" {
		reply = reply[:len(reply)-3]
	}
	return reply
}

func v2GSSClient(t *testing.T, transport string, service uint32, handler func(*v2GSSCall) ([]byte, error)) *Client {
	t.Helper()
	rpc := v2GSSPeer(t, transport, func(raw []byte) ([]byte, error) {
		call, err := v2GSSDecode(raw, service)
		if err != nil {
			return nil, err
		}
		if call.version != 2 || call.program != nfsProgram && call.program != nfsACLProgram {
			return nil, errors.New("incorrect NFSv2/NFSACLv2 RPC program/version")
		}
		return handler(call)
	})
	rpc.gss = &rpcGSS{context: v2GSSMechanism{}, handle: []byte("v2-context"), established: true, service: service, nfsVersion: 2}
	return &Client{version: "2", nfs: rpc, Auth: Auth{UID: 999}, mounted: make(map[string]bool), ReadSize: 4096, WriteSize: 4096,
		security: map[uint32]string{1: "krb5", 2: "krb5i", 3: "krb5p"}[service], principal: "alice@NFS.TEST"}
}

func TestV2GSSMountReadWriteACL(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, service := range []uint32{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/%d", transport, service), func(t *testing.T) {
				fh := bytes.Repeat([]byte{7}, 32)
				payload := bytes.Repeat([]byte{0, 255, 1, 2, 3}, 1800)
				stored := make([]byte, 0, len(payload))
				var calls atomic.Uint32
				c := v2GSSClient(t, transport, service, func(call *v2GSSCall) ([]byte, error) {
					if call.sequence != calls.Add(1) || !bytes.Equal(call.args.take(32), fh) {
						return nil, errors.New("sequence or fixed NFSv2 handle mismatch")
					}
					var result encoder
					result.u32(0)
					if call.program == nfsACLProgram {
						if call.proc != 1 || call.args.u32() != 15 {
							return nil, errors.New("incorrect NFSACLv2 GETACL")
						}
						attrReply2(&result, uint32(len(stored)))
						for _, n := range []uint32{15, 4, 4, 1, 1000, 6, 4, 1001, 4, 16, 0, 4, 32, 0, 4, 0, 0} {
							result.u32(n)
						}
					} else {
						switch call.proc {
						case 1:
							attrReply2(&result, uint32(len(stored)))
						case 8:
							if call.args.u32() != 0 || call.args.u32() != uint32(len(stored)) || call.args.u32() != 0 {
								return nil, errors.New("incorrect NFSv2 WRITE offset")
							}
							stored = append(stored, call.args.opaque(4096)...)
							attrReply2(&result, uint32(len(stored)))
						case 6:
							offset, count := call.args.u32(), call.args.u32()
							if count != 4096 || call.args.u32() != 0 || offset >= uint32(len(stored)) {
								return nil, errors.New("incorrect NFSv2 READ arguments")
							}
							attrReply2(&result, uint32(len(stored)))
							result.opaque(stored[offset:min(offset+count, uint32(len(stored)))])
						default:
							return nil, fmt.Errorf("unexpected procedure %d", call.proc)
						}
					}
					if call.args.err != nil || len(call.args.b) != 0 {
						return nil, errors.New("incorrect argument length")
					}
					return v2GSSResponse(call, result, ""), nil
				})
				// MOUNTv1 has no advertised security list. AUTH_SYS discovers the
				// handle; Mount's GETATTR and every data/ACL call must retain GSS.
				c.mount = v2GSSPeer(t, transport, func(raw []byte) ([]byte, error) {
					d := &decoder{b: raw}
					xid := d.u32()
					for _, want := range []uint32{0, 2, mountProgram, 1, 1, 1} {
						if d.u32() != want {
							return nil, errors.New("incorrect MOUNTv1 authentication/header")
						}
					}
					d.opaque(400)
					if d.u32() != 0 || len(d.opaque(400)) != 0 || d.str() != "/data" || d.err != nil || len(d.b) != 0 {
						return nil, errors.New("incorrect MOUNTv1 arguments")
					}
					return append(udpReply(xid, 0), fh...), nil
				})
				ctx := context.Background()
				root, err := c.Mount(ctx, "/data")
				if err != nil || !bytes.Equal(root.Handle, fh) {
					t.Fatal("protected mount", err)
				}
				if n, err := c.WriteFrom(ctx, fh, bytes.NewReader(payload)); err != nil || n != int64(len(payload)) {
					t.Fatal("protected write", n, err)
				}
				var out bytes.Buffer
				if n, err := c.ReadTo(ctx, fh, &out); err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
					t.Fatal("protected read", n, err)
				}
				if acl, err := c.getLegacyACL(ctx, fh); err != nil || len(acl.Access) != 4 {
					t.Fatal("protected NFSACLv2", err)
				}
				if calls.Load() != 8 || c.Identity() != "alice@NFS.TEST ("+c.Security()+")" {
					t.Fatal("unexpected call count or identity")
				}
			})
		}
	}
}

func TestV2GSSRejectsUnverifiedRead(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, service := range []uint32{1, 2, 3} {
			faults := []string{"sys-reply", "replayed-verifier", "tampered-verifier", "denied"}
			if service > 1 {
				faults = append(faults, "tampered-body", "wrong-body-sequence", "trailing-envelope", "truncated-envelope")
			}
			for _, fault := range faults {
				t.Run(fmt.Sprintf("%s/%d/%s", transport, service, fault), func(t *testing.T) {
					var calls atomic.Int32
					c := v2GSSClient(t, transport, service, func(call *v2GSSCall) ([]byte, error) {
						calls.Add(1)
						if fault == "denied" {
							var reply encoder
							for _, n := range []uint32{call.xid, 1, 1, 1, 14} {
								reply.u32(n)
							}
							return reply, nil
						}
						var result encoder
						result.u32(0)
						attrReply2(&result, 6)
						result.opaque([]byte("secret"))
						return v2GSSResponse(call, result, fault), nil
					})
					var out bytes.Buffer
					if n, err := c.ReadTo(context.Background(), make([]byte, 32), &out); err == nil || n != 0 || out.Len() != 0 {
						t.Fatalf("unverified data exposed: bytes=%d err=%v", n, err)
					}
					if _, err := c.GetAttr(context.Background(), make([]byte, 32)); err == nil || calls.Load() != 1 {
						t.Fatal("failed authentication retried/downgraded or session reused")
					}
				})
			}
		}
	}
}

func TestV2GSSMutationsNeverReplay(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, service := range []uint32{1, 2, 3} {
			for _, fault := range []string{"lost", "tampered-verifier"} {
				for _, proc := range []uint32{2, 8, 9, 10, 11, 12, 13, 14, 15} {
					t.Run(fmt.Sprintf("%s/%d/%s/%d", transport, service, fault, proc), func(t *testing.T) {
						var calls atomic.Int32
						c := v2GSSClient(t, transport, service, func(call *v2GSSCall) ([]byte, error) {
							calls.Add(1)
							if fault == "lost" {
								return nil, nil
							}
							return v2GSSResponse(call, []byte{0, 0, 0, 0}, fault), nil
						})
						c.nfs.timeout = 35 * time.Millisecond
						_, err := c.call(context.Background(), proc, nil)
						if err == nil || calls.Load() != 1 || !c.nfs.closed {
							t.Fatalf("mutation replay/session reuse: count=%d err=%v", calls.Load(), err)
						}
						if transport == "udp" && !strings.Contains(err.Error(), "outcome unknown") {
							t.Fatal("missing ambiguous mutation diagnostic", err)
						}
					})
				}
			}
		}
	}
}

func TestV2GSSUDPReadRetriesRefreshSequence(t *testing.T) {
	for _, service := range []uint32{1, 2, 3} {
		for _, proc := range []uint32{0, 1, 4, 5, 6, 16, 17} {
			t.Run(fmt.Sprintf("%d/%d", service, proc), func(t *testing.T) {
				var calls atomic.Int32
				var firstXID uint32
				c := v2GSSClient(t, "udp", service, func(call *v2GSSCall) ([]byte, error) {
					n := calls.Add(1)
					if call.sequence != uint32(n) || call.proc != proc {
						return nil, errors.New("reused GSS sequence or wrong procedure")
					}
					if n == 1 {
						firstXID = call.xid
						return nil, nil
					}
					if call.xid == firstXID {
						return nil, errors.New("reused retry XID")
					}
					return v2GSSResponse(call, []byte{0, 0, 0, 42}, ""), nil
				})
				d, err := c.nfs.call(context.Background(), nfsProgram, 2, proc, &c.Auth, nil)
				if err != nil || d.u32() != 42 || calls.Load() != 2 || c.nfs.closed {
					t.Fatalf("authenticated read retry: count=%d err=%v", calls.Load(), err)
				}
			})
		}
	}
}

func TestV2GSSACLMutationNeverReplays(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, service := range []uint32{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/%d", transport, service), func(t *testing.T) {
				var calls atomic.Int32
				c := v2GSSClient(t, transport, service, func(call *v2GSSCall) ([]byte, error) {
					calls.Add(1)
					if call.program != nfsACLProgram || call.proc != 2 {
						return nil, errors.New("incorrect NFSACLv2 SETACL program/procedure")
					}
					return nil, nil
				})
				c.nfs.timeout = 35 * time.Millisecond
				_, err := c.nfs.call(context.Background(), nfsACLProgram, 2, 2, &c.Auth, nil)
				if err == nil || calls.Load() != 1 || !c.nfs.closed {
					t.Fatalf("ACL mutation replay/session reuse: count=%d err=%v", calls.Load(), err)
				}
			})
		}
	}
}
