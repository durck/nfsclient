package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var aclRPCAuth = Auth{UID: 20001, GID: 20003, Groups: []uint32{20004, 20005}}

// These tests isolate RPC framing with the existing synthetic GSS mechanism.
// They do not substitute for the opt-in kernel/KDC interoperability tests.
func aclRPCRequest(raw []byte, program, version, procedure, service, sequence uint32, args []byte) error {
	d := &decoder{b: raw}
	d.u32() // XID is checked by the caller when retry behavior matters.
	for _, want := range []uint32{0, 2, program, version, procedure} {
		if got := d.u32(); got != want {
			return fmt.Errorf("RPC header field %d, want %d", got, want)
		}
	}
	flavor := d.u32()
	cred := &decoder{b: d.opaque(400)}
	if service == 0 {
		if flavor != 1 {
			return fmt.Errorf("AUTH_SYS changed to flavor %d", flavor)
		}
		cred.u32() // AUTH_SYS timestamp.
		if cred.str() != "nfs-viewer" || cred.u32() != aclRPCAuth.UID || cred.u32() != aclRPCAuth.GID {
			return errors.New("AUTH_SYS identity changed")
		}
		if cred.u32() != uint32(len(aclRPCAuth.Groups)) {
			return errors.New("AUTH_SYS group count changed")
		}
		for _, group := range aclRPCAuth.Groups {
			if cred.u32() != group {
				return errors.New("AUTH_SYS supplementary groups changed")
			}
		}
		if d.u32() != 0 || len(d.opaque(400)) != 0 {
			return errors.New("unexpected AUTH_SYS verifier")
		}
	} else {
		if flavor != 6 {
			return fmt.Errorf("existing GSS context downgraded to flavor %d", flavor)
		}
		for _, want := range []uint32{1, 0, sequence, service} {
			if cred.u32() != want {
				return errors.New("GSS version, DATA procedure, sequence or service changed")
			}
		}
		if string(cred.opaque(380)) != "acl-existing-context" {
			return errors.New("existing GSS context handle changed")
		}
		signed := len(raw) - len(d.b)
		if d.u32() != 6 {
			return errors.New("missing GSS header verifier")
		}
		if err := (testMIC{}).VerifySignature(raw[:signed], d.opaque(400)); err != nil {
			return fmt.Errorf("header MIC does not cover selected RPC program: %w", err)
		}
		if service > 1 {
			body := d.opaque(maxRecord)
			if service == 2 {
				if err := (testMIC{}).VerifySignature(body, d.opaque(400)); err != nil {
					return err
				}
			}
			if d.err != nil || len(d.b) != 0 || len(body) < 4 || binary.BigEndian.Uint32(body) != sequence {
				return errors.New("invalid protected request body or sequence")
			}
			d = &decoder{b: body[4:]}
		}
	}
	if d.err != nil || cred.err != nil || len(cred.b) != 0 || !bytes.Equal(d.b, args) {
		return errors.New("malformed credentials, changed arguments or trailing request data")
	}
	return nil
}

func aclRPCArgs() encoder {
	var e encoder
	e.opaque([]byte{0, 1, 2, 3, 0xfe}) // An opaque, unaligned file handle.
	e.u32(15)                          // Full access/default entries and counts.
	return e
}

func aclRPCBody() encoder {
	var e encoder
	e.u32(0) // NFS3_OK.
	e.u32(1) // post_op_attr present.
	for _, value := range []uint32{1, 0640, 1, 20001, 20003} {
		e.u32(value)
	}
	e.u64(17) // Size.
	e.u64(4096)
	e.u32(0)
	e.u32(0)
	e.u64(9)  // FSID.
	e.u64(41) // File ID.
	for i := 0; i < 3; i++ {
		e.u32(100)
		e.u32(0)
	}
	for _, value := range []uint32{15, 4, 4, 1, 20001, 6, 4, 20003, 4, 16, 0, 4, 32, 0, 0, 0, 0} {
		e.u32(value)
	}
	return e
}

func aclRPCReply(xid, service, sequence uint32, body []byte) encoder {
	var reply encoder
	for _, value := range []uint32{xid, 1, 0} {
		reply.u32(value)
	}
	if service == 0 {
		reply.u32(0)
		reply.opaque(nil)
	} else {
		reply.u32(6)
		mic, _ := (testMIC{}).MakeSignature(binary.BigEndian.AppendUint32(nil, sequence))
		reply.opaque(mic)
	}
	reply.u32(0)
	switch service {
	case 2:
		reply = append(reply, integrityEnvelope(sequence, body)...)
	case 3:
		reply.opaque(append(binary.BigEndian.AppendUint32(nil, sequence), body...))
	default:
		reply = append(reply, body...)
	}
	return reply
}

func aclRPCClient(t *testing.T, service uint32, calls int, handler func(int, []byte) ([]byte, error)) *Client {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	rpc := &rpcClient{conn: client, timeout: 2 * time.Second}
	if service != 0 {
		rpc.gss = &rpcGSS{context: testPrivacy{}, handle: []byte("acl-existing-context"), seq: 50, service: service, established: true}
	}
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(5 * time.Second))
		for i := 0; i < calls; i++ {
			raw, err := readRecord(server)
			if err != nil {
				done <- err
				return
			}
			reply, err := handler(i, raw)
			if err == nil {
				_, err = server.Write(record(reply, true))
			}
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	t.Cleanup(func() {
		client.Close()
		server.Close()
		if err := <-done; err != nil {
			t.Errorf("ACL RPC peer: %v", err)
		}
	})
	return &Client{nfs: rpc, version: "3", Auth: Auth{UID: aclRPCAuth.UID, GID: aclRPCAuth.GID, Groups: append([]uint32(nil), aclRPCAuth.Groups...)}}
}

func TestNFS3ACLRPCPreservesIdentityAndContext(t *testing.T) {
	for _, service := range []uint32{0, 1, 2, 3} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			c := aclRPCClient(t, service, 3, func(index int, raw []byte) ([]byte, error) {
				program, procedure, args, body := uint32(100003), uint32(0), encoder(nil), encoder(nil)
				if index == 1 {
					program, procedure, args, body = 100227, 1, aclRPCArgs(), aclRPCBody()
				}
				seq := uint32(51 + index)
				if err := aclRPCRequest(raw, program, 3, procedure, service, seq, args); err != nil {
					return nil, err
				}
				return aclRPCReply(binary.BigEndian.Uint32(raw), service, seq, body), nil
			})
			original := c.nfs.gss
			if _, err := c.nfs.call(context.Background(), 100003, 3, 0, &c.Auth, nil); err != nil {
				t.Fatal(err)
			}
			result, err := c.GetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe})
			if err != nil || result == nil {
				t.Fatalf("GETACL: %v", err)
			}
			if result.Attr.FileID != 41 || result.Attr.Mode != 0640 || len(result.Access) != 4 || len(result.Default) != 0 {
				t.Fatalf("wrong observed ACL: %+v", result)
			}
			if _, err := c.nfs.call(context.Background(), 100003, 3, 0, &c.Auth, nil); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.Auth, aclRPCAuth) || c.nfs.gss != original || (original != nil && original.seq != 53) {
				t.Fatal("GETACL changed identity/context or forked its GSS sequence")
			}
		})
	}
}

func TestNFS3ACLRPCErrorsDoNotFallBack(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rpc, nfs    uint32
		denied      bool
		unavailable bool
	}{
		{name: "program", rpc: 1, unavailable: true},
		{name: "version", rpc: 2, unavailable: true},
		{name: "procedure", rpc: 3, unavailable: true},
		{name: "not-supported", nfs: 10004, unavailable: true},
		{name: "access-denied", nfs: 13},
		{name: "stale-handle", nfs: 70},
		{name: "auth-denied", denied: true},
	} {
		for _, service := range []uint32{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, service), func(t *testing.T) {
				c := aclRPCClient(t, service, 1, func(_ int, raw []byte) ([]byte, error) {
					if err := aclRPCRequest(raw, 100227, 3, 1, service, 51, aclRPCArgs()); err != nil {
						return nil, err
					}
					xid := binary.BigEndian.Uint32(raw)
					if tc.denied {
						var reply encoder
						for _, value := range []uint32{xid, 1, 1, 1, 14} {
							reply.u32(value)
						}
						return reply, nil
					}
					if tc.rpc != 0 {
						reply := aclRPCReply(xid, 0, 0, nil)
						binary.BigEndian.PutUint32(reply[20:], tc.rpc)
						if tc.rpc == 2 {
							reply.u32(2)
							reply.u32(2)
						}
						return reply, nil
					}
					var body encoder
					body.u32(tc.nfs)
					body.u32(0) // Failed GETACL may omit post-operation attributes.
					return aclRPCReply(xid, service, 51, body), nil
				})
				result, err := c.GetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe})
				if result != nil || err == nil || errors.Is(err, ErrNFSACLUnavailable) != tc.unavailable {
					t.Fatalf("wrong error/result: result=%v err=%v", result, err)
				}
				var want error = Status(tc.nfs)
				if tc.rpc != 0 {
					want = RPCStatus(tc.rpc)
				} else if tc.denied {
					want = RPCDenied(1)
				}
				if !errors.Is(err, want) || !reflect.DeepEqual(c.Auth, aclRPCAuth) {
					t.Fatalf("lost original error or changed identity: %v", err)
				}
				if c.nfs.xid != 1 || (service != 0 && (c.nfs.gss == nil || c.nfs.gss.seq != 51)) {
					t.Fatal("ACL error initiated another RPC or abandoned GSS authentication")
				}
			})
		}
	}
}

func TestNFS3ACLRPCRejectsUnverifiedResult(t *testing.T) {
	for _, mode := range []string{"verifier", "integrity-body"} {
		t.Run(mode, func(t *testing.T) {
			c := aclRPCClient(t, 2, 1, func(_ int, raw []byte) ([]byte, error) {
				if err := aclRPCRequest(raw, 100227, 3, 1, 2, 51, aclRPCArgs()); err != nil {
					return nil, err
				}
				reply := aclRPCReply(binary.BigEndian.Uint32(raw), 2, 51, aclRPCBody())
				if mode == "verifier" {
					reply[20] ^= 1
				} else {
					reply[len(reply)-1] ^= 1
				}
				return reply, nil
			})
			result, err := c.GetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe})
			if result != nil || err == nil || !c.nfs.closed {
				t.Fatalf("unverified ACL exposed or session reused: result=%v err=%v", result, err)
			}
			if _, err := c.GetNFS3ACL(context.Background(), []byte{1}); err == nil || c.nfs.xid != 1 {
				t.Fatal("unverified ACL triggered authentication fallback or replay")
			}
		})
	}
}

func TestNFS3ACLUDPReadRetry(t *testing.T) {
	for _, service := range []uint32{0, 1, 2, 3} { // AUTH_SYS and all GSS services.
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			var count atomic.Int32
			packets := make(chan []byte, 8)
			_, port := udpPeer(t, func(s *net.UDPConn, addr *net.UDPAddr, raw []byte) {
				select {
				case packets <- raw:
				default:
				}
				if count.Add(1) == 1 {
					return // Lose the first GETACL reply.
				}
				s.WriteToUDP(aclRPCReply(binary.BigEndian.Uint32(raw), service, 52, aclRPCBody()), addr)
			})
			rpc := udpClient(t, port)
			if service != 0 {
				rpc.gss = &rpcGSS{context: testPrivacy{}, handle: []byte("acl-existing-context"), seq: 50, service: service, established: true}
			}
			c := &Client{nfs: rpc, version: "3", Auth: aclRPCAuth}
			result, err := c.GetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe})
			if err != nil || result == nil || result.Attr.FileID != 41 || count.Load() != 2 {
				t.Fatalf("GETACL retry: packets=%d result=%v err=%v", count.Load(), result, err)
			}
			one, two := <-packets, <-packets
			for index, raw := range [][]byte{one, two} {
				if err := aclRPCRequest(raw, 100227, 3, 1, service, uint32(51+index), aclRPCArgs()); err != nil {
					t.Fatal(err)
				}
			}
			if service == 0 && !bytes.Equal(one, two) {
				t.Fatal("AUTH_SYS retry changed the datagram")
			}
			if service != 0 && (binary.BigEndian.Uint32(one) == binary.BigEndian.Uint32(two) || rpc.gss.seq != 52) {
				t.Fatal("GSS retry reused its XID or sequence")
			}
		})
	}
}

func TestNFS3ACLUDPRetryIsBoundedAndSelective(t *testing.T) {
	for _, service := range []uint32{0, 1, 2, 3} {
		for _, tc := range []struct {
			name                        string
			program, version, procedure uint32
			readOnly                    bool
		}{
			{"getacl", 100227, 3, 1, true},
			{"getacl-v2", 100227, 2, 1, true},
			{"setacl-v2", 100227, 2, 2, false},
			{"setacl", 100227, 3, 2, false},
			{"unknown-procedure", 100227, 3, 99, false},
			{"unknown-version", 100227, 4, 1, false},
			{"unknown-program", 100228, 3, 1, false},
		} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, service), func(t *testing.T) {
				var count atomic.Int32
				_, port := udpPeer(t, func(_ *net.UDPConn, _ *net.UDPAddr, _ []byte) { count.Add(1) })
				rpc := udpClient(t, port)
				if service != 0 {
					rpc.gss = &rpcGSS{context: testPrivacy{}, handle: []byte("acl-existing-context"), service: service, established: true}
				}
				start := time.Now()
				_, err := rpc.call(context.Background(), tc.program, tc.version, tc.procedure, &aclRPCAuth, nil)
				want := int32(1)
				if tc.readOnly {
					want = 3
				}
				if err == nil || count.Load() != want || time.Since(start) > 2*time.Second {
					t.Fatalf("unbounded/wrong retry: packets=%d want=%d err=%v", count.Load(), want, err)
				}
				if strings.Contains(err.Error(), "outcome unknown") == tc.readOnly {
					t.Fatalf("wrong read/mutation timeout classification: %v", err)
				}
			})
		}
	}
}

func TestNFS3ACLRejectsUnsupportedVersionAndHandleBeforeRPC(t *testing.T) {
	for _, version := range []string{"2", "4.0", "4.1", "4.2"} {
		c := &Client{version: version}
		if result, err := c.GetNFS3ACL(context.Background(), []byte{1}); result != nil || !errors.Is(err, ErrNFSACLUnavailable) {
			t.Fatalf("version %s: result=%v err=%v", version, result, err)
		}
	}
	for _, handle := range [][]byte{nil, make([]byte, 65)} {
		c := &Client{version: "3"}
		if result, err := c.GetNFS3ACL(context.Background(), handle); result != nil || err == nil {
			t.Fatalf("invalid handle: result=%v err=%v", result, err)
		}
	}
}
