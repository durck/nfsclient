package nfs

import (
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

func aclSetPolicy(typ uint32) *NFS3ACL {
	p := &NFS3ACL{
		// Source identity/content fields deliberately differ from the target.
		// This is a policy copy to another object with the same UID and GID.
		Attr: Attr{Type: typ, Mode: 0620, UID: 20001, GID: 20003, FSID: 777, FileID: 999, Size: 9999},
		Access: []NFS3ACLEntry{
			{Tag: 1, ID: 20001, Perm: 6}, {Tag: 2, ID: 20002, Perm: 7},
			{Tag: 4, ID: 20003, Perm: 0}, {Tag: 16, Perm: 2}, {Tag: 32, Perm: 0},
		},
	}
	if typ == 2 {
		p.Default = []NFS3ACLEntry{
			{Tag: 1, ID: 20001, Perm: 7}, {Tag: 2, ID: 20002, Perm: 7},
			{Tag: 4, ID: 20003, Perm: 0}, {Tag: 16, Perm: 5}, {Tag: 32, Perm: 0},
		}
	}
	return p
}

func aclSetLists(e *encoder, p *NFS3ACL) {
	for i, entries := range [][]NFS3ACLEntry{p.Access, p.Default} {
		e.u32(uint32(len(entries)))
		e.u32(uint32(len(entries)))
		for _, entry := range entries {
			tag := entry.Tag
			if i == 1 {
				tag |= 0x1000
			}
			e.u32(tag)
			e.u32(entry.ID)
			e.u32(entry.Perm)
		}
	}
}

func aclSetArgs(p *NFS3ACL) encoder {
	var e encoder
	e.opaque([]byte{0, 1, 2, 3, 0xfe})
	e.u32(5) // Both ACL lists; neither list is an implicit patch/omission.
	aclSetLists(&e, p)
	return e
}

func aclSetObservation(p *NFS3ACL) encoder {
	e := append(encoder(nil), aclRPCBody()[:92]...)
	binary.BigEndian.PutUint32(e[8:], p.Attr.Type)
	binary.BigEndian.PutUint32(e[12:], p.Attr.Mode)
	binary.BigEndian.PutUint32(e[20:], p.Attr.UID)
	binary.BigEndian.PutUint32(e[24:], p.Attr.GID)
	binary.BigEndian.PutUint32(e[84:], 101) // ACL change may update ctime.
	e.u32(15)
	aclSetLists(&e, p)
	return e
}

func aclSetBefore(typ uint32) encoder {
	e := aclRPCBody()
	binary.BigEndian.PutUint32(e[8:], typ)
	return e
}

func aclSetAck(p *NFS3ACL, attrs bool) encoder {
	if attrs {
		return append(encoder(nil), aclSetObservation(p)[:92]...)
	}
	return encoder{0, 0, 0, 0, 0, 0, 0, 0} // NFS3_OK, absent post_op_attr.
}

func TestNFS3ACLSetRPCCompletePolicyAndReadback(t *testing.T) {
	for _, service := range []uint32{0, 1, 2, 3} {
		for _, typ := range []uint32{1, 2} {
			for _, attrs := range []bool{false, true} {
				t.Run(fmt.Sprintf("service-%d/type-%d/attrs-%v", service, typ, attrs), func(t *testing.T) {
					policy := aclSetPolicy(typ)
					c := aclRPCClient(t, service, 3, func(index int, raw []byte) ([]byte, error) {
						procedure, args, body := uint32(1), aclRPCArgs(), aclSetBefore(typ)
						if index == 1 {
							procedure, args, body = 2, aclSetArgs(policy), aclSetAck(policy, attrs)
						} else if index == 2 {
							body = aclSetObservation(policy)
						}
						sequence := uint32(51 + index)
						if err := aclRPCRequest(raw, 100227, 3, procedure, service, sequence, args); err != nil {
							return nil, err
						}
						return aclRPCReply(binary.BigEndian.Uint32(raw), service, sequence, body), nil
					})
					original := c.nfs.gss
					if err := c.SetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe}, policy); err != nil {
						t.Fatal(err)
					}
					if c.nfs.xid != 3 || !reflect.DeepEqual(c.Auth, aclRPCAuth) || c.nfs.gss != original || (original != nil && original.seq != 53) {
						t.Fatal("SETACL skipped readback, changed identity/context or initiated additional RPCs")
					}
				})
			}
		}
	}
}

func TestNFS3ACLSetRPCFailureMayHaveApplied(t *testing.T) {
	for _, mode := range []string{"partial-nfs-error", "not-supported", "rpc-unavailable", "auth-denied", "truncated-ack", "invalid-attr-bool", "trailing-ack", "tampered-verifier", "tampered-body"} {
		t.Run(mode, func(t *testing.T) {
			policy := aclSetPolicy(2)
			var applied atomic.Bool
			c := aclRPCClient(t, 2, 2, func(index int, raw []byte) ([]byte, error) {
				procedure, args := uint32(1), aclRPCArgs()
				if index == 1 {
					procedure, args = 2, aclSetArgs(policy)
				}
				sequence := uint32(51 + index)
				if err := aclRPCRequest(raw, 100227, 3, procedure, 2, sequence, args); err != nil {
					return nil, err
				}
				xid := binary.BigEndian.Uint32(raw)
				if index == 0 {
					return aclRPCReply(xid, 2, sequence, aclSetBefore(2)), nil
				}
				// Model ACCESS succeeding before DEFAULT fails. Other error
				// cases check uncertainty without asserting server execution.
				if mode == "partial-nfs-error" {
					applied.Store(true)
				}
				body := aclSetAck(policy, false)
				switch mode {
				case "partial-nfs-error":
					binary.BigEndian.PutUint32(body, 5)
				case "not-supported":
					binary.BigEndian.PutUint32(body, 10004)
				case "rpc-unavailable":
					reply := aclRPCReply(xid, 0, 0, nil)
					binary.BigEndian.PutUint32(reply[20:], 3)
					return reply, nil
				case "auth-denied":
					var reply encoder
					for _, value := range []uint32{xid, 1, 1, 1, 14} {
						reply.u32(value)
					}
					return reply, nil
				case "truncated-ack":
					body = body[:4]
				case "invalid-attr-bool":
					binary.BigEndian.PutUint32(body[4:], 2)
				case "trailing-ack":
					body = append(body, 0, 0, 0, 0)
				}
				reply := aclRPCReply(xid, 2, sequence, body)
				if mode == "tampered-verifier" {
					reply[20] ^= 1
				} else if mode == "tampered-body" {
					reply[len(reply)-1] ^= 1
				}
				return reply, nil
			})
			err := c.SetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe}, policy)
			if !errors.Is(err, ErrNFSACLMutationUnverified) || (mode == "partial-nfs-error" && !applied.Load()) || c.nfs.xid != 2 || c.nfs.gss.seq != 52 {
				t.Fatalf("lost uncertain mutation or issued repair/replay: applied=%v xid=%d err=%v", applied.Load(), c.nfs.xid, err)
			}
			var cause error
			switch mode {
			case "partial-nfs-error":
				cause = Status(5)
			case "not-supported":
				cause = Status(10004)
			case "rpc-unavailable":
				cause = RPCStatus(3)
			case "auth-denied":
				cause = RPCDenied(1)
			}
			if cause != nil && !errors.Is(err, cause) {
				t.Fatalf("original mutation error lost: %v", err)
			}
		})
	}
}

func TestNFS3ACLSetRPCPreflightRefusesBeforeMutation(t *testing.T) {
	for _, mode := range []string{"owner", "group", "type", "special-mode", "getacl-denied"} {
		t.Run(mode, func(t *testing.T) {
			before := aclSetBefore(2)
			switch mode {
			case "owner":
				binary.BigEndian.PutUint32(before[20:], 20002)
				binary.BigEndian.PutUint32(before[108:], 20002)
			case "group":
				binary.BigEndian.PutUint32(before[24:], 20004)
				binary.BigEndian.PutUint32(before[120:], 20004)
			case "type":
				binary.BigEndian.PutUint32(before[8:], 1)
			case "special-mode":
				binary.BigEndian.PutUint32(before[12:], 04640)
			case "getacl-denied":
				before = encoder{0, 0, 0, 13, 0, 0, 0, 0}
			}
			c := aclRPCClient(t, 0, 1, func(_ int, raw []byte) ([]byte, error) {
				if err := aclRPCRequest(raw, 100227, 3, 1, 0, 0, aclRPCArgs()); err != nil {
					return nil, err
				}
				return aclRPCReply(binary.BigEndian.Uint32(raw), 0, 0, before), nil
			})
			err := c.SetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe}, aclSetPolicy(2))
			if err == nil || errors.Is(err, ErrNFSACLMutationUnverified) || c.nfs.xid != 1 {
				t.Fatalf("preflight refusal dispatched SETACL or falsely claimed an uncertain mutation: xid=%d err=%v", c.nfs.xid, err)
			}
			if mode == "getacl-denied" && !errors.Is(err, Status(13)) {
				t.Fatalf("preflight error lost: %v", err)
			}
		})
	}
}

func TestNFS3ACLSetRPCReadbackMismatchIsUnverified(t *testing.T) {
	for _, mode := range []string{"raw-access", "default", "mode", "owner", "group", "type", "fsid", "fileid", "size", "mtime", "readback-denied"} {
		t.Run(mode, func(t *testing.T) {
			policy := aclSetPolicy(2)
			observed := aclSetPolicy(2)
			switch mode {
			case "raw-access":
				observed.Access[1].Perm = 3 // Effective rights still equal 2.
			case "default":
				observed.Default = nil
			case "mode":
				observed.Attr.Mode, observed.Access[3].Perm = 0640, 4
			case "owner":
				observed.Attr.UID, observed.Access[0].ID, observed.Default[0].ID = 20002, 20002, 20002
			case "group":
				observed.Attr.GID, observed.Access[2].ID, observed.Default[2].ID = 20004, 20004, 20004
			case "type":
				observed.Attr.Type, observed.Default = 1, nil
			}
			readback := aclSetObservation(observed)
			switch mode {
			case "fsid":
				binary.BigEndian.PutUint64(readback[52:], 10)
			case "fileid":
				binary.BigEndian.PutUint64(readback[60:], 42)
			case "size":
				binary.BigEndian.PutUint64(readback[28:], 18)
			case "mtime":
				binary.BigEndian.PutUint32(readback[76:], 101)
			case "readback-denied":
				readback = encoder{0, 0, 0, 13, 0, 0, 0, 0}
			}
			c := aclRPCClient(t, 0, 3, func(index int, raw []byte) ([]byte, error) {
				procedure, args, body := uint32(1), aclRPCArgs(), aclSetBefore(2)
				if index == 1 {
					procedure, args, body = 2, aclSetArgs(policy), aclSetAck(policy, false)
				} else if index == 2 {
					body = readback
				}
				if err := aclRPCRequest(raw, 100227, 3, procedure, 0, 0, args); err != nil {
					return nil, err
				}
				return aclRPCReply(binary.BigEndian.Uint32(raw), 0, 0, body), nil
			})
			err := c.SetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe}, policy)
			if !errors.Is(err, ErrNFSACLMutationUnverified) || c.nfs.xid != 3 {
				t.Fatalf("SETACL success inferred without exact stable readback: %v", err)
			}
			if mode == "readback-denied" && !errors.Is(err, Status(13)) {
				t.Fatalf("readback error lost: %v", err)
			}
		})
	}
}

func TestNFS3ACLSetUDPReplyLossNeverReplays(t *testing.T) {
	for _, service := range []uint32{0, 1} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			policy := aclSetPolicy(1)
			var gets, sets atomic.Int32
			peerErrors := make(chan error, 8)
			_, port := udpPeer(t, func(s *net.UDPConn, addr *net.UDPAddr, raw []byte) {
				if len(raw) < 24 {
					return
				}
				procedure := binary.BigEndian.Uint32(raw[20:])
				args, sequence := aclRPCArgs(), uint32(51)
				if procedure == 2 {
					args, sequence = aclSetArgs(policy), 52
					sets.Add(1)
				} else {
					gets.Add(1)
				}
				if err := aclRPCRequest(raw, 100227, 3, procedure, service, sequence, args); err != nil {
					select {
					case peerErrors <- err:
					default:
					}
				}
				if procedure == 1 {
					s.WriteToUDP(aclRPCReply(binary.BigEndian.Uint32(raw), service, sequence, aclSetBefore(1)), addr)
				}
				// SETACL is applied but its reply is lost; no readback/retry is
				// a substitute for acknowledging that the outcome is uncertain.
			})
			rpc := udpClient(t, port)
			if service != 0 {
				rpc.gss = &rpcGSS{context: testMIC{}, handle: []byte("acl-existing-context"), seq: 50, service: service, established: true}
			}
			c := &Client{nfs: rpc, version: "3", Auth: aclRPCAuth}
			start := time.Now()
			err := c.SetNFS3ACL(context.Background(), []byte{0, 1, 2, 3, 0xfe}, policy)
			if !errors.Is(err, ErrNFSACLMutationUnverified) || !strings.Contains(err.Error(), "outcome unknown") || gets.Load() != 1 || sets.Load() != 1 || time.Since(start) > 2*time.Second {
				t.Fatalf("uncertain SETACL replayed or hidden: gets=%d sets=%d err=%v", gets.Load(), sets.Load(), err)
			}
			select {
			case err := <-peerErrors:
				t.Fatal(err)
			default:
			}
		})
	}
}
