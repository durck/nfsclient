package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
)

// All peers below accept only exact LOOKUP/GETACL requests. A payload READ,
// WRITE, CREATE, SETACL, RENAME, REMOVE or authentication downgrade is a failure.
// These are synthetic RPC tests, not a kernel/NFSACL interoperability claim.
type replacementRPCObject struct {
	name   string
	handle []byte
	acl    encoder
}

func replacementRPCParent() []byte { return []byte{0xf0, 0, 1, 0xfe, 4} }

func replacementRPCSource() replacementRPCObject {
	policy := aclSetPolicy(1)
	body := append(encoder(nil), aclRPCBody()[:92]...)
	binary.BigEndian.PutUint32(body[12:], policy.Attr.Mode)
	body.u32(15)
	aclSetLists(&body, policy)
	return replacementRPCObject{"original.bin", []byte{0, 1, 2, 3, 0xfe}, body}
}

func replacementRPCStage() replacementRPCObject {
	policy := &NFS3ACL{Access: []NFS3ACLEntry{
		{Tag: ACLUserObj, ID: 20001, Perm: 6}, {Tag: ACLUser, ID: 20002},
		{Tag: ACLGroupObj, ID: 20003}, {Tag: ACLGroup, ID: 20006},
		{Tag: ACLMask}, {Tag: ACLOther},
	}}
	body := append(encoder(nil), aclRPCBody()[:92]...)
	binary.BigEndian.PutUint32(body[12:], 0600)
	binary.BigEndian.PutUint64(body[28:], 0)
	binary.BigEndian.PutUint64(body[60:], 42)
	body.u32(15)
	aclSetLists(&body, policy)
	return replacementRPCObject{".synthetic-private-stage", []byte{0x41, 0x42, 0x43}, body}
}

func replacementRPCLookup(o replacementRPCObject) encoder {
	var body encoder
	body.u32(0)
	body.opaque(o.handle)
	body.u32(1)
	body = append(body, o.acl[8:92]...)
	body.u32(0) // Optional parent attributes are absent.
	return body
}

func replacementRPCStep(o replacementRPCObject, step int) (program, procedure uint32, args, body encoder) {
	if step == 1 {
		args.opaque(o.handle)
		args.u32(15)
		return 100227, 1, args, o.acl
	}
	args.opaque(replacementRPCParent())
	args.str(o.name)
	return 100003, 3, args, replacementRPCLookup(o)
}

func replacementRPCPeer(t *testing.T, service uint32, observations []replacementRPCObject) *Client {
	t.Helper()
	return aclRPCClient(t, service, len(observations), func(index int, raw []byte) ([]byte, error) {
		program, procedure, args, body := replacementRPCStep(observations[index], index%3)
		sequence := uint32(51 + index)
		if err := aclRPCRequest(raw, program, 3, procedure, service, sequence, args); err != nil {
			return nil, fmt.Errorf("read-only replacement step %d: %w", index, err)
		}
		return aclRPCReply(binary.BigEndian.Uint32(raw), service, sequence, body), nil
	})
}

func replacementRPCCapture(t *testing.T, c *Client) *NFS3ReplacementMetadata {
	t.Helper()
	snapshot, err := c.CaptureNFS3Replacement(context.Background(), replacementRPCParent(), "original.bin")
	if err != nil || snapshot == nil {
		t.Fatalf("initial source capture failed: %v", err)
	}
	return snapshot
}

func TestNFS3ReplacementRPCReadOnlyIdentityContext(t *testing.T) {
	for _, service := range []uint32{0, 1, 2, 3} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			source, stage := replacementRPCSource(), replacementRPCStage()
			c := replacementRPCPeer(t, service, []replacementRPCObject{source, source, source, source, source, source, stage, stage, stage})
			gss := c.nfs.gss
			parent := replacementRPCParent()
			original, err := c.CaptureNFS3Replacement(context.Background(), parent, source.name)
			if err != nil || original == nil {
				t.Fatalf("source capture: %v", err)
			}
			// A snapshot must own the original parent handle, rather than borrow
			// the caller's mutable slice and silently verify another directory.
			parent[0] ^= 0xff
			if err := c.VerifyNFS3ReplacementSource(context.Background(), original); err != nil {
				t.Fatalf("source verification: %v", err)
			}
			if err := c.CheckNFS3ReplacementStage(context.Background(), replacementRPCParent(), stage.name, stage.handle, original); err != nil {
				t.Fatalf("private distinct stage: %v", err)
			}
			if c.nfs.xid != 9 || c.nfs.gss != gss || (gss != nil && gss.seq != 59) || !reflect.DeepEqual(c.Auth, aclRPCAuth) {
				t.Fatal("replacement inspection changed credentials, context, sequence or RPC count")
			}
		})
	}
}

func TestNFS3ReplacementRPCCaptureRejectsRaces(t *testing.T) {
	for _, scenario := range []string{"last-handle", "last-fileid", "last-ctime-nanosecond", "acl-size", "acl-mtime-nanosecond"} {
		for _, service := range []uint32{0, 3} {
			t.Run(fmt.Sprintf("%s/%d", scenario, service), func(t *testing.T) {
				first, changed := replacementRPCSource(), replacementRPCSource()
				observed := []replacementRPCObject{first, first, changed}
				switch scenario {
				case "last-handle":
					changed.handle = []byte{9, 9, 9} // Same attrs, file ID and timestamps.
				case "last-fileid":
					binary.BigEndian.PutUint64(changed.acl[60:], 42)
				case "last-ctime-nanosecond":
					binary.BigEndian.PutUint32(changed.acl[88:], 1)
				case "acl-size":
					binary.BigEndian.PutUint64(changed.acl[28:], 18)
				case "acl-mtime-nanosecond":
					binary.BigEndian.PutUint32(changed.acl[80:], 1)
				}
				observed[2] = changed
				if scenario == "acl-size" || scenario == "acl-mtime-nanosecond" {
					observed = []replacementRPCObject{first, changed}
				}
				c := replacementRPCPeer(t, service, observed)
				got, err := c.CaptureNFS3Replacement(context.Background(), replacementRPCParent(), first.name)
				if !errors.Is(err, ErrNFS3ReplacementRefused) || got != nil || c.nfs.xid != uint32(len(observed)) {
					t.Fatalf("inconsistent source was accepted or caused another RPC: xid=%d err=%v", c.nfs.xid, err)
				}
			})
		}
	}
}

func TestNFS3ReplacementRPCVerifyRejectsUnchangedTimestampRaces(t *testing.T) {
	for _, scenario := range []string{"raw-masked-ACL", "pathname-handle"} {
		for _, service := range []uint32{0, 3} {
			t.Run(fmt.Sprintf("%s/%d", scenario, service), func(t *testing.T) {
				source, observed := replacementRPCSource(), replacementRPCSource()
				if scenario == "raw-masked-ACL" {
					// Named user: 7 -> 3 with mask 2: same effective rights, mode,
					// identity, size and timestamps; preserving raw policy matters.
					binary.BigEndian.PutUint32(observed.acl[124:], 3)
				} else {
					observed.handle = []byte{8, 7, 6}
				}
				c := replacementRPCPeer(t, service, []replacementRPCObject{source, source, source, observed, observed, observed})
				original := replacementRPCCapture(t, c)
				if err := c.VerifyNFS3ReplacementSource(context.Background(), original); !errors.Is(err, ErrNFS3ReplacementRefused) || c.nfs.xid != 6 {
					t.Fatalf("observable source policy/path race accepted: xid=%d err=%v", c.nfs.xid, err)
				}
			})
		}
	}
}

func TestNFS3ReplacementRPCStageMustBePrivateAndDistinct(t *testing.T) {
	for _, scenario := range []string{"same-handle", "same-fileid", "different-fsid", "path-swapped-before-lookup", "raw-user-grant", "raw-group-grant", "raw-owning-group-grant", "nonempty", "other-owner", "other-group"} {
		t.Run(scenario, func(t *testing.T) {
			source, stage := replacementRPCSource(), replacementRPCStage()
			createdHandle := append([]byte(nil), stage.handle...)
			switch scenario {
			case "same-handle":
				stage.handle, createdHandle = source.handle, source.handle
			case "same-fileid":
				binary.BigEndian.PutUint64(stage.acl[60:], 41)
			case "different-fsid":
				binary.BigEndian.PutUint64(stage.acl[52:], 10)
			case "path-swapped-before-lookup":
				stage.handle = []byte{0x90, 0x91}
			case "raw-user-grant":
				binary.BigEndian.PutUint32(stage.acl[124:], 7)
			case "raw-group-grant":
				binary.BigEndian.PutUint32(stage.acl[148:], 7)
			case "raw-owning-group-grant":
				binary.BigEndian.PutUint32(stage.acl[136:], 7)
			case "nonempty":
				binary.BigEndian.PutUint64(stage.acl[28:], 1)
			case "other-owner":
				binary.BigEndian.PutUint32(stage.acl[20:], 20007)
				binary.BigEndian.PutUint32(stage.acl[108:], 20007)
			case "other-group":
				binary.BigEndian.PutUint32(stage.acl[24:], 20007)
				binary.BigEndian.PutUint32(stage.acl[132:], 20007)
			}
			c := replacementRPCPeer(t, 2, []replacementRPCObject{source, source, source, stage, stage, stage})
			original := replacementRPCCapture(t, c)
			if err := c.CheckNFS3ReplacementStage(context.Background(), replacementRPCParent(), stage.name, createdHandle, original); !errors.Is(err, ErrNFS3ReplacementRefused) || c.nfs.xid != 6 {
				t.Fatalf("unsafe staging identity/raw policy accepted: xid=%d err=%v", c.nfs.xid, err)
			}
		})
	}
}

func TestNFS3ReplacementRPCSnapshotBinding(t *testing.T) {
	for _, scenario := range []string{"uid", "gid", "groups", "security", "principal", "client", "rpc", "connection"} {
		t.Run(scenario, func(t *testing.T) {
			source := replacementRPCSource()
			c := replacementRPCPeer(t, 1, []replacementRPCObject{source, source, source})
			c.security, c.principal = "krb5", "alice@SYNTHETIC.TEST"
			original := replacementRPCCapture(t, c)
			oldRPC := c.nfs
			switch scenario {
			case "uid":
				c.Auth.UID++
			case "gid":
				c.Auth.GID++
			case "groups":
				c.Auth.Groups[0]++ // Must not mutate snapshot's copy.
			case "security":
				c.security = "sys"
			case "principal":
				c.principal = "bob@SYNTHETIC.TEST"
			case "client":
				c = &Client{nfs: c.nfs, Auth: c.Auth, version: c.version, security: c.security, principal: c.principal}
			case "rpc":
				c.nfs = &rpcClient{conn: oldRPC.conn}
			case "connection":
				one, two := net.Pipe()
				defer one.Close()
				defer two.Close()
				c.nfs.conn = one
			}
			xid := c.nfs.xid
			if err := c.VerifyNFS3ReplacementSource(context.Background(), original); !errors.Is(err, ErrNFS3ReplacementRefused) || c.nfs.xid != xid || oldRPC.xid != 3 {
				t.Fatalf("foreign snapshot was not rejected before RPC: xid=%d err=%v", c.nfs.xid, err)
			}
			stage := replacementRPCStage()
			if err := c.CheckNFS3ReplacementStage(context.Background(), replacementRPCParent(), stage.name, stage.handle, original); !errors.Is(err, ErrNFS3ReplacementRefused) || c.nfs.xid != xid || oldRPC.xid != 3 {
				t.Fatalf("foreign stage snapshot was not rejected before RPC: xid=%d err=%v", c.nfs.xid, err)
			}
		})
	}
}

func TestNFS3ReplacementRPCStrictLookup(t *testing.T) {
	for _, scenario := range []string{"no-attributes", "empty-handle", "trailing-data", "invalid-boolean", "hardlink", "special-mode"} {
		t.Run(scenario, func(t *testing.T) {
			source := replacementRPCSource()
			if scenario == "hardlink" {
				binary.BigEndian.PutUint32(source.acl[16:], 2)
			}
			if scenario == "special-mode" {
				binary.BigEndian.PutUint32(source.acl[12:], 04620)
			}
			program, procedure, args, body := replacementRPCStep(source, 0)
			attrOffset := 4 + 4 + ((len(source.handle) + 3) &^ 3)
			switch scenario {
			case "empty-handle":
				source.handle = nil
				body = replacementRPCLookup(source)
			case "no-attributes":
				body = append(append(encoder(nil), body[:attrOffset]...), make([]byte, 8)...)
			case "trailing-data":
				body = append(body, 0, 0, 0, 0)
			case "invalid-boolean":
				binary.BigEndian.PutUint32(body[attrOffset:], 2)
			}
			c := aclRPCClient(t, 0, 1, func(_ int, raw []byte) ([]byte, error) {
				if err := aclRPCRequest(raw, program, 3, procedure, 0, 0, args); err != nil {
					return nil, err
				}
				return aclRPCReply(binary.BigEndian.Uint32(raw), 0, 0, body), nil
			})
			got, err := c.CaptureNFS3Replacement(context.Background(), replacementRPCParent(), source.name)
			if !errors.Is(err, ErrNFS3ReplacementRefused) || got != nil || c.nfs.xid != 1 {
				t.Fatalf("unsafe/incomplete LOOKUP accepted or GETATTR fallback sent: xid=%d err=%v", c.nfs.xid, err)
			}
		})
	}
}

func TestNFS3ReplacementRPCACLFailurePreservesCause(t *testing.T) {
	for _, status := range []Status{13, 10004} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			source := replacementRPCSource()
			c := aclRPCClient(t, 3, 2, func(index int, raw []byte) ([]byte, error) {
				program, procedure, args, body := replacementRPCStep(source, index)
				sequence := uint32(51 + index)
				if err := aclRPCRequest(raw, program, 3, procedure, 3, sequence, args); err != nil {
					return nil, err
				}
				if index == 1 {
					body = nil
					body.u32(uint32(status))
					body.u32(0)
				}
				return aclRPCReply(binary.BigEndian.Uint32(raw), 3, sequence, body), nil
			})
			got, err := c.CaptureNFS3Replacement(context.Background(), replacementRPCParent(), source.name)
			if got != nil || !errors.Is(err, ErrNFS3ReplacementRefused) || !errors.Is(err, status) || c.nfs.xid != 2 || (status == 10004 && !errors.Is(err, ErrNFSACLUnavailable)) {
				t.Fatalf("ACL failure was hidden or caused fallback: xid=%d err=%v", c.nfs.xid, err)
			}
		})
	}
}

func TestNFS3ReplacementRPCUDPReadLoss(t *testing.T) {
	for _, service := range []uint32{0, 1} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			source := replacementRPCSource()
			packets := make(chan []byte, 8)
			peerErrors := make(chan error, 8)
			var count atomic.Int32
			_, port := udpPeer(t, func(s *net.UDPConn, peer *net.UDPAddr, raw []byte) {
				index := int(count.Add(1)) - 1
				select {
				case packets <- raw:
				default:
				}
				step := index - 1
				if index == 0 {
					step = 0
				}
				if step > 2 {
					select {
					case peerErrors <- errors.New("unexpected extra datagram"):
					default:
					}
					return
				}
				program, procedure, args, body := replacementRPCStep(source, step)
				sequence := uint32(51 + index)
				if err := aclRPCRequest(raw, program, 3, procedure, service, sequence, args); err != nil {
					select {
					case peerErrors <- err:
					default:
					}
					return
				}
				if index == 0 {
					return
				} // Lose only the first read-only LOOKUP reply.
				if _, err := s.WriteToUDP(aclRPCReply(binary.BigEndian.Uint32(raw), service, sequence, body), peer); err != nil {
					select {
					case peerErrors <- err:
					default:
					}
				}
			})
			rpc := udpClient(t, port)
			if service != 0 {
				rpc.gss = &rpcGSS{context: testMIC{}, handle: []byte("acl-existing-context"), seq: 50, service: service, established: true}
			}
			c := &Client{nfs: rpc, version: "3", Auth: Auth{UID: aclRPCAuth.UID, GID: aclRPCAuth.GID, Groups: append([]uint32(nil), aclRPCAuth.Groups...)}}
			original := replacementRPCCapture(t, c)
			if original == nil || count.Load() != 4 {
				t.Fatalf("capture retry count=%d", count.Load())
			}
			select {
			case err := <-peerErrors:
				t.Fatal(err)
			default:
			}
			first, second := <-packets, <-packets
			if service == 0 && !bytes.Equal(first, second) {
				t.Fatal("AUTH_SYS read retry changed datagram")
			}
			if service != 0 && (binary.BigEndian.Uint32(first) == binary.BigEndian.Uint32(second) || rpc.gss.seq != 54) {
				t.Fatal("protected read retry reused XID/sequence or reset context")
			}
		})
	}
}
