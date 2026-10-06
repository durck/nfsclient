package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func editACLObservation(version string, policy *NFS3ACL) encoder {
	if version == "3" {
		return aclSetObservation(policy)
	}
	var e encoder
	typeBits := uint32(0100000)
	if policy.Attr.Type == 2 {
		typeBits = 0040000
	}
	for _, v := range []uint32{0, policy.Attr.Type, typeBits | policy.Attr.Mode, 1, policy.Attr.UID, policy.Attr.GID, 17, 4096, 0, 1, 9, 41, 100, 0, 100, 0, 101, 0, 15} {
		e.u32(v)
	}
	aclSetLists(&e, policy)
	return e
}

func TestLegacyACLEditPreservesSelectedSecurity(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		for _, service := range []uint32{0, 1, 2, 3} {
			for _, typ := range []uint32{1, 2} {
				t.Run(fmt.Sprintf("v%s/service%d/type%d", version, service, typ), func(t *testing.T) {
					policy := aclSetPolicy(typ)
					if policy.Default == nil {
						policy.Default = []NFS3ACLEntry{}
					}
					before := *policy
					before.Access = append([]NFS3ACLEntry(nil), policy.Access...)
					before.Access[1].Perm = 1
					body := editACLObservation(version, &before)
					var observed *NFS3ACL
					var err error
					if version == "2" {
						observed, err = decodeNFS2ACL(&decoder{b: body})
					} else {
						observed, err = decodeNFS3ACL(&decoder{b: body})
					}
					if err != nil {
						t.Fatal(err)
					}
					fh := bytes.Repeat([]byte{1}, 32)
					selected := Node{Handle: fh, Attr: observed.Attr}
					c := aclRPCClient(t, service, 3, func(index int, raw []byte) ([]byte, error) {
						var args encoder
						if version == "2" {
							args = append(args, fh...)
						} else {
							args.opaque(fh)
						}
						procedure := uint32(1)
						reply := body
						if index == 1 {
							procedure = 2
							args.u32(5)
							aclSetLists(&args, policy)
							reply = editACLObservation(version, policy)
							if version == "2" {
								reply = reply[:72]
							} else {
								reply = reply[:92]
							}
						} else {
							args.u32(15)
							if index == 2 {
								reply = editACLObservation(version, policy)
							}
						}
						ver := uint32(3)
						if version == "2" {
							ver = 2
						}
						if err := aclRPCRequest(raw, 100227, ver, procedure, service, uint32(51+index), args); err != nil {
							return nil, err
						}
						return aclRPCReply(binary.BigEndian.Uint32(raw), service, uint32(51+index), reply), nil
					})
					c.version = version
					original := c.nfs.gss
					if err := c.EditLegacyACL(context.Background(), selected, policy); err != nil {
						t.Fatal(err)
					}
					if c.nfs.xid != 3 || !reflect.DeepEqual(c.Auth, aclRPCAuth) || c.nfs.gss != original {
						t.Fatal("identity/context changed or extra calls")
					}
				})
			}
		}
	}
}

func TestLegacyACLEditRejectsBeforeMutation(t *testing.T) {
	for _, fault := range []string{"fileid", "fsid", "owner", "type", "size", "mtime", "incomplete"} {
		t.Run(fault, func(t *testing.T) {
			policy := aclSetPolicy(2)
			before, err := decodeNFS3ACL(&decoder{b: aclSetBefore(2)})
			if err != nil {
				t.Fatal(err)
			}
			selected := Node{Handle: []byte{0, 1, 2, 3, 0xfe}, Attr: before.Attr}
			switch fault {
			case "fileid":
				selected.Attr.FileID++
			case "fsid":
				selected.Attr.FSID++
			case "owner":
				selected.Attr.UID++
			case "type":
				selected.Attr.Type = 1
			case "size":
				selected.Attr.Size++
			case "mtime":
				selected.Attr.MTime = selected.Attr.MTime.Add(1)
			case "incomplete":
				selected.Attr.HasFileID = false
			}
			c := aclRPCClient(t, 0, 1, func(index int, raw []byte) ([]byte, error) {
				if err := aclRPCRequest(raw, 100227, 3, 1, 0, 0, aclRPCArgs()); err != nil {
					return nil, err
				}
				return aclRPCReply(binary.BigEndian.Uint32(raw), 0, 0, aclSetBefore(2)), nil
			})
			if err := c.EditLegacyACL(context.Background(), selected, policy); err == nil || errors.Is(err, ErrNFSACLMutationUnverified) {
				t.Fatalf("selection mismatch: %v", err)
			}
			if c.nfs.xid != 1 {
				t.Fatal("mutation attempted")
			}
		})
	}
	for _, typ := range []uint32{0, 5, 6} {
		if err := (&Client{version: "3"}).EditLegacyACL(context.Background(), Node{Attr: Attr{Type: typ}}, aclSetPolicy(2)); err == nil {
			t.Fatal("unsupported target")
		}
	}
	if err := (&Client{version: "3"}).EditLegacyACL(context.Background(), Node{Attr: Attr{Type: 1}}, aclSetPolicy(1)); err == nil {
		t.Fatal("omitted defaults accepted")
	}
}
