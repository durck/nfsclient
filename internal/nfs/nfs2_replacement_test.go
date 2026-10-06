package nfs

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestNFS2ReplacementRejectsInvalidInputs(t *testing.T) {
	c := &Client{version: "2"}
	for _, size := range []int64{-1, 1 << 31} {
		if _, err := c.ReplaceNFS2(context.Background(), make([]byte, 32), "file", bytes.NewReader(nil), size, nil); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
	if _, err := c.ReplaceNFS2(context.Background(), []byte("short"), "file", bytes.NewReader(nil), 0, nil); err == nil {
		t.Fatal("short handle accepted")
	}
}
func TestNFS2ReplacementLifecycle(t *testing.T) {
	for _, fault := range []string{"", "short", "long", "source-change", "stage-size", "acl-change", "mkdir-collision", "hardlink", "special-mode", "dir-acl", "no-acl", "rename-malformed", "rename-lost"} {
		t.Run(fault, func(t *testing.T) {
			handles := func(id byte) []byte { return bytes.Repeat([]byte{id}, 32) }
			modes := map[byte]uint32{1: 0100640, 2: 0040700, 3: 0100600}
			sizes := map[byte]uint32{1: 3, 2: 0, 3: 0}
			ctime := uint32(1)
			attrs := func(id byte) encoder {
				var e encoder
				typ := uint32(1)
				links := uint32(1)
				if id == 2 {
					typ = 2
					links = 2
				}
				if fault == "hardlink" && id == 1 {
					links = 2
				}
				mode := modes[id]
				if fault == "special-mode" && id == 1 {
					mode |= 04000
				}
				for _, v := range []uint32{typ, mode, links, 20001, 20001, sizes[id], 4096, 0, 1, 7, uint32(id), 0, 0, 1, 0, ctime, 0} {
					e.u32(v)
				}
				return e
			}
			acl := func(id byte) encoder {
				var e encoder
				e.u32(0)
				e = append(e, attrs(id)...)
				e.u32(15)
				perm := modes[id] & 0777
				entries := []NFS3ACLEntry{{ACLUserObj, 20001, perm >> 6}, {ACLGroupObj, 20001, (perm >> 3) & 7}, {ACLMask, 0, (perm >> 3) & 7}, {ACLOther, 0, perm & 7}}
				if id == 1 || modes[id]&0777 == 0640 {
					entries = append(entries, NFS3ACLEntry{ACLUser, 20002, 4})
				}
				if fault == "dir-acl" && id == 2 {
					entries = append(entries, NFS3ACLEntry{ACLUser, 20002, 4})
				}
				aclSetLists(&e, &NFS3ACL{Access: entries})
				return e
			}
			var c *Client
			var data []byte
			var stageName string
			creates, renames, sets, removes := 0, 0, 0, 0
			c = scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				var e encoder
				e.u32(0)
				id := d.take(32)[0]
				if prog == nfsACLProgram {
					if proc == 1 {
						if d.u32() != 15 || len(d.b) != 0 {
							return nil, fmt.Errorf("bad GETACL2 args")
						}
						if fault == "no-acl" {
							var fail encoder
							fail.u32(10004)
							return fail, nil
						}
						return acl(id), nil
					}
					if proc != 2 || id != 3 || d.u32() != 5 {
						return nil, fmt.Errorf("unexpected ACL mutation")
					}
					policy, err := decodeNFS2ACL(&decoder{b: acl(1)})
					if err != nil {
						return nil, err
					}
					var want encoder
					aclSetLists(&want, policy)
					if !bytes.Equal(d.b, want) {
						return nil, fmt.Errorf("wrong raw ACL restoration")
					}
					sets++
					modes[3] = 0100640
					if fault == "acl-change" {
						modes[3] = 0100600
					}
					return append(e, attrs(3)...), nil
				}
				switch proc {
				case 4:
					name := d.str()
					var obj byte
					switch {
					case id == 0 && name == "target":
						obj = 1
					case id == 0 && name == stageName:
						obj = 2
					case id == 2 && name == "payload":
						obj = 3
					default:
						return nil, fmt.Errorf("unexpected lookup %d/%s", id, name)
					}
					return append(append(e, handles(obj)...), attrs(obj)...), nil
				case 14:
					stageName = d.str()
					if id != 0 || !strings.HasPrefix(stageName, ".nfs-replace-") || d.u32() != 0700 {
						return nil, fmt.Errorf("bad private mkdir")
					}
					if fault == "mkdir-collision" {
						var fail encoder
						fail.u32(17)
						return fail, nil
					}
					return append(append(e, handles(2)...), attrs(2)...), nil
				case 9:
					if id != 2 || d.str() != "payload" || d.u32() != 0600 {
						return nil, fmt.Errorf("CREATE outside private directory")
					}
					creates++
					return append(append(e, handles(3)...), attrs(3)...), nil
				case 8:
					if id != 3 || d.u32() != 0 || d.u32() != uint32(len(data)) || d.u32() != 0 {
						return nil, fmt.Errorf("WRITE outside payload")
					}
					data = append(data, d.opaque(8192)...)
					sizes[3] = uint32(len(data))
					if fault == "stage-size" {
						sizes[3]++
					}
					if fault == "source-change" {
						sizes[1]++
					}
					return append(e, attrs(3)...), nil
				case 11:
					if id != 2 || d.str() != "payload" || !bytes.Equal(d.take(32), handles(0)) || d.str() != "target" || len(d.b) != 0 {
						return nil, fmt.Errorf("wrong publication")
					}
					renames++
					if fault == "rename-malformed" {
						return append(e, 0), nil
					}
					if fault == "rename-lost" {
						c.nfs.conn.Close()
					}
					return e, nil
				case 15:
					removes++
					if id != 0 || d.str() != stageName {
						return nil, fmt.Errorf("wrong cleanup")
					}
					return e, nil
				default:
					return nil, fmt.Errorf("unexpected procedure %d", proc)
				}
			}, true)
			c.version = "2"
			payload := []byte("replacement")
			size := int64(len(payload))
			if fault == "short" {
				size++
			}
			if fault == "long" {
				size--
			}
			n, err := c.ReplaceNFS2(context.Background(), handles(0), "target", bytes.NewReader(payload), size, nil)
			if fault == "" {
				if err != nil || n != size || creates != 1 || renames != 1 || sets != 1 || removes != 1 || !bytes.Equal(payload, data) {
					t.Fatal(n, creates, renames, sets, removes, err)
				}
			} else {
				if err == nil || removes != 0 {
					t.Fatal("fault accepted or stage removed", err, removes)
				}
				if strings.HasPrefix(fault, "rename-") {
					if renames != 1 || !strings.Contains(err.Error(), "outcome unknown") {
						t.Fatal("publication state misreported", err)
					}
				} else if renames != 0 {
					t.Fatal("published after verification failure")
				}
			}
		})
	}
}
func TestNFS2ACLDecodeStrict(t *testing.T) {
	var e encoder
	e.u32(0)
	for _, v := range []uint32{1, 0100640, 1, 20001, 20001, 9, 4096, 0, 1, 7, 11, 0, 0, 1, 123, 2, 456} {
		e.u32(v)
	}
	e.u32(15)
	aclSetLists(&e, &NFS3ACL{Access: []NFS3ACLEntry{{ACLUserObj, 20001, 6}, {ACLUser, 20002, 4}, {ACLGroupObj, 20001, 4}, {ACLMask, 0, 4}, {ACLOther, 0, 0}}})
	got, err := decodeNFS2ACL(&decoder{b: e})
	if err != nil || got.Attr.Mode != 0640 || !got.Attr.HasNLink || got.Attr.NLink != 1 {
		t.Fatal(got, err)
	}
	for i := 0; i < len(e); i++ {
		if _, err := decodeNFS2ACL(&decoder{b: e[:i]}); err == nil {
			t.Fatal("truncated ACL accepted", i)
		}
	}
	if _, err := decodeNFS2ACL(&decoder{b: append(bytes.Clone(e), 0)}); err == nil {
		t.Fatal("trailing data accepted")
	}
}
