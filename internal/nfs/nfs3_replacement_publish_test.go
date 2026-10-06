package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNFS3ReplacementLifecycle(t *testing.T) {
	for _, failure := range []string{"", "short-source", "long-source", "source-changed", "stage-size", "policy-mismatch", "rename-reply"} {
		t.Run(failure, func(t *testing.T) {
			source, stage := replacementRPCSource(), replacementRPCStage()
			var payload []byte
			renames, creates, sets := 0, 0, 0
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				var e encoder
				if prog == nfsACLProgram {
					fh := d.opaque(64)
					if proc == 1 {
						if bytes.Equal(fh, source.handle) {
							return source.acl, nil
						}
						if bytes.Equal(fh, stage.handle) {
							return stage.acl, nil
						}
						return nil, fmt.Errorf("unknown ACL handle")
					}
					if proc != 2 || !bytes.Equal(fh, stage.handle) {
						return nil, fmt.Errorf("unexpected ACL mutation")
					}
					sets++
					if d.u32() != 5 {
						return nil, fmt.Errorf("not complete ACL replacement")
					}
					policy, err := decodeNFS3ACL(&decoder{b: source.acl})
					if err != nil {
						return nil, err
					}
					var want encoder
					aclSetLists(&want, policy)
					if !bytes.Equal(d.b, want) {
						return nil, fmt.Errorf("raw ACL not restored exactly")
					}
					binary.BigEndian.PutUint32(stage.acl[12:], policy.Attr.Mode)
					stage.acl = append(stage.acl[:96:96], want...)
					if failure == "policy-mismatch" {
						binary.BigEndian.PutUint32(stage.acl[len(stage.acl)-4:], 1)
					}
					e.u32(0)
					e.u32(1)
					e = append(e, stage.acl[8:92]...)
					return e, nil
				}
				switch proc {
				case 3:
					d.opaque(64)
					name := d.str()
					if name == source.name {
						return replacementRPCLookup(source), nil
					}
					if name == stage.name {
						return replacementRPCLookup(stage), nil
					}
					return nil, fmt.Errorf("unknown lookup %q", name)
				case 8:
					d.opaque(64)
					stage.name = d.str()
					if d.u32() != 1 || !strings.HasPrefix(stage.name, ".nfs-upload-") {
						return nil, fmt.Errorf("unguarded or nonprivate creation")
					}
					creates++
					return stageCreateAck(stage, false), nil
				case 7:
					if !bytes.Equal(d.opaque(64), stage.handle) || d.u64() != uint64(len(payload)) {
						return nil, fmt.Errorf("write outside stage")
					}
					count := d.u32()
					if d.u32() != 2 {
						return nil, fmt.Errorf("nonstable write")
					}
					data := d.opaque(32768)
					if count != uint32(len(data)) {
						return nil, fmt.Errorf("write size mismatch")
					}
					payload = append(payload, data...)
					size := uint64(len(payload))
					if failure == "stage-size" {
						size++
					}
					binary.BigEndian.PutUint64(stage.acl[28:], size)
					binary.BigEndian.PutUint32(stage.acl[76:], 200)
					binary.BigEndian.PutUint32(stage.acl[84:], 200)
					if failure == "source-changed" {
						binary.BigEndian.PutUint32(source.acl[84:], 201)
					}
					e.u32(0)
					e.u32(0)
					e.u32(0)
					e.u32(count)
					e.u32(2)
					e = append(e, make([]byte, 8)...)
					return e, nil
				case 14:
					d.opaque(64)
					from := d.str()
					d.opaque(64)
					to := d.str()
					if from != stage.name || to != source.name {
						return nil, fmt.Errorf("wrong publication names")
					}
					renames++
					if failure == "rename-reply" {
						return encoder{0}, nil
					}
					e.u32(0)
					for i := 0; i < 4; i++ {
						e.u32(0)
					}
					return e, nil
				default:
					return nil, fmt.Errorf("unexpected mutation/procedure %d", proc)
				}
			})
			input := []byte("replacement")
			size := int64(len(input))
			if failure == "short-source" {
				size++
			}
			if failure == "long-source" {
				size--
			}
			n, err := c.ReplaceNFS3(context.Background(), replacementRPCParent(), source.name, bytes.NewReader(input), size, nil)
			if failure == "" {
				if err != nil || n != int64(len(input)) || renames != 1 || sets != 1 || creates != 1 || !bytes.Equal(payload, input) {
					t.Fatalf("lifecycle n=%d create=%d set=%d rename=%d: %v", n, creates, sets, renames, err)
				}
			} else {
				if err == nil {
					t.Fatal("accepted fault")
				}
				if failure == "rename-reply" {
					if renames != 1 || !errors.Is(err, ErrNFS3PublishUncertain) {
						t.Fatalf("uncertain rename replayed/misreported: %d %v", renames, err)
					}
				} else if renames != 0 {
					t.Fatal("published after failed verification")
				}
			}
		})
	}
}
