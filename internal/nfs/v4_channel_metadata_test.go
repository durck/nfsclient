package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestSessionChannelACLUsesFullCompoundBudget(t *testing.T) {
	for _, size := range []int{328, 329} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			who := strings.Repeat("a", size)
			acl := &NFS4ACL{Attribute: "acl", Entries: []NFS4ACE{{Type: 0, Mask: 1, Who: who}}}
			// Literal XDR: ACL count, type, flags, mask and opaque WHO.
			wire := channelWords(1, 0, 0, 1, uint32(size))
			wire = append(wire, []byte(who)...)
			for len(wire)%4 != 0 {
				wire = append(wire, 0)
			}
			setters := 0
			v, _ := channelWirePeer(t, sessionChannelLimits{512, 512, 128, 4}, func(request []byte) []byte {
				if len(request) > 512 {
					t.Error("metadata exceeded full RPC request limit")
				}
				code := binary.BigEndian.Uint32(request[132:]) // four-byte file handle
				switch code {
				case 9:
					values := channelWords(1, 0x3003, 1)
					values = append(values, wire...)
					values = append(values, channelWords(15)...)
					body := channelWords(9, 0, 1, 0x3003, uint32(len(values)))
					return channelReply(request, append(body, values...))
				case 34:
					setters++
					if len(request) != 512 || !bytes.Equal(request[164:], wire) || binary.BigEndian.Uint32(request[116:]) != 1 {
						t.Error("ACL mutation wire or cache flag differs")
					}
					return channelReply(request, channelWords(34, 0, 1, 1<<12))
				default:
					t.Errorf("unexpected metadata op %d", code)
					return nil
				}
			})
			v.c.v4 = v
			v.c.version = "4.1"
			if err := v.setChannel(v.channel); err != nil {
				t.Fatal(err)
			}
			err := v.c.SetNFS4ACL(context.Background(), []byte("file"), acl)
			if size == 328 && (err != nil || setters != 1) {
				t.Fatalf("legal exact-boundary ACL refused: %v setters=%d", err, setters)
			}
			if size == 329 && (err == nil || setters != 0 || v.stateLost.Load()) {
				t.Fatalf("oversized ACL not refused locally: %v setters=%d", err, setters)
			}
		})
	}
}

func TestSessionChannelSmallXattrReplies(t *testing.T) {
	for _, operation := range []string{"get", "list"} {
		t.Run(operation, func(t *testing.T) {
			listed := false
			v, _ := channelWirePeer(t, sessionChannelLimits{512, 512, 128, 4}, func(request []byte) []byte {
				code := binary.BigEndian.Uint32(request[132:])
				switch code {
				case 72:
					return channelReply(request, append(channelWords(72, 0, 412), bytes.Repeat([]byte{7}, 412)...))
				case 74:
					if got := binary.BigEndian.Uint32(request[144:]); got != 416 {
						t.Errorf("LISTXATTRS count=%d want416", got)
					}
					listed = true
					return channelReply(request, append(channelWords(74, 0, 0, 1, 1, 4), append([]byte("name"), channelWords(1)...)...))
				case 9:
					n := binary.BigEndian.Uint32(request[136:])
					var bitmap, values []byte
					if n == 1 && binary.BigEndian.Uint32(request[140:]) == 1 {
						bitmap, values = channelWords(1, 1), channelWords(3, 0, 0, 1<<18)
					} else if n == 3 && binary.BigEndian.Uint32(request[148:]) == 1<<18 {
						bitmap, values = channelWords(3, 0, 0, 1<<18), channelWords(1)
					} else {
						bitmap, values = channelWords(1, 10), channelWords(1, 0, 5)
					}
					body := append(channelWords(9, 0), bitmap...)
					body = append(body, channelWords(uint32(len(values)))...)
					return channelReply(request, append(body, values...))
				default:
					t.Errorf("unexpected xattr operation %d", code)
					return nil
				}
			})
			v.minor = 2
			v.c.v4 = v
			v.c.version = "4.2"
			if err := v.setChannel(v.channel); err != nil {
				t.Fatal(err)
			}
			if operation == "get" {
				got, err := v.c.getXattr42(context.Background(), []byte("file"), "name")
				if err != nil || len(got) != 412 {
					t.Fatalf("exact reply boundary refused: %d %v", len(got), err)
				}
			} else {
				names, err := v.c.ListXattrs(context.Background(), []byte("file"))
				if err != nil || !listed || fmt.Sprint(names) != "[name]" {
					t.Fatalf("small channel list refused: %v %v", names, err)
				}
			}
		})
	}
}
