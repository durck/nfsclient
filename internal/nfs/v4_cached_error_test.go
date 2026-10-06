package nfs

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestCachedErrorObserverRequiresCheckedSequence(t *testing.T) {
	for _, mode := range []string{"denied", "trailing", "sequence", "wrong-operation"} {
		t.Run(mode, func(t *testing.T) {
			v, _ := channelWirePeer(t, sessionChannelLimits{512, 512, 512, 4}, func(request []byte) []byte {
				b := channelReply(request, channelWords(4, 13))
				binary.BigEndian.PutUint32(b[24:], 13)
				switch mode {
				case "trailing":
					b = append(b, 0)
				case "sequence":
					binary.BigEndian.PutUint32(b[32:], 1)
					binary.BigEndian.PutUint32(b[40:], 13)
					b = b[:44]
				case "wrong-operation":
					binary.BigEndian.PutUint32(b[len(b)-8:], 18)
				}
				return b
			})
			calls := 0
			v.afterCachedError = func(s SavedCompound, body []byte) error {
				calls++
				if s.Validate() != nil || len(body) == 0 || v.sequence != s.Sequence+1 {
					t.Fatal("observer ran before checked sequence advancement")
				}
				return nil
			}
			if err := v.compound(context.Background(), fh4([]byte("file")), op4(4, make(encoder, 20), nil)); err == nil {
				t.Fatal("error response accepted as success")
			}
			if (calls == 1) != (mode == "denied") {
				t.Fatalf("observer calls %d", calls)
			}
		})
	}
}
