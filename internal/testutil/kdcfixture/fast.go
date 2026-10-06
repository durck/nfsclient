package kdcfixture

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type FASTObservation struct {
	Armored, PKINIT, PlainTimestamp, Removed atomic.Int32
}

// FASTConfig forwards to the independent native MIT KDC. The negative profile
// removes FAST from replies, without creating any successful credentials.
func FASTConfig(t *testing.T, source, network string, strip bool) (string, *FASTObservation) {
	var pa int32
	if strip {
		pa = patype.PA_FX_FAST
	}
	return nativeASConfig(t, source, network, pa)
}

func PKINITConfig(t *testing.T, source, network string, strip bool) (string, *FASTObservation) {
	var pa int32
	if strip {
		pa = 16
	}
	return nativeASConfig(t, source, network, pa)
}

func nativeASConfig(t *testing.T, source, network string, strip int32) (string, *FASTObservation) {
	t.Helper()
	o := new(FASTObservation)
	s := Start(t, func(transport string, b []byte) []byte {
		var req messages.ASReq
		if req.Unmarshal(b) == nil {
			if req.PAData.Contains(16) {
				o.PKINIT.Add(1)
			}
			if req.PAData.Contains(patype.PA_FX_FAST) {
				o.Armored.Add(1)
			}
			if req.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
				o.PlainTimestamp.Add(1)
			}
		}
		c, err := net.DialTimeout(transport, "127.0.0.1:88", time.Second)
		if err != nil {
			t.Error(err)
			return nil
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		var reply []byte
		if transport == "tcp" {
			packet := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
			packet = append(packet, b...)
			if _, err = c.Write(packet); err != nil {
				t.Error(err)
				return nil
			}
			var prefix [4]byte
			if _, err = io.ReadFull(c, prefix[:]); err != nil {
				t.Error(err)
				return nil
			}
			n := binary.BigEndian.Uint32(prefix[:])
			if n == 0 || n > 4<<20 {
				t.Error("invalid native KDC record")
				return nil
			}
			reply = make([]byte, n)
			if _, err = io.ReadFull(c, reply); err != nil {
				t.Error(err)
				return nil
			}
		} else {
			if _, err = c.Write(b); err != nil {
				t.Error(err)
				return nil
			}
			reply = make([]byte, 65536)
			n, err := c.Read(reply)
			if err != nil {
				t.Error(err)
				return nil
			}
			reply = reply[:n]
		}
		if strip == 0 {
			return reply
		}
		filter := func(p types.PADataSequence) types.PADataSequence {
			var result types.PADataSequence
			for _, item := range p {
				if item.PADataType == strip || strip == 16 && item.PADataType == 17 {
					o.Removed.Add(1)
				} else {
					result = append(result, item)
				}
			}
			return result
		}
		var ke messages.KRBError
		if ke.Unmarshal(reply) == nil {
			var p types.PADataSequence
			if _, err := asn1.Unmarshal(ke.EData, &p); err == nil {
				ke.EData, err = asn1.Marshal(filter(p))
				if err != nil {
					t.Error(err)
					return nil
				}
			}
			reply, err = ke.Marshal()
		} else {
			var rep messages.ASRep
			if rep.Unmarshal(reply) == nil {
				rep.PAData = filter(rep.PAData)
				reply, err = rep.Marshal()
			}
		}
		if err != nil {
			t.Error(err)
			return nil
		}
		return reply
	})
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(b), "127.0.0.1:88", s.Address)
	if network == "udp" {
		text = strings.Replace(text, "udp_preference_limit = 1", "udp_preference_limit = 32700", 1)
	}
	path := filepath.Join(t.TempDir(), "fast.conf")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path, o
}
