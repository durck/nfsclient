package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestCachedReplayPreservesExactSessionRequest(t *testing.T) {
	for _, mode := range []string{"success", "known-denial", "uncached", "malformed", "second-disconnect"} {
		t.Run(mode, func(t *testing.T) {
			left, right := net.Pipe()
			t.Cleanup(func() { left.Close(); right.Close() })
			original := make(chan []byte, 1)
			go func() {
				var header [4]byte
				if _, err := io.ReadFull(right, header[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint32(header[:]) & 0x7fffffff
				b := make([]byte, n)
				if _, err := io.ReadFull(right, b); err != nil {
					return
				}
				original <- b
				right.Close() // mutation may have executed; reply was lost
			}()
			v := &v4Client{c: &Client{nfs: &rpcClient{conn: left, timeout: time.Second}}, minor: 1, session: bytes.Repeat([]byte{7}, 16), sequence: 1, channel: sessionChannelLimits{512, 512, 112, 3}}
			admissions, finalizations := 0, 0
			var finalized bool
			v.recoverCached = func(ctx context.Context, ticket *v4ReplayRequest) (*rpcClient, func(bool), error) {
				admissions++
				first := <-original
				if ticket.Owner != v || ticket.Sequence != 1 || !bytes.Equal(ticket.Inner, first[72:]) {
					t.Error("admission changed original inner request")
				}
				candidate, _ := channelWirePeer(t, v.channel, func(request []byte) []byte {
					if !bytes.Equal(request[72:], first[72:]) {
						t.Error("retransmitted NFS request differs")
					}
					if mode == "second-disconnect" {
						return nil
					}
					status := uint32(0)
					if mode == "known-denial" {
						status = 13
					}
					if mode == "uncached" {
						status = 10068
					}
					last := channelWords(38, status)
					if status == 0 {
						last = append(last, channelWords(0, 2, 0, 0)...)
					}
					b := channelReply(request, last)
					binary.BigEndian.PutUint32(b[24:], status)
					if mode == "malformed" {
						b = append(b, 0, 0, 0, 0)
					}
					return b
				})
				return candidate.c.nfs, func(ok bool) { finalizations++; finalized = ok }, nil
			}
			err := v.compound(context.Background(), fh4([]byte("file")), op4(38, make(encoder, 32), func(d *decoder) { d.take(16) }))
			known := mode == "success" || mode == "known-denial"
			if admissions != 1 || finalizations != 1 || finalized != known || v.stateLost.Load() == known {
				t.Fatalf("mode=%s err=%v admissions=%d finalizations=%d confirmed=%t lost=%t", mode, err, admissions, finalizations, finalized, v.stateLost.Load())
			}
			if mode == "success" && err != nil || mode == "known-denial" && !errors.Is(err, Status(13)) || !known && err == nil {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
		})
	}
}

func TestCachedReplayRejectsUnverifiedAndNonDataRequests(t *testing.T) {
	v := &v4Client{session: make([]byte, 16)}
	v.recoverCached = func(context.Context, *v4ReplayRequest) (*rpcClient, func(bool), error) {
		t.Fatal("unsafe replay admission")
		return nil, nil, nil
	}
	for _, code := range []uint32{18, 28, 29, 34} {
		_, _, _, err := v.replayCached(context.Background(), Auth{}, nil, nil, []v4Op{op4(53, nil, nil), fh4(nil), op4(code, nil, nil)}, &rpcTransportFailure{io.EOF})
		if err == nil {
			t.Fatal("lost cause")
		}
	}
	for _, err := range []error{errors.New("invalid authenticated body"), Status(10068), context.Canceled} {
		_, _, _, got := v.replayCached(context.Background(), Auth{}, nil, nil, []v4Op{op4(53, nil, nil), fh4(nil), op4(38, nil, nil)}, err)
		if !errors.Is(got, err) {
			t.Fatalf("got %v", got)
		}
	}
}
