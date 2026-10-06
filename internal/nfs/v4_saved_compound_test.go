package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
)

func TestSavedCompoundCaptureAndExactReplay(t *testing.T) {
	var saved SavedCompound
	v, _ := channelWirePeer(t, sessionChannelLimits{512, 512, 112, 3}, func(request []byte) []byte {
		if saved.Validate() != nil || !bytes.Equal(saved.Inner, request[72:]) {
			t.Error("request sent before exact durable capture")
		}
		return channelReply(request, channelWords(38, 0, 0, 2, 0, 0))
	})
	v.beforeCached = func(s SavedCompound) error { saved = s; return nil }
	ops := []v4Op{fh4([]byte("file")), op4(38, make(encoder, 32), func(d *decoder) { d.take(16) })}
	if err := v.compound(context.Background(), ops...); err != nil {
		t.Fatal(err)
	}
	bound, _ := channelWirePeer(t, v.channel, func(request []byte) []byte {
		if !bytes.Equal(request[72:], saved.Inner) {
			t.Error("saved replay changed payload")
		}
		return channelReply(request, channelWords(38, 0, 0, 2, 0, 0))
	})
	if err := bound.replaySavedCompound(context.Background(), saved, ops...); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SavedCompound){
		func(s *SavedCompound) { s.Sequence++ },
		func(s *SavedCompound) { s.Minor++ },
		func(s *SavedCompound) { s.Session = make([]byte, 16) },
		func(s *SavedCompound) {
			s.Inner = bytes.Clone(s.Inner)
			s.Inner[44] = 0
			s.Inner[47] = 0
			s.Digest = sha256.Sum256(s.Inner)
		},
		func(s *SavedCompound) { s.Digest[0] ^= 1 },
	} {
		bad := saved
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("corrupt saved compound accepted")
		}
	}
}

func TestSavedCompoundRefusesAdaptiveRewrite(t *testing.T) {
	v, calls := channelWirePeer(t, sessionChannelLimits{512, 512, 112, 3}, func([]byte) []byte { t.Error("rewritten replay transmitted"); return nil })
	args := make(encoder, 28)
	args.opaque(bytes.Repeat([]byte{1}, 1024))
	ops := []v4Op{fh4([]byte("file")), op4(38, args, nil)}
	var inner encoder
	inner.str("")
	inner.u32(1)
	inner.u32(3)
	inner.u32(53)
	inner = append(inner, v.session...)
	inner.u32(1)
	inner.u32(0)
	inner.u32(0)
	inner.u32(1)
	for _, op := range ops {
		inner.u32(op.code)
		inner = append(inner, op.args...)
	}
	saved := saveCompound(v, Auth{}, inner, append([]v4Op{op4(53, nil, nil)}, ops...))
	if err := v.replaySavedCompound(context.Background(), saved, ops...); !channelNotSent(err) || calls.Load() != 0 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}
