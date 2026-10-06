package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestCachedObserversResolveOnlyValidatedReplies(t *testing.T) {
	for _, mode := range []string{"success", "trailing", "denial", "storage"} {
		t.Run(mode, func(t *testing.T) {
			var request SavedCompound
			var body []byte
			before, after := 0, 0
			v, _ := channelWirePeer(t, sessionChannelLimits{512, 512, 112, 3}, func(wire []byte) []byte {
				if binary.BigEndian.Uint32(wire[116:]) != 1 {
					t.Error("durable read observer did not force caching")
				}
				r := channelReply(wire, channelWords(25, 0, 1, 4, 0x64617461))
				if mode == "denial" {
					r = channelReply(wire, channelWords(25, 13))
					binary.BigEndian.PutUint32(r[24:], 13)
				}
				if mode == "trailing" {
					r = append(r, 0, 0, 0, 0)
				}
				body = bytes.Clone(r[24:])
				return r
			})
			v.requireCached = true
			v.beforeCached = func(s SavedCompound) error { request = s; before++; return nil }
			v.afterCached = func(s SavedCompound, reply []byte) error {
				after++
				if s.Digest != request.Digest || !bytes.Equal(s.Inner, request.Inner) || !bytes.Equal(reply, body) {
					t.Error("observer did not receive exact original request/reply")
				}
				if mode == "storage" {
					return errors.New("receipt sync failed")
				}
				return nil
			}
			e := make(encoder, 24)
			e.u32(4)
			err := v.compound(context.Background(), fh4([]byte("file")), op4(25, e, func(d *decoder) { d.boolean(); d.opaque(4) }))
			wantAfter := 0
			if mode == "success" || mode == "storage" {
				wantAfter = 1
			}
			if before != 1 || after != wantAfter || (err == nil) != (mode == "success") {
				t.Fatalf("mode=%s before=%d after=%d err=%v", mode, before, after, err)
			}
			if v.stateLost.Load() != (mode == "storage" || mode == "trailing") {
				t.Fatal("invalid reply or unsynced receipt did not quarantine slot")
			}
		})
	}
}
