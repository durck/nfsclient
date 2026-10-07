package nfs

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestV4ChmodAcknowledgement(t *testing.T) {
	for _, mode := range []string{"ok", "missing-ack", "extra-ack", "denied", "partial", "malformed-failure"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				calls++
				if code != 34 {
					return nil, 0, errors.New("unexpected chmod operation")
				}
				d.take(16)
				if !slices.Equal(readBitmap4(d), []uint32{33}) {
					return nil, 0, errors.New("chmod changed unrelated metadata")
				}
				sub := &decoder{b: d.opaque(4)}
				if sub.u32() != 0640 || sub.err != nil {
					return nil, 0, errors.New("wrong chmod mode")
				}
				var e encoder
				switch mode {
				case "ok":
					bitmap4(&e, 33)
				case "missing-ack":
					bitmap4(&e)
				case "extra-ack":
					bitmap4(&e, 12, 33)
				case "denied":
					bitmap4(&e)
					return e, 13, nil
				case "partial":
					bitmap4(&e, 33)
					return e, 13, nil
				case "malformed-failure":
					return []byte{0}, 13, nil
				}
				return e, 0, nil
			})
			err := v.c.Chmod(context.Background(), []byte("file"), 0640)
			if calls != 1 || (err == nil) != (mode == "ok") {
				t.Fatalf("chmod %s: calls=%d err=%v", mode, calls, err)
			}
			if mode == "denied" || mode == "partial" {
				if !errors.Is(err, Status(13)) || v.stateLost.Load() {
					t.Fatalf("valid SETATTR refusal poisoned session/lost status: %v", err)
				}
			}
			if mode == "partial" && !strings.Contains(err.Error(), "may have changed") {
				t.Fatalf("partial mutation not explained: %v", err)
			}
		})
	}
}
