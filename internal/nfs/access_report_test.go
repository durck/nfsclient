package nfs

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestAccessReportPreservesSupported(t *testing.T) {
	for _, tc := range []struct {
		name               string
		supported, allowed uint32
		bad                bool
	}{
		{"partial", 33, 32, false}, {"denied", 63, 0, false},
		{"unavailable-checks", 0, 0, false}, {"unrequested", 64, 0, true},
		{"outside-supported", 1, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := peer4(t, 0, func(op uint32, d *decoder) (encoder, Status, error) {
				if op != 3 || d.u32() != 63 {
					return nil, 0, fmt.Errorf("unexpected ACCESS")
				}
				var e encoder
				e.u32(tc.supported)
				e.u32(tc.allowed)
				return e, 0, nil
			})
			r, err := v.c.CheckAccess(context.Background(), []byte("file"), 63)
			if (err != nil) != tc.bad {
				t.Fatalf("%+v %v", r, err)
			}
			if !tc.bad && (!r.Available || r.Supported != tc.supported || r.Allowed != tc.allowed) {
				t.Fatalf("lost masks: %+v", r)
			}
			if tc.name == "partial" && (r.Decision(1) != "denied" || r.Decision(2) != "unsupported" || r.Decision(32) != "allowed") {
				t.Fatalf("decisions: %+v", r)
			}
		})
	}
}

func TestAccessReportErrorsAndLegacy(t *testing.T) {
	v := peer4(t, 0, func(op uint32, d *decoder) (encoder, Status, error) { d.u32(); return nil, 13, nil })
	r, err := v.c.CheckAccess(context.Background(), []byte("file"), 1)
	if !errors.Is(err, Status(13)) || r.Available || r.Decision(1) != "unknown" {
		t.Fatalf("%+v %v", r, err)
	}
	c := &Client{version: "2"}
	r, err = c.CheckAccess(context.Background(), []byte("file"), 1)
	if err != nil || r.Available || r.Decision(1) != "unsupported" {
		t.Fatalf("v2 %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.CheckAccess(ctx, nil, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = c.CheckAccess(context.Background(), nil, 64); err == nil {
		t.Fatal("invalid mask accepted")
	}
}

func TestAccessReportExecuteRead(t *testing.T) {
	r := AccessReport{Requested: 63, Supported: 33, Allowed: 32, Available: true}
	if r.ReadDecision(true) != "allowed" || r.ReadDecision(false) != "denied" || r.Decision(1) != "denied" {
		t.Fatal(r)
	}
	r.Allowed = 0
	if r.ReadDecision(true) != "denied" {
		t.Fatal(r)
	}
	r.Supported = 1
	if r.ReadDecision(true) != "unsupported" {
		t.Fatal(r)
	}
	r.Error = "request failed"
	if r.ReadDecision(true) != "unknown" {
		t.Fatal(r)
	}
}
