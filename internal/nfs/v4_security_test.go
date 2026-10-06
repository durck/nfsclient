package nfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSecurityTuples4(t *testing.T) {
	var e encoder
	e.u32(6)
	e.u32(0)
	e.u32(1)
	for service := uint32(1); service <= 3; service++ {
		e.u32(6)
		e.opaque(krb5OID)
		e.u32(0)
		e.u32(service)
	}
	e.u32(6)
	e.opaque([]byte("unknown mechanism"))
	e.u32(1)
	e.u32(3)
	d := &decoder{b: e}
	if modes := readSecurity4(d); d.err != nil || strings.Join(modes, ",") != "AUTH_NONE,sys,krb5,krb5i,krb5p,RPCSEC_GSS (unsupported tuple)" || len(d.b) != 0 {
		t.Fatalf("security modes: %v, %v", modes, d.err)
	}
	for i := 0; i < len(e); i++ {
		d := &decoder{b: e[:i]}
		readSecurity4(d)
		if d.err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	for _, malformed := range []encoder{{0, 0, 0, 65}, {0, 0, 0, 1, 0, 0, 0, 6, 255, 255, 255, 255}} {
		d := &decoder{b: malformed}
		readSecurity4(d)
		if d.err == nil {
			t.Fatal("accepted oversized SECINFO array/OID")
		}
	}
}

func TestWrongSecurityDiagnostic4(t *testing.T) {
	for _, mode := range []string{"listed", "unavailable", "malformed", "permission"} {
		t.Run(mode, func(t *testing.T) {
			var calls []uint32
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				calls = append(calls, code)
				if d.str() != "private" {
					return nil, 0, errors.New("wrong SECINFO/LOOKUP name")
				}
				switch code {
				case 15:
					if mode == "permission" {
						return nil, 13, nil
					}
					return nil, 10016, nil
				case 33:
					if mode == "unavailable" {
						return nil, 13, nil
					}
					if mode == "malformed" {
						return encoder{0, 0, 0, 65}, 0, nil
					}
					var e encoder
					e.u32(1)
					e.u32(6)
					e.opaque(krb5OID)
					e.u32(0)
					e.u32(3)
					return e, 0, nil
				}
				return nil, 0, fmt.Errorf("unexpected operation %d", code)
			})
			v.c.security = "krb5i"
			_, err := v.lookup(context.Background(), v.root, "private")
			if mode == "permission" {
				if !errors.Is(err, Status(13)) || fmt.Sprint(calls) != "[15]" {
					t.Fatalf("permission error treated as security negotiation: %v %v", err, calls)
				}
				return
			}
			if !errors.Is(err, Status(10016)) || fmt.Sprint(calls) != "[15 33]" || v.c.Security() != "krb5i" {
				t.Fatalf("replayed lookup or changed security: %v %v", calls, err)
			}
			want := "SECINFO unavailable"
			if mode == "listed" {
				want = "server advertises krb5p"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
		})
	}
}
