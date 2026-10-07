package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestValidateOwnership(t *testing.T) {
	for _, tt := range []struct {
		version, value string
		ok             bool
	}{
		{"2", "4294967294", true}, {"2", "4294967295", false},
		{"3", "4294967295", true}, {"3", "4294967296", false},
		{"3", "0", true}, {"3", "0012", true}, {"3", "+12", false},
		{"3", "-1", false}, {"3", "user", false}, {"3", " 1", false},
		{"4.0", "user@domain", true}, {"4.1", "DOMAIN\\user", true},
		{"4.2", "испытание@domain", true}, {"4.2", "123", true},
		{"4.2", "", false}, {"4.2", "a\x00b", false}, {"4.2", "\xff", false},
		{"4.2", strings.Repeat("a", 1024), true}, {"4.2", strings.Repeat("a", 1025), false},
	} {
		if err := ValidateOwnership(tt.version, &tt.value, nil); (err == nil) != tt.ok {
			t.Errorf("%+v: %v", tt, err)
		}
		if err := ValidateOwnership(tt.version, nil, &tt.value); (err == nil) != tt.ok {
			t.Errorf("group %+v: %v", tt, err)
		}
	}
	if ValidateOwnership("3", nil, nil) == nil {
		t.Fatal("empty change accepted")
	}
}

func ownershipAttr3(e *encoder, uid, gid uint32) {
	for _, n := range []uint32{1, 0640, 1, uid, gid} {
		e.u32(n)
	}
	e.u64(17)
	e.u64(17)
	e.u32(0)
	e.u32(0)
	e.u64(1)
	e.u64(2)
	for range 6 {
		e.u32(0)
	}
}

func TestLegacyOwnershipWireAndVerification(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		for _, scenario := range []string{"both", "owner", "group", "rejected", "readback-denied", "mismatch", "malformed-reply"} {
			t.Run(version+"/"+scenario, func(t *testing.T) {
				owner, group := "1000", "1001"
				o, g := &owner, &group
				if scenario == "owner" {
					g = nil
				}
				if scenario == "group" {
					o = nil
				}
				writes, reads := 0, 0
				fh := bytes.Repeat([]byte{7}, 32)
				c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
					if prog != nfsProgram {
						return nil, errors.New("wrong program")
					}
					var got []byte
					if version == "2" {
						got = d.take(32)
					} else {
						got = d.opaque(64)
					}
					if !bytes.Equal(got, fh) {
						return nil, errors.New("changed ownership handle")
					}
					var e encoder
					switch proc {
					case 2:
						writes++
						if version == "2" {
							want := []uint32{^uint32(0), 1000, 1001, ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}
							if o == nil {
								want[1] = ^uint32(0)
							}
							if g == nil {
								want[2] = ^uint32(0)
							}
							for _, n := range want {
								if d.u32() != n {
									return nil, errors.New("wrong NFSv2 sattr")
								}
							}
						} else {
							if d.u32() != 0 {
								return nil, errors.New("mode changed")
							}
							for i, value := range []*string{o, g} {
								set := d.boolean()
								if set != (value != nil) || set && d.u32() != uint32(1000+i) {
									return nil, errors.New("wrong numeric owner")
								}
							}
							for range 4 {
								if d.u32() != 0 {
									return nil, errors.New("unrequested attribute changed")
								}
							}
						}
						if d.err != nil || len(d.b) != 0 {
							return nil, errors.New("malformed request")
						}
						if scenario == "rejected" {
							e.u32(1)
							return e, nil
						}
						e.u32(0)
						if scenario == "malformed-reply" {
							return e, nil
						}
						if version == "2" {
							attrReply2(&e, 17)
						} else {
							e.u32(0)
							e.u32(0)
						}
					case 1:
						reads++
						if scenario == "readback-denied" {
							e.u32(13)
							return e, nil
						}
						e.u32(0)
						if version == "2" {
							attrReply2(&e, 17)
							if scenario == "mismatch" {
								e[19]++
							}
						} else {
							uid := uint32(1000)
							if scenario == "mismatch" {
								uid++
							}
							ownershipAttr3(&e, uid, 1001)
						}
					default:
						return nil, fmt.Errorf("unexpected proc %d", proc)
					}
					return e, nil
				})
				c.version = version
				err := c.SetOwnership(context.Background(), fh, o, g)
				good := scenario == "both" || scenario == "owner" || scenario == "group"
				if good && err != nil || !good && !errors.Is(err, ErrMutationUncertain) || writes != 1 {
					t.Fatalf("writes=%d reads=%d: %v", writes, reads, err)
				}
				if scenario == "rejected" && (!errors.Is(err, Status(1)) || reads != 0) {
					t.Fatal(err, reads)
				}
				if good && reads != 1 {
					t.Fatal("readback absent")
				}
			})
		}
	}
}

func TestV4OwnershipWireAndVerification(t *testing.T) {
	for _, scenario := range []string{"both", "owner", "group", "badowner", "partial", "wrong-ack", "missing-ack", "readback-denied", "mismatch", "missing-owner"} {
		t.Run(scenario, func(t *testing.T) {
			owner, group := "User@EXAMPLE", "Group@EXAMPLE"
			o, g := &owner, &group
			if scenario == "owner" {
				g = nil
			}
			if scenario == "group" {
				o = nil
			}
			want := []uint32{}
			if o != nil {
				want = append(want, 36)
			}
			if g != nil {
				want = append(want, 37)
			}
			writes, reads := 0, 0
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 34:
					writes++
					if !bytes.Equal(d.take(16), make([]byte, 16)) || !reflect.DeepEqual(readBitmap4(d), want) {
						return nil, 0, errors.New("bad SETATTR stateid/bitmap")
					}
					values := &decoder{b: d.opaque(4096)}
					for _, value := range []*string{o, g} {
						if value != nil && values.str() != *value {
							return nil, 0, errors.New("ownership string changed")
						}
					}
					if values.err != nil || len(values.b) != 0 {
						return nil, 0, errors.New("trailing attributes")
					}
					switch scenario {
					case "badowner":
						bitmap4(&e)
						return e, 10039, nil
					case "partial":
						bitmap4(&e, 36)
						return e, 1, nil
					case "wrong-ack":
						bitmap4(&e, 33)
					case "missing-ack":
						bitmap4(&e)
					default:
						bitmap4(&e, want...)
					}
				case 9:
					reads++
					readBitmap4(d)
					if scenario == "readback-denied" {
						return nil, 13, nil
					}
					var a encoder
					a.u32(1)
					if scenario == "missing-owner" {
						bitmap4(&e, 1, 37)
					} else {
						bitmap4(&e, 1, 36, 37)
						value := owner
						if scenario == "mismatch" {
							value = "user@EXAMPLE"
						}
						a.str(value)
					}
					a.str(group)
					e.opaque(a)
				default:
					return nil, 0, fmt.Errorf("unexpected op %d", code)
				}
				return e, 0, nil
			})
			err := v.c.SetOwnership(context.Background(), []byte("file"), o, g)
			good := scenario == "both" || scenario == "owner" || scenario == "group"
			if writes != 1 || good && (err != nil || reads != 1) {
				t.Fatal(writes, reads, err)
			}
			if scenario == "badowner" {
				if !errors.Is(err, Status(10039)) || errors.Is(err, ErrMutationUncertain) {
					t.Fatal(err)
				}
			} else if !good && !errors.Is(err, ErrMutationUncertain) {
				t.Fatal(err)
			}
			if scenario == "partial" && !errors.Is(err, Status(1)) {
				t.Fatal("lost status", err)
			}
		})
	}
}
