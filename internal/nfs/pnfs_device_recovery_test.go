package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
)

// Independent wire oracle: DELETE revokes the old grant, while a new grant
// must use a different device ID (RFC 8881 20.12.3). Never resend data here.
func TestPNFSDeletedDeviceRecovery(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, write := range []bool{false, true} {
			for _, outcome := range []string{"ok", "revoked", "reused", "denied", "lost"} {
				t.Run(fmt.Sprintf("4.%d/write=%v/%s", minor, write, outcome), func(t *testing.T) {
					old := bytes.Repeat([]byte{9}, 16)
					open, state := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
					mode := uint32(1)
					if write {
						mode = 2
					}
					var calls []uint32
					v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
						calls = append(calls, code)
						var e encoder
						switch code {
						case 51:
							if d.u32() != 0 || d.u32() != 1 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != math.MaxUint64 || !bytes.Equal(d.take(16), state) || len(d.opaque(64)) != 0 {
								return nil, 0, errors.New("wrong revoked grant return")
							}
							if outcome == "revoked" {
								return nil, Status(10025), nil
							}
							e.u32(0)
						case 50:
							if d.u32() != 0 || d.u32() != 1 || d.u32() != mode || d.u64() != 0 || d.u64() != math.MaxUint64 || d.u64() != 1 || !bytes.Equal(d.take(16), open) || d.u32() != 32768 {
								return nil, 0, errors.New("fresh grant lost original OPEN or mode")
							}
							if outcome == "denied" {
								return nil, Status(13), nil
							}
							e = segmentReply([]layoutSegmentSpec{{0, math.MaxUint64, 0, mode, 1}})
							if outcome == "reused" {
								copy(e[52:68], old)
							}
						case 47:
							if !bytes.Equal(d.take(16), make([]byte, 16)) || d.u32() != 1 || d.u32() != 32768 {
								return nil, 0, errors.New("queried old device")
							}
							readBitmap4(d)
							var body encoder
							body.u32(1)
							body.u32(0)
							body.u32(1)
							body.u32(1)
							body.str("tcp")
							body.str("192.0.2.2.8.1")
							e.u32(1)
							e.opaque(body)
							bitmap4(&e, 1, 2)
						default:
							return nil, 0, fmt.Errorf("unsafe recovery op %d", code)
						}
						return e, 0, nil
					})
					v.recall = &layoutRecall{active: true, state: state, layoutType: 1, devices: map[string]deviceNotice{string(old): {generation: 1, deleted: true, invalid: true}}, deletedDevices: map[string]bool{string(old): true}}
					if outcome == "lost" {
						v.stateLost.Store(true)
					}
					attempts := 0
					layouts, err := v.recoverLayoutDevices(context.Background(), []byte("file"), open, 64, []*fileLayout{{device: old}}, PNFSOptions{RefreshDevices: true, DataServers: map[string]string{"192.0.2.2:2049": "192.0.2.20:2049"}}, write, &attempts)
					ok := outcome == "ok" || outcome == "revoked"
					if (err == nil) != ok {
						t.Fatal("recovery outcome", err, calls)
					}
					if outcome == "lost" {
						if len(calls) != 0 || !v.stateLost.Load() {
							t.Fatal("lost metadata state bypassed")
						}
						return
					}
					want := []uint32{51, 50}
					if ok {
						want = append(want, 47)
					}
					if fmt.Sprint(calls) != fmt.Sprint(want) || attempts != 1 {
						t.Fatal("unexpected recovery calls", calls, attempts)
					}
					if ok && (len(layouts) != 1 || bytes.Equal(layouts[0].device, old) || layouts[0].endpoints[0][0] != "192.0.2.20:2049" || v.stateLost.Load() || v.recall.devicesPending()) {
						t.Fatal("recovery lost new mapping or retained revoked state")
					}
					if !v.recall.deletedDevices[string(old)] {
						t.Fatal("deleted ID tombstone lost")
					}
				})
			}
		}
	}
}

func TestPNFSDeviceBarrierDoesNotHideFailure(t *testing.T) {
	if !onlyDeviceBarrier(errors.Join(errPNFSDeviceChange, context.Canceled)) || onlyDeviceBarrier(errors.Join(errPNFSDeviceChange, Status(13))) || onlyDeviceBarrier(errors.Join(errPNFSDeviceDeleted, errors.New("authentication failed"))) {
		t.Fatal("device recovery hid an independent failure")
	}
}

func TestFlexWriteDeviceRegistrationIncludesRequiredMirrors(t *testing.T) {
	for _, one := range []bool{false, true} {
		a, b := &flexDS{device: bytes.Repeat([]byte{1}, 16)}, &flexDS{device: bytes.Repeat([]byte{2}, 16)}
		l := &fileLayout{flex: &flexLayout{mirrors: [][]*flexDS{{a}, {b}}, selected: []*flexDS{b}}}
		if one {
			l.flex.flags = 8
		}
		r := &layoutRecall{devices: map[string]deviceNotice{string(a.device): {generation: 2, invalid: true}, string(b.device): {generation: 1}}}
		if err := r.registerLayoutDevices([]*fileLayout{l}, true); err != nil {
			t.Fatal(err)
		}
		want := 2
		if one {
			want = 1
		}
		if len(r.devices) != want {
			t.Fatal("write mirror device tracking", len(r.devices), want)
		}
		b.deviceGeneration = 1
		r.acknowledgeDeviceGenerations([]*fileLayout{l})
		if r.devicesPending() == one {
			t.Fatal("unrefreshed required mirror acknowledged")
		}
		if !one {
			a.deviceGeneration = 2
			r.acknowledgeDeviceGenerations([]*fileLayout{l})
			if r.devicesPending() || r.devices[string(a.device)].invalid {
				t.Fatal("refreshed mirror remains fenced")
			}
		}
	}
}
