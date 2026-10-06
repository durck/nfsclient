package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestFlexMITDeviceRefresh(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, width := range []int{1, 3} {
					for _, mode := range []string{"change", "race", "initial", "flood", "immediate", "delete", "unapproved", "version", "limits", "denied", "unsupported", "midbatch", "holes-change", "holes-race", "holes-initial"} {
						t.Run(fmt.Sprintf("4.%d/%s/tls=%v/w%d/%s", minor, security, secure, width, mode), func(t *testing.T) {
							p := newFlexMITProfile(t, security, secure)
							p.refreshMode = mode
							readMode := "data"
							if len(mode) > 6 && mode[:6] == "holes-" {
								readMode, p.refreshMode = "holes", mode[6:]
							}
							runFlexReadWire(t, minor, 2, width, width, readMode, p)
						})
					}
				}
			}
		}
	}
}

func TestFlexMITDeviceNotifications(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", secure), func(t *testing.T) { runPNFSMITBackchannel(t, secure, 14, 4) })
	}
}

func TestFlexRefreshSharedHandles(t *testing.T) {
	for _, mode := range []string{"ok", "second-shape", "version", "immediate"} {
		t.Run(mode, func(t *testing.T) {
			device := bytes.Repeat([]byte{1}, 16)
			var v *v4Client
			queries := 0
			v = peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 47 || !bytes.Equal(d.take(16), device) || d.u32() != 4 || d.u32() != 32768 {
					return nil, 0, fmt.Errorf("unexpected refresh query %d", code)
				}
				readBitmap4(d)
				queries++
				body := flexTestDevice(1)
				binary.BigEndian.PutUint32(body[len(body)-20:], 4)
				minor := uint32(1)
				if mode == "version" {
					minor = 2
				}
				binary.BigEndian.PutUint32(body[len(body)-16:], minor)
				binary.BigEndian.PutUint32(body[len(body)-4:], 1)
				if mode == "immediate" {
					v.recall.mu.Lock()
					n := v.recall.devices[string(device)]
					n.generation++
					n.invalid = true
					v.recall.devices[string(device)] = n
					v.recall.mu.Unlock()
				}
				var e encoder
				e.u32(4)
				e.opaque(body)
				bitmap4(&e, 1, 2)
				return e, 0, nil
			})
			v.recall = &layoutRecall{active: true, fh: []byte("file"), layoutType: 4, devices: map[string]deviceNotice{string(device): {generation: 1}}}
			layouts := []*fileLayout{}
			for i := range 2 {
				handle := []byte(fmt.Sprintf("segment%d", i))
				ds := &flexDS{device: device, state: bytes.Repeat([]byte{byte(i + 7)}, 16), handles: [][]byte{handle}, handle: handle, major: 4, minor: 1, rsize: 128, wsize: 128, endpoints: []string{"127.0.0.1:1"}}
				if mode == "second-shape" && i == 1 {
					ds.handles = nil
				}
				layouts = append(layouts, &fileLayout{flex: &flexLayout{selected: []*flexDS{ds}}})
			}
			o := PNFSOptions{Layout: "flex", RefreshDevices: true, DataServers: map[string]string{"192.0.2.1:2049": "127.0.0.1:2"}}
			err := v.refreshFlexDevice(context.Background(), []byte("file"), layouts, device, o)
			if (err == nil) != (mode == "ok" || mode == "immediate") || queries != 1 {
				t.Fatal("refresh result", err, queries)
			}
			for i, l := range layouts {
				ds := l.flex.selected[0]
				endpoint, generation := "127.0.0.1:1", uint64(0)
				if mode == "ok" || mode == "immediate" {
					endpoint, generation = "127.0.0.1:2", 1
				}
				if ds.endpoints[0] != endpoint || ds.deviceGeneration != generation || string(ds.handle) != fmt.Sprintf("segment%d", i) || !bytes.Equal(ds.state, bytes.Repeat([]byte{byte(i + 7)}, 16)) {
					t.Fatal("partial commit or changed component handle/state", ds)
				}
			}
			// RFC 8881 20.12.3 permits an immediate mapping refresh, but a
			// later notification must fence I/O until its generation is fetched.
			if mode == "immediate" && (!v.recall.devicesPending() || !v.recall.devices[string(device)].invalid) {
				t.Fatal("racing immediate change was acknowledged by an older fetch")
			}
			if mode == "ok" {
				layouts[0].flex.selected[0].deviceGeneration = 0
				v.recall.acknowledgeDeviceGenerations(layouts)
				if !v.recall.devicesPending() {
					t.Fatal("stale shared component acknowledged")
				}
			}
		})
	}
}

func TestFlexDeviceNotificationTypeIsolation(t *testing.T) {
	id := bytes.Repeat([]byte{9}, 16)
	r := &layoutRecall{minor: 1, session: bytes.Repeat([]byte{2}, 16), layoutType: 4, deviceNotifications: true, devices: map[string]deviceNotice{string(id): {}}}
	sender := &layoutRecall{minor: r.minor, session: r.session}
	if _, err := r.callback(deviceCallbackCall(sender, 1, id, 1, true)); err != nil {
		t.Fatal(err)
	}
	if r.devices[string(id)] != (deviceNotice{}) {
		t.Fatal("FILE notification changed Flex mapping")
	}
	if _, err := r.callback(deviceCallbackCall(r, 2, id, 1, false)); err != nil {
		t.Fatal(err)
	}
	if r.devices[string(id)].generation != 1 || r.devices[string(id)].invalid {
		t.Fatal("Flex notification was not applied")
	}
}
