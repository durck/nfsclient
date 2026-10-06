package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
)

func deviceCallbackCall(r *layoutRecall, seq uint32, id []byte, kind uint32, immediate bool) encoder {
	e := callbackCall(r, seq, false)
	binary.BigEndian.PutUint32(e[44:48], r.minor)
	binary.BigEndian.PutUint32(e[52:56], 2)
	e.u32(14)
	e.u32(1)
	bitmap4(&e, kind)
	var body encoder
	body.u32(r.layoutKind())
	body = append(body, id...)
	if kind == 1 {
		if immediate {
			body.u32(1)
		} else {
			body.u32(0)
		}
	}
	e.opaque(body)
	return e
}

func TestPNFSDeviceNotificationTransactions(t *testing.T) {
	for _, mode := range []string{"change", "immediate", "delete", "unknown", "truncated", "trailing", "boolean", "unsupported", "limit", "reply-limit"} {
		t.Run(mode, func(t *testing.T) {
			id := bytes.Repeat([]byte{9}, 16)
			r := &layoutRecall{minor: 1, session: bytes.Repeat([]byte{2}, 16), deviceNotifications: true, devices: map[string]deviceNotice{string(id): {}}}
			kind := uint32(1)
			if mode == "delete" {
				kind = 2
			}
			call := deviceCallbackCall(r, 1, id, kind, mode == "immediate")
			switch mode {
			case "unknown":
				call = deviceCallbackCall(r, 1, bytes.Repeat([]byte{1}, 16), 1, false)
			case "truncated":
				call = call[:len(call)-1]
			case "trailing":
				call = append(call, 0)
			case "boolean":
				binary.BigEndian.PutUint32(call[len(call)-4:], 2)
			case "unsupported":
				call = deviceCallbackCall(r, 1, id, 3, false)
			case "limit":
				binary.BigEndian.PutUint32(call[len(callbackCall(r, 1, false))+4:], 65)
			case "reply-limit":
				r.responseLimit = 32
			}
			reply, err := r.callback(call)
			valid := mode == "change" || mode == "immediate" || mode == "delete" || mode == "unknown"
			if valid {
				if err != nil || binary.BigEndian.Uint32(reply[24:28]) != 0 || r.sequence != 1 {
					t.Fatal("notification failed", err)
				}
				want := uint64(1)
				if mode == "unknown" {
					want = 0
				}
				if len(r.devices) != 1 || r.devices[string(id)].generation != want || r.devices[string(id)].invalid != (mode == "immediate" || mode == "delete") {
					t.Fatal("incorrect device state", r.devices)
				}
				if replay, err := r.callback(call); err != nil || !bytes.Equal(replay, reply) || r.devices[string(id)].generation != want {
					t.Fatal("callback retransmission applied twice", err)
				}
			} else if r.sequence != 0 || r.devices[string(id)] != (deviceNotice{}) || err == nil && mode != "reply-limit" {
				t.Fatal("invalid callback mutated state", err)
			}
		})
	}
}

func TestPNFSDeviceRefreshOptions(t *testing.T) {
	for _, security := range []string{"", "sys", "krb5"} {
		c := &Client{config: &Config{Security: security}, nfs: &rpcClient{}}
		if _, err := c.pnfsKerberosConfigs(PNFSOptions{RefreshDevices: true}); err == nil {
			t.Fatal("unprotected device refresh accepted", security)
		}
	}
	c := &Client{}
	if c.ValidatePNFSWriteOptions(PNFSOptions{RefreshDevices: true}) == nil {
		t.Fatal("device refresh accepted for write preflight")
	}
	if _, err := c.WritePNFSRangeFromProgress(context.Background(), nil, 0, 1, bytes.NewReader([]byte{1}), PNFSOptions{RefreshDevices: true}, nil); err == nil {
		t.Fatal("device refresh accepted for writes")
	}
	for _, mode := range []string{"ok", "flex", "path", "mirror"} {
		t.Run(mode, func(t *testing.T) {
			o := PNFSOptions{RefreshDevices: true, DataServers: map[string]string{"192.0.2.1:2049": "192.0.2.1:2049"}}
			switch mode {
			case "flex":
				o.Layout = "flex"
			case "path":
				o.ReadFailover = true
			case "mirror":
				o.MirrorFailover = true
			}
			if _, err := validatePNFSOptions(o); (err == nil) != (mode == "ok" || mode == "flex") {
				t.Fatal("unexpected option validation", err)
			}
		})
	}
}

func TestPNFSMITDeviceRefresh(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, tls := range []string{"", "tls-"} {
				for _, parallel := range []int{1, 3} {
					for _, mode := range []string{"change", "race", "immediate", "delete", "topology", "unapproved", "denied", "unsupported", "flood", "midbatch", "initial"} {
						t.Run(fmt.Sprintf("4.%d/%s/%sp%d/%s", minor, security, tls, parallel, mode), func(t *testing.T) {
							runPNFSStripedRead(t, minor, "gss-"+security+"-"+tls+"refresh-"+mode+"-dense", 128, "data", parallel)
						})
					}
					for _, mode := range []string{"change", "race"} {
						t.Run(fmt.Sprintf("4.%d/%s/%sp%d/sparse-%s", minor, security, tls, parallel, mode), func(t *testing.T) {
							runPNFSStripedRead(t, minor, "gss-"+security+"-"+tls+"refresh-"+mode+"-sparse-many", 128, "holes", parallel)
						})
					}
				}
			}
		}
	}
}

func TestPNFSDeviceRefreshSharedSegments(t *testing.T) {
	device := bytes.Repeat([]byte{8}, 16)
	queries := 0
	v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
		queries++
		if code != 47 || !bytes.Equal(d.take(16), device) || d.u32() != 1 || d.u32() != 32768 {
			t.Error("wrong device refresh request")
		}
		readBitmap4(d)
		var body, e encoder
		body.u32(1)
		body.u32(0)
		body.u32(1)
		body.u32(1)
		body.str("tcp")
		body.str("192.0.2.2.8.1")
		e.u32(1)
		e.opaque(body)
		bitmap4(&e, 1, 2)
		return e, 0, nil
	})
	v.recall = &layoutRecall{active: true, devices: map[string]deviceNotice{string(device): {generation: 1}}}
	a := &fileLayout{device: device, util: 64, indices: []uint32{0}, servers: [][]string{{"192.0.2.1:2049"}}, endpoints: [][]string{{"192.0.2.1:2049"}}}
	b := *a
	b.offset, b.pattern = 64, 64
	other := *a
	other.device = bytes.Repeat([]byte{7}, 16)
	o := PNFSOptions{RefreshDevices: true, DataServers: map[string]string{"192.0.2.2:2049": "192.0.2.20:2049"}}
	attempts := 0
	if err := v.refreshLayoutDevices(context.Background(), []byte("file"), []*fileLayout{a, &b, &other}, o, &attempts); err != nil {
		t.Fatal(err)
	}
	if queries != 1 || attempts != 1 || a.endpoints[0][0] != "192.0.2.20:2049" || b.endpoints[0][0] != a.endpoints[0][0] || other.endpoints[0][0] != "192.0.2.1:2049" || b.pattern != 64 || v.recall.devicesPending() {
		t.Fatal("device refresh lost shared segments or changed another device")
	}
}
