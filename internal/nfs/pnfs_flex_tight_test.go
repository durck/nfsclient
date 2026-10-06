package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestFlexTightDevice(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		ds := &flexDS{handles: [][]byte{bytes.Repeat([]byte{1}, 128)}, owner: "ignored@example.test", group: "ignored"}
		b := flexTestDevice(1)
		binary.BigEndian.PutUint32(b[len(b)-20:], 4)
		binary.BigEndian.PutUint32(b[len(b)-16:], minor)
		binary.BigEndian.PutUint32(b[len(b)-4:], 1)
		d := &decoder{b: b}
		decodeFlexDevice(d, ds, PNFSOptions{DataServers: map[string]string{"192.0.2.1:2049": "127.0.0.1:2049"}})
		if d.err != nil || ds.major != 4 || ds.minor != minor || len(ds.handle) != 128 || ds.rsize != 128 {
			t.Fatal(ds, d.err)
		}
	}
}

func TestFlexFreeBSDVersionHandlePrefix(t *testing.T) {
	for _, mode := range []string{"stock", "reversed", "loose", "different-major", "zero-rsize", "extra-handle", "canonical"} {
		t.Run(mode, func(t *testing.T) {
			b := flexTestDevice(1)
			b = b[:len(b)-24]
			b.u32(2)
			for _, minor := range []uint32{2, 1} {
				major, tight, rsize := uint32(4), uint32(1), uint32(128)
				if mode == "reversed" {
					minor = 3 - minor
				}
				if mode == "loose" {
					tight = 0
				}
				if mode == "different-major" {
					major = 3
				}
				if mode == "zero-rsize" && minor == 2 {
					rsize = 0
				}
				for _, n := range []uint32{major, minor, rsize, 128, tight} {
					b.u32(n)
				}
			}
			ds := &flexDS{handles: [][]byte{[]byte("first")}}
			if mode == "canonical" {
				ds.handles = append(ds.handles, []byte("second"))
			}
			if mode == "extra-handle" {
				ds.handles = append(ds.handles, []byte("second"), []byte("third"))
			}
			d := &decoder{b: b}
			decodeFlexDevice(d, ds, PNFSOptions{})
			if (d.err == nil) != (mode == "stock" || mode == "canonical") {
				t.Fatal(mode, d.err)
			}
			if d.err == nil && (ds.major != 4 || ds.minor != 2 || string(ds.handle) != "first") {
				t.Fatal(ds)
			}
		})
	}
}

func TestFlexTightReadWire(t *testing.T) {
	for _, mdsMinor := range []uint32{1, 2} {
		for _, dsMinor := range []uint32{1, 2} {
			for _, mode := range []string{"data", "short", "holes", "zero", "denied", "bad-xdr"} {
				t.Run(fmt.Sprintf("mds%d/ds%d/%s", mdsMinor, dsMinor, mode), func(t *testing.T) {
					state := bytes.Repeat([]byte{9}, 16)
					var offsets []uint64
					s := &createSequenceServer{next: 22, clientID: 123, owner: "ds", scope: "scope"}
					peer := s.peer(t, dsMinor, nil, 0x40000, func(code uint32, d *decoder) (encoder, Status, error) {
						if !bytes.Equal(d.take(16), state) {
							return nil, 0, errors.New("Flex global stateid changed")
						}
						offset, count := d.u64(), d.u32()
						if offset < 123 || offset >= 138 || count == 0 || offset+uint64(count) != 138 {
							return nil, 0, errors.New("Flex READ range changed")
						}
						offsets = append(offsets, offset)
						if mode == "denied" {
							return nil, Status(13), nil
						}
						if mode == "bad-xdr" {
							return nil, 0, nil
						}
						var e encoder
						if mode == "holes" {
							e.u32(1)
						} else {
							e.u32(0)
						}
						if mode == "short" {
							count = min(count, 3)
						}
						if mode == "holes" || mode == "zero" {
							count = 0
						}
						data := make([]byte, count)
						for i := range data {
							data[i] = byte(offset + uint64(i))
						}
						e.opaque(data)
						return e, 0, nil
					})
					endpoint := pnfsPeerEndpoint(t, peer)
					parent := &Client{Auth: Auth{UID: 25001, GID: 25000, Groups: []uint32{25002}}, ReadSize: 128, config: &Config{Timeout: time.Second}}
					parent.v4 = &v4Client{c: parent, minor: mdsMinor, clientNonce: bytes.Repeat([]byte{6}, 16)}
					component := &flexDS{rsize: 128, major: 4, minor: dsMinor, state: state, endpoints: []string{endpoint}, handle: []byte("ds-file"), owner: "ignored", group: "ignored"}
					get, _, _, closePool := parent.pnfsFlexServers(context.Background(), nil, nil, func() error { return nil })
					defer closePool()
					ds, _, err := get(component)
					if err != nil {
						t.Fatal(err)
					}
					cached, _, err := get(component)
					if err != nil || cached != ds || !reflect.DeepEqual(ds.Auth, parent.Auth) || ds.v4.minor != dsMinor {
						t.Fatal("identity, protocol or cache changed", err)
					}
					r := &pnfsRead{ds: ds, flex: component, handle: component.handle, offset: 123, limit: 15}
					err = readPNFSBatch(context.Background(), []*pnfsRead{r}, bytes.Repeat([]byte{7}, 16), func() error { return nil })
					success := mode == "data" || mode == "short" || mode == "holes"
					if (err == nil) != success || (r.ioErr == nil) != success {
						t.Fatal(err, r.ioErr)
					}
					if success {
						want := make([]byte, 15)
						if mode != "holes" {
							for i := range want {
								want[i] = byte(123 + i)
							}
						}
						if !bytes.Equal(r.data, want) || mode == "short" && fmt.Sprint(offsets) != "[123 126 129 132 135]" {
							t.Fatal(r.data, offsets)
						}
					}
				})
			}
		}
	}
}

func TestFlexTightTLS(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"tls-name", "tls-wrong-name", "tls-untrusted", "tls-no-upgrade", "tls-no-alpn", "tls-client-cert", "tls-client-cert-missing"} {
			t.Run(fmt.Sprintf("%d/%s", minor, mode), func(t *testing.T) {
				policy, server := pnfsTLSFixture(t, mode)
				s := &createSequenceServer{next: 22, clientID: 123, owner: "ds", scope: "scope"}
				peer := s.peer(t, minor, nil, 0x40000)
				endpoint := pnfsTLSPeerEndpoint(t, peer, server(0), mode)
				name := "ds-0.test"
				if mode == "tls-wrong-name" {
					name = "wrong.test"
				}
				parent := &Client{Auth: Auth{UID: 25001, GID: 25000}, config: &Config{Transport: "tcp", Timeout: time.Second, TLS: policy}}
				parent.v4 = &v4Client{c: parent, minor: minor, clientNonce: bytes.Repeat([]byte{6}, 16)}
				policies, err := pnfsTLSConfigs(*parent.config, PNFSOptions{DataServers: map[string]string{endpoint: endpoint}, TLSNames: map[string]string{endpoint: name}})
				if err != nil {
					t.Fatal(err)
				}
				get, _, _, closePool := parent.pnfsFlexServers(context.Background(), policies, nil, func() error { return nil })
				defer closePool()
				_, _, err = get(&flexDS{major: 4, minor: minor, endpoints: []string{endpoint}})
				if (err == nil) != (mode == "tls-name" || mode == "tls-client-cert") {
					t.Fatal(mode, err)
				}
			})
		}
	}
}
