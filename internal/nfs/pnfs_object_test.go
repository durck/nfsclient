package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/iscsi"
	"nfsclient/internal/testiscsi"
)

func objectCredentialWire(device []byte, object uint64, root bool) encoder {
	e := append(encoder(nil), device...)
	p := uint64(0x10000)
	if root {
		p = 0
	}
	e.u64(p)
	e.u64(object)
	e.u32(1)
	e.u32(0)
	e.opaque(nil)
	e.opaque(make([]byte, 80))
	return e
}
func objectLayoutWire(device []byte) encoder {
	var e encoder
	e.u32(2)
	e.u64(97)
	for _, n := range []uint32{0, 0, 0, 1, 0, 2} {
		e.u32(n)
	}
	e = append(e, objectCredentialWire(device, 0x10001, false)...)
	return append(e, objectCredentialWire(device, 0x10002, false)...)
}

func TestObjectGeometryAndRefusals(t *testing.T) {
	id := bytes.Repeat([]byte{0x21}, 16)
	d := &decoder{b: objectLayoutWire(id)}
	l := decodeObjectLayout(d)
	if d.err != nil {
		t.Fatal(d.err)
	}
	for off := uint64(0); off < 10000; off++ {
		index, pos, left := objectPosition(l, off)
		if index != int((off/97)%2) || pos != (off/194)*97+off%97 || left != 97-off%97 {
			t.Fatal(off, index, pos, left)
		}
	}
	for _, mode := range []string{"count", "unit", "width", "depth", "mirror", "raid", "first", "partial", "version", "security", "cap-method", "duplicate", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			b := bytes.Clone(objectLayoutWire(id))
			switch mode {
			case "count":
				binary.BigEndian.PutUint32(b, 65)
			case "unit":
				binary.BigEndian.PutUint64(b[4:], 0)
			case "width":
				binary.BigEndian.PutUint32(b[12:], 1)
			case "depth":
				binary.BigEndian.PutUint32(b[16:], 1)
			case "mirror":
				binary.BigEndian.PutUint32(b[20:], 1)
			case "raid":
				binary.BigEndian.PutUint32(b[24:], 3)
			case "first":
				binary.BigEndian.PutUint32(b[28:], 1)
			case "partial":
				binary.BigEndian.PutUint32(b[32:], 1)
			case "version":
				binary.BigEndian.PutUint32(b[68:], 2)
			case "security":
				binary.BigEndian.PutUint32(b[72:], 1)
			case "cap-method":
				b[86] = 1
			case "duplicate":
				copy(b[36+128:], b[36:36+128])
			case "trailing":
				b = append(b, 0)
			}
			d := &decoder{b: b}
			decodeObjectLayout(d)
			if d.err == nil {
				t.Fatal("unsafe layout accepted")
			}
		})
	}
}

func runObjectWire(t *testing.T, minor uint32, mode, security string, secure bool) {
	t.Helper()
	allData := strings.HasPrefix(mode, "alldata-")
	mode = strings.TrimPrefix(mode, "alldata-")
	id := bytes.Repeat([]byte{0x21}, 16)
	system := bytes.Repeat([]byte{0x31}, 20)
	var workingKey []byte
	if allData {
		workingKey = bytes.Repeat([]byte{0x71}, 20)
	}
	credentialWire := func(object uint64, root bool) encoder {
		if !allData || mode == "nosec" || mode == "root-nosec" && root {
			return objectCredentialWire(id, object, root)
		}
		partition := uint64(0x10000)
		if root {
			partition = 0
		}
		cap, key := testiscsi.OSDCredential(system, workingKey, partition, object, iscsi.ObjectRead|iscsi.ObjectGetAttributes, time.Now().Add(time.Hour))
		if !root {
			switch mode {
			case "expired":
				clear(cap[4:10])
				cap[9] = 1
			case "wrong-object":
				cap[75] ^= 1
			case "rights":
				cap[49] = iscsi.ObjectGetAttributes
			}
		}
		e := append(encoder(nil), id...)
		e.u64(partition)
		e.u64(object)
		e.u32(1)
		e.u32(0)
		e.opaque(key)
		e.opaque(cap)
		return e
	}
	data := make([]byte, 1301)
	for i := range data {
		data[i] = byte(i*23 + 7)
	}
	objects := map[[2]uint64][]byte{{0x10000, 0x10001}: {}, {0x10000, 0x10002}: {}}
	for i, b := range data {
		key := [2]uint64{0x10000, 0x10001 + uint64((i/97)%2)}
		objects[key] = append(objects[key], b)
	}
	if mode == "hole" {
		objects[[2]uint64{0x10000, 0x10002}] = objects[[2]uint64{0x10000, 0x10002}][:120]
		for i := range data {
			if (i/97)%2 == 1 && (i/194)*97+i%97 >= 120 {
				data[i] = 0
			}
		}
	}
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
		t.Fatal(err)
	}
	peer := testiscsi.Start(t, path, testiscsi.Options{OSDSystemID: system, OSDName: []byte("fixture"), OSDKey: workingKey, OSDObjects: objects, Fault: mode, AllowProcessKill: true})
	target, err := iscsi.ParseTarget(peer.URL())
	if err != nil {
		t.Fatal(err)
	}
	var returned, closed int
	var v *v4Client
	sid := bytes.Repeat([]byte{7}, 16)
	lsid := bytes.Repeat([]byte{8}, 16)
	binary.BigEndian.PutUint32(lsid, 1)
	v = peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 18:
			d.take(12)
			d.u64()
			d.opaque(128)
			d.u32()
			d.u32()
			d.str()
			e = append(e, sid...)
			e.u32(1)
			e.u64(1)
			e.u64(1)
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 10:
			e.opaque([]byte("file"))
		case 50:
			if d.u32() != 0 || d.u32() != 2 || d.u32() != 1 || d.u64() != 0 || d.u64() != math.MaxUint64 || d.u64() != 1 || !bytes.Equal(d.take(16), sid) || d.u32() != 32768 {
				return nil, 0, errors.New("incorrect OSD LAYOUTGET")
			}
			e.u32(1)
			e = append(e, lsid...)
			e.u32(1)
			e.u64(0)
			e.u64(math.MaxUint64)
			e.u32(1)
			e.u32(2)
			body := objectLayoutWire(id)
			if allData {
				body = body[:36]
				body = append(body, credentialWire(0x10001, false)...)
				body = append(body, credentialWire(0x10002, false)...)
			}
			e.opaque(body)
		case 47:
			if !bytes.Equal(d.take(16), id) || d.u32() != 2 || d.u32() != 32768 || d.u32() != 0 {
				return nil, 0, errors.New("incorrect OSD GETDEVICEINFO")
			}
			var a encoder
			a.u32(2)
			name := target.Name
			if mode == "unapproved" {
				name = "iqn.2026-10.test:other"
			}
			a.str(name)
			a.u32(1)
			a.str("tcp")
			host, port, _ := net.SplitHostPort(target.Endpoint)
			pn, _ := strconv.Atoi(port)
			a.str(fmt.Sprintf("%s.%d.%d", host, pn/256, pn%256))
			a = append(a, make([]byte, 8)...)
			a.opaque(system)
			a = append(a, credentialWire(0, true)...)
			a.opaque([]byte("fixture"))
			e.u32(2)
			e.opaque(a)
			e.u32(0)
		case 51:
			returned++
			if d.u32() != 0 || d.u32() != 2 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != math.MaxUint64 || !bytes.Equal(d.take(16), lsid) {
				return nil, 0, errors.New("incorrect OSD LAYOUTRETURN")
			}
			body := &decoder{b: d.opaque(128)}
			n := body.u32()
			if n > 1 {
				return nil, 0, errors.New("excessive OSD errors")
			}
			if n == 1 {
				if !bytes.Equal(body.take(16), id) || body.u64() != 0x10000 {
					return nil, 0, errors.New("incorrect OSD error component")
				}
				body.u64()
				body.u64()
				body.u64()
				if body.boolean() || body.u32() != 1 {
					return nil, 0, errors.New("incorrect OSD read error")
				}
			}
			if body.err != nil || len(body.b) != 0 {
				return nil, 0, errors.New("malformed OSD return body")
			}
			if mode == "return-failure" {
				return nil, 10025, nil
			}
			e.u32(0)
		case 4:
			closed++
			d.u32()
			e = append(e, d.take(16)...)
			if mode == "close-failure" {
				return nil, 10025, nil
			}
		default:
			return nil, 0, fmt.Errorf("unexpected MDS operation %d", code)
		}
		return e, 0, nil
	})
	v.recall = &layoutRecall{}
	v.c.config = &Config{PNFS: true, Timeout: time.Second}
	v.c.ReadSize = 129
	if security != "" {
		opts := mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]}
		if secure {
			policy, server := pnfsTLSFixture(t, "data")
			opts.client, opts.server = policy, server(0)
		}
		pnfsMITWrapClient(t, v.c, security, nil, opts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	verified := false
	n, err := v.c.ReadPNFSToProgressVerified(ctx, []byte("file"), uint64(len(data)), &out, PNFSOptions{Layout: "object", OSDTargets: []string{peer.URL()}, OSDInitiator: testiscsi.Initiator, OSDRequireSecure: allData}, func(done uint64) {
		if done > 0 {
			switch mode {
			case "cancel":
				cancel()
			case "identity":
				v.c.Auth.UID++
			case "recall":
				v.recall.mu.Lock()
				v.recall.recalled = true
				v.recall.mu.Unlock()
			}
		}
	}, func() error {
		verified = true
		if returned != 0 || closed != 0 || !bytes.Equal(data, out.Bytes()) {
			t.Fatal("verification order/data")
		}
		if mode == "verify-failure" {
			return errors.New("source changed")
		}
		return nil
	})
	if allData && (security != "krb5p" && !secure || mode == "expired" || mode == "wrong-object" || mode == "rights" || mode == "nosec" || mode == "root-nosec") {
		if err == nil || n != 0 || out.Len() != 0 || len(peer.Events()) != 0 {
			t.Fatal("invalid capability reached storage", n, err, peer.Events())
		}
		return
	}
	if mode == "ok" || mode == "hole" {
		if err != nil || n != int64(len(data)) || !verified || !bytes.Equal(data, out.Bytes()) || returned != 1 || closed != 1 {
			t.Fatal(n, err, verified, returned, closed)
		}
	} else if err == nil {
		t.Fatal("unsafe read succeeded", mode)
	}
	if mode == "osd-id" || mode == "osd-type" || mode == "unapproved" {
		if n != 0 || out.Len() != 0 || verified {
			t.Fatal("unverified device leaked data")
		}
	}
}

func TestObjectAllDataWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, tls := range []bool{false, true} {
				for _, mode := range []string{"ok", "hole", "osd-secure-icv", "osd-secure-status", "expired", "wrong-object", "rights", "nosec", "root-nosec", "cancel", "recall"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%t/%s", minor, security, tls, mode), func(t *testing.T) { runObjectWire(t, minor, "alldata-"+mode, security, tls) })
				}
			}
		}
	}
}

func TestObjectWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"ok", "hole", "unapproved", "osd-id", "osd-type", "osd-drop", "osd-attribute", "osd-residual", "osd-data-sequence", "cancel", "identity", "recall", "verify-failure", "return-failure", "close-failure"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runObjectWire(t, minor, mode, "", false) })
		}
	}
}
func TestMITObjectWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"ok", "hole", "osd-id", "osd-drop", "recall", "verify-failure"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%t/%s", minor, security, secure, mode), func(t *testing.T) { runObjectWire(t, minor, mode, security, secure) })
				}
			}
		}
	}
}
