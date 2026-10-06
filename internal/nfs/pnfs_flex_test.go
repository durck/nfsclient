package nfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

func flexTestBody(mirrors, width int, distinctStates ...bool) encoder {
	var e encoder
	if width == 1 {
		e.u64(0)
	} else {
		e.u64(64)
	}
	e.u32(uint32(mirrors))
	for mirror := 0; mirror < mirrors; mirror++ {
		e.u32(uint32(width))
		for stripe := 0; stripe < width; stripe++ {
			id := mirror*width + stripe + 1
			e = append(e, bytes.Repeat([]byte{byte(id)}, 16)...)
			e.u32(uint32(mirror+1) * 100)
			if len(distinctStates) > 0 && distinctStates[0] {
				e = append(e, bytes.Repeat([]byte{byte(id)}, 16)...)
			} else {
				e = append(e, make([]byte, 16)...)
			}
			e.u32(1)
			e.opaque([]byte(fmt.Sprintf("ds%d", id)))
			e.str(fmt.Sprint(100 + id))
			e.str(fmt.Sprint(200 + id))
		}
	}
	e.u32(3)
	e.u32(0)
	return e
}

func flexTestDevice(id int) encoder {
	var e encoder
	e.u32(1)
	e.str("tcp")
	e.str(fmt.Sprintf("192.0.2.%d.8.1", id))
	e.u32(1)
	for _, n := range []uint32{3, 0, 128, 128, 0} {
		e.u32(n)
	}
	return e
}

func TestFlexLayoutDecoderAndMapping(t *testing.T) {
	for _, mirrors := range []int{1, 2, 8} {
		for _, width := range []int{1, 3, 8} {
			t.Run(fmt.Sprintf("m%d/w%d", mirrors, width), func(t *testing.T) {
				d := &decoder{b: flexTestBody(mirrors, width)}
				l := decodeFlexLayout(d)
				if d.err != nil || len(l.selected) != width {
					t.Fatal(d.err)
				}
				for _, offset := range []uint64{0, 1, 63, 64, 65, 127, 128, 191, 192, math.MaxInt64} {
					ds, left := l.position(offset)
					stripe := 0
					wantLeft := uint64(math.MaxUint64) - offset
					if width != 1 {
						stripe = int(offset / 64 % uint64(width))
						wantLeft = 64 - offset%64
					}
					wantID := (mirrors-1)*width + stripe + 1
					if ds.device[0] != byte(wantID) || left != wantLeft || ds.owner != fmt.Sprint(100+wantID) || ds.group != fmt.Sprint(200+wantID) {
						t.Fatal(offset, ds, left, wantID, wantLeft)
					}
				}
			})
		}
	}
	good := flexTestBody(1, 1)
	for n := 0; n < len(good); n++ {
		d := &decoder{b: good[:n]}
		decodeFlexLayout(d)
		if d.err == nil {
			t.Fatal("truncation accepted", n)
		}
	}
	for _, mode := range []string{"mirrors-zero", "mirrors-large", "width-zero", "width-large", "stripe-nonzero", "stripe-zero", "stripe-overflow", "flags", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			b := append(encoder(nil), good...)
			switch mode {
			case "mirrors-zero":
				binary.BigEndian.PutUint32(b[8:], 0)
			case "mirrors-large":
				binary.BigEndian.PutUint32(b[8:], 9)
			case "width-zero":
				binary.BigEndian.PutUint32(b[12:], 0)
			case "width-large":
				binary.BigEndian.PutUint32(b[12:], 65)
			case "stripe-nonzero":
				binary.BigEndian.PutUint64(b, 64)
			case "stripe-zero":
				b = flexTestBody(1, 3)
				binary.BigEndian.PutUint64(b, 0)
			case "stripe-overflow":
				b = flexTestBody(1, 3)
				binary.BigEndian.PutUint64(b, math.MaxUint64)
			case "flags":
				binary.BigEndian.PutUint32(b[len(b)-8:], 16)
			case "trailing":
				b = append(b, 0)
			}
			d := &decoder{b: b}
			decodeFlexLayout(d)
			if d.err == nil {
				t.Fatal("invalid layout accepted")
			}
		})
	}
}

func TestFlexNumericIdentity(t *testing.T) {
	for _, s := range []string{"", "00", "01", "-1", "+1", " 1", "1 ", "root", "root@realm", "4294967296", "99999999999"} {
		if _, err := flexNumericID(s); err == nil {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"0", "1", "4294967295"} {
		if _, err := flexNumericID(s); err != nil {
			t.Fatal(s, err)
		}
	}
}

func TestFlexErrorStatusMapping(t *testing.T) {
	for _, tc := range []struct{ major, input, want uint32 }{
		{3, 13, 13}, {3, 10004, 10004}, {3, 10025, 5}, {4, 13, 13}, {4, 10025, 10025}, {4, 10021, 10021},
	} {
		v := &v4Client{recall: &layoutRecall{}}
		v.recordFlexError(&flexDS{major: tc.major, device: make([]byte, 16)}, 0, 10, Status(tc.input))
		if got := v.recall.flexErrors[0].status; got != tc.want {
			t.Errorf("v%d status %d mapped to %d, want %d", tc.major, tc.input, got, tc.want)
		}
	}
}

func TestFlexDeviceValidation(t *testing.T) {
	for _, mode := range []string{"valid", "paths-zero", "paths-large", "versions", "minor", "tight", "rsize", "v4-only", "handle", "unapproved", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			layoutD := &decoder{b: flexTestBody(1, 1)}
			ds := decodeFlexLayout(layoutD).selected[0]
			b := flexTestDevice(1)
			o := PNFSOptions{DataServers: map[string]string{"192.0.2.1:2049": "127.0.0.1:2049"}}
			switch mode {
			case "paths-zero":
				binary.BigEndian.PutUint32(b, 0)
			case "paths-large":
				binary.BigEndian.PutUint32(b, 9)
			case "versions":
				binary.BigEndian.PutUint32(b[len(b)-24:], 2)
			case "minor":
				binary.BigEndian.PutUint32(b[len(b)-16:], 1)
			case "tight":
				binary.BigEndian.PutUint32(b[len(b)-4:], 1)
			case "rsize":
				binary.BigEndian.PutUint32(b[len(b)-12:], 0)
			case "v4-only":
				binary.BigEndian.PutUint32(b[len(b)-20:], 4)
			case "handle":
				ds.handles[0] = make([]byte, 65)
			case "unapproved":
				o.DataServers = nil
			case "trailing":
				b = append(b, 0)
			}
			d := &decoder{b: b}
			decodeFlexDevice(d, ds, o)
			if (d.err == nil) != (mode == "valid" || mode == "unapproved") {
				t.Fatal(mode, d.err)
			}
			if mode == "unapproved" && len(ds.endpoints) != 0 {
				t.Fatal("unapproved path retained")
			}
		})
	}
	good := flexTestDevice(1)
	for n := 0; n < len(good); n++ {
		ds := &flexDS{handles: [][]byte{[]byte("f")}}
		d := &decoder{b: good[:n]}
		decodeFlexDevice(d, ds, PNFSOptions{})
		if d.err == nil {
			t.Fatal("truncated device", n)
		}
	}
}

func FuzzFlexLayout(f *testing.F) {
	f.Add([]byte(flexTestBody(1, 1)))
	f.Add([]byte(flexTestBody(2, 3)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		d := &decoder{b: b}
		l := decodeFlexLayout(d)
		if d.err == nil {
			if len(l.selected) == 0 {
				t.Fatal("no selected mirror")
			}
			l.position(math.MaxInt64)
		}
	})
}

func TestFlexCallbackTypeAndTruncation(t *testing.T) {
	fresh := func() *layoutRecall {
		return &layoutRecall{session: bytes.Repeat([]byte{1}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{2}, 16), layoutType: 4}
	}
	r := fresh()
	fileCall := callbackCall(r, 1, true)
	if _, err := r.callback(fileCall); err != nil || r.recalled {
		t.Fatal("FILE callback recalled Flex layout", err)
	}
	r = fresh()
	call := callbackCall(r, 1, true)
	binary.BigEndian.PutUint32(call[len(callbackCall(r, 1, false))+4:], 4)
	reply, err := r.callback(call)
	if err != nil || !r.recalled || binary.BigEndian.Uint32(reply[24:]) != 0 {
		t.Fatal("Flex callback refused", err)
	}
	for end := 0; end < len(call); end++ {
		r := fresh()
		if _, err := r.callback(call[:end]); err == nil || r.recalled || r.sequence != 0 {
			t.Fatal("truncated callback changed state", end, err)
		}
	}
}

func TestFlexSegmentRanges(t *testing.T) {
	for _, mode := range []string{"valid", "gap", "overlap", "wrong-type", "rw-no-read"} {
		t.Run(mode, func(t *testing.T) {
			var e encoder
			e.u32(0)
			e = append(e, bytes.Repeat([]byte{8}, 16)...)
			e.u32(2)
			for i := 0; i < 2; i++ {
				offset := uint64(i * 100)
				if i == 1 && mode == "gap" {
					offset++
				}
				if i == 1 && mode == "overlap" {
					offset--
				}
				e.u64(offset)
				e.u64(100)
				if mode == "rw-no-read" {
					e.u32(2)
				} else {
					e.u32(1)
				}
				if i == 1 && mode == "wrong-type" {
					e.u32(1)
				} else {
					e.u32(4)
				}
				body := flexTestBody(1, 3)
				if mode == "rw-no-read" {
					binary.BigEndian.PutUint32(body[len(body)-8:], 4)
				}
				e.opaque(body)
			}
			d := &decoder{b: e}
			_, layouts := decodeLayoutRange(d, 0, 200, 4)
			if (d.err == nil) != (mode == "valid" || mode == "rw-no-read") {
				t.Fatal(d.err)
			}
			if mode == "valid" {
				l, err := fileLayoutAt(layouts, 100)
				if err != nil || l != layouts[1] {
					t.Fatal(err)
				}
				ds, left := l.flex.position(100)
				if ds.device[0] != 2 || left != 28 {
					t.Fatal("stripe mapping reset at segment boundary", ds, left)
				}
			}
		})
	}
}
