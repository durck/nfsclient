package nfs

import (
	"context"
	"errors"
	"math"
	"testing"
)

func TestNLMRangeEncoding(t *testing.T) {
	for _, tc := range []struct {
		version        uint32
		offset, length uint64
		bad            bool
	}{
		{1, 0, LockToEOF, false}, {4, 0, LockToEOF, false},
		{1, math.MaxUint32, 1, false}, {1, math.MaxUint32, 2, true},
		{1, 1 << 32, LockToEOF, true}, {4, 1 << 33, 7, false},
		{1, 0, 1 << 32, true},
		{4, math.MaxInt64, 1, false}, {4, math.MaxInt64, 2, true},
		{4, 1 << 63, LockToEOF, true}, {4, 0, 0, true},
	} {
		err := validateNLMRange(tc.version, tc.offset, tc.length)
		if (err != nil) != tc.bad {
			t.Fatalf("%+v: %v", tc, err)
		}
		if tc.bad {
			continue
		}
		var e encoder
		encodeNLMRange(&e, tc.version, tc.offset, tc.length)
		d := &decoder{b: e}
		var offset, length uint64
		if tc.version == 1 {
			offset, length = uint64(d.u32()), uint64(d.u32())
		} else {
			offset, length = d.u64(), d.u64()
		}
		want := tc.length
		if want == LockToEOF {
			want = 0
		}
		if offset != tc.offset || length != want || d.err != nil || len(d.b) != 0 {
			t.Fatalf("wire range %d %d", offset, length)
		}
	}
}

func TestNLMTestReply(t *testing.T) {
	cookie := []byte("unique-test-cookie")
	for _, version := range []uint32{1, 4} {
		build := func(status uint32) encoder {
			var e encoder
			e.opaque(cookie)
			e.u32(status)
			if status == 1 {
				e.u32(1)
				e.u32(123)
				e.opaque([]byte{0xff, 0, 1})
				encodeNLMRange(&e, version, 2, LockToEOF)
			}
			return e
		}
		for status := uint32(0); status <= 10; status++ {
			conflict, err := decodeNLMTest(&decoder{b: build(status)}, version, cookie, true, 0, LockToEOF)
			switch status {
			case 0:
				if err != nil || conflict != nil {
					t.Fatalf("free: %v %v", conflict, err)
				}
			case 1:
				if err != nil || conflict == nil || !conflict.Write || conflict.SVID != 123 || conflict.Offset != 2 || conflict.Length != LockToEOF {
					t.Fatalf("conflict: %+v %v", conflict, err)
				}
			default:
				if err == nil || conflict != nil {
					t.Fatalf("status %d accepted", status)
				}
				if status <= 5 || version == 4 && status <= 9 {
					if !errors.Is(err, NLMStatus(status)) {
						t.Fatalf("lost NLM status: %v", err)
					}
				}
			}
		}
		valid := build(1)
		for n := 0; n < len(valid); n++ {
			if _, err := decodeNLMTest(&decoder{b: valid[:n]}, version, cookie, true, 0, LockToEOF); err == nil {
				t.Fatalf("accepted truncation %d", n)
			}
		}
		for _, bad := range []encoder{append(build(0), 0), append(build(1), 0), append(build(4), 0)} {
			if _, err := decodeNLMTest(&decoder{b: bad}, version, cookie, true, 0, LockToEOF); err == nil {
				t.Fatal("accepted trailing bytes")
			}
		}
		if _, err := decodeNLMTest(&decoder{b: build(0)}, version, []byte("wrong"), true, 0, LockToEOF); err == nil {
			t.Fatal("accepted wrong cookie")
		}
		if _, err := decodeNLMTest(&decoder{b: valid}, version, cookie, true, 0, 1); err == nil {
			t.Fatal("accepted non-overlapping holder")
		}
		bad := build(1)
		// The holder's exclusive discriminator follows the cookie and status.
		pos := 4 + (len(cookie)+3)/4*4 + 4
		bad[pos+3] = 2
		if _, err := decodeNLMTest(&decoder{b: bad}, version, cookie, true, 0, LockToEOF); err == nil {
			t.Fatal("accepted invalid boolean")
		}
		bad[pos+3] = 0
		if _, err := decodeNLMTest(&decoder{b: bad}, version, cookie, false, 0, LockToEOF); err == nil {
			t.Fatal("accepted read/read conflict")
		}
	}
}

func TestNLMTestPreflight(t *testing.T) {
	for _, c := range []*Client{
		{version: "4.0"}, {version: "4.1"}, {version: "4.2"},
		{version: "3", config: &Config{Security: "krb5"}},
		{version: "3", config: &Config{TLS: TLSConfig{Enabled: true}}},
		{version: "3"},
	} {
		if _, err := c.TestLock(context.Background(), []byte("fh"), true, 0, LockToEOF); err == nil {
			t.Fatal("unsupported client accepted")
		}
	}
	for _, version := range []uint32{1, 4} {
		for proc := uint32(0); proc <= 23; proc++ {
			if udpReadOnly(nlmProgram, version, proc) != (proc == 1) {
				t.Fatalf("unsafe NLM retry allowlist v%d proc%d", version, proc)
			}
		}
	}
}
