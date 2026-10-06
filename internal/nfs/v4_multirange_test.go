package nfs

import "testing"

func TestLockRangesOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, al, b, bl uint64
		overlap      bool
	}{
		{0, 16, 16, 16, false}, {0, 16, 15, 16, true},
		{0, 1, 0, 1, true}, {0, 10, 2, 1, true},
		{0, LockToEOF, LockToEOF, LockToEOF, true},
		{0, 16, 16, LockToEOF, false},
		{LockToEOF - 16, 16, LockToEOF, LockToEOF, false},
		{LockToEOF - 16, 16, LockToEOF - 1, LockToEOF, true},
	} {
		if got := lockRangesOverlap(tc.a, tc.al, tc.b, tc.bl); got != tc.overlap {
			t.Errorf("%+v: %v", tc, got)
		}
		if got := lockRangesOverlap(tc.b, tc.bl, tc.a, tc.al); got != tc.overlap {
			t.Errorf("reverse %+v: %v", tc, got)
		}
	}
}

func TestMultiRangeUncertaintyWins(t *testing.T) {
	v := &v4Client{locks: map[uint64]*v4Lock{
		1: {info: LockInfo{ID: 1}, file: &v4Open{fh: []byte("file")}},
		2: {info: LockInfo{ID: 2, Uncertain: true}, file: &v4Open{fh: []byte("file")}},
	}}
	for range 50 {
		if got := v.lockFor([]byte("file")); got == nil || !got.info.Uncertain {
			t.Fatal("confirmed range hid uncertain state")
		}
	}
}
