package iscsi

import "testing"

func TestTargetApproval(t *testing.T) {
	for _, url := range []string{"iscsi://127.0.0.1:3260/iqn.2026-10.test:disk/0", "iscsi://[::1]:3260/iqn.2026-10.test:disk/255"} {
		if _, err := ParseTarget(url); err != nil {
			t.Fatal(err)
		}
	}
	for _, url := range []string{"iscsi://host:3260/iqn.2026-10.test:disk/0", "iscsi://127.0.0.1/iqn.2026-10.test:disk/0", "iscsi://127.0.0.1:0/iqn.2026-10.test:disk/0", "iscsi://127.0.0.1:3260/iqn.2026-10.test:disk/256", "iscsi://user@127.0.0.1:3260/iqn.2026-10.test:disk/0", "iscsi://127.0.0.1:3260/iqn.2026-10.test:disk/0?chap=x", "iscsi://127.0.0.1:3260/bad/0", "iscsi://127.0.0.1:3260/iqn.2026-10.test:disk/00", "iscsi://0.0.0.0:3260/iqn.2026-10.test:disk/0"} {
		if _, err := ParseTarget(url); err == nil {
			t.Fatalf("accepted unapproved target %q", url)
		}
	}
}

func TestNAAIdentity(t *testing.T) {
	good := []byte{0, 0x83, 0, 12, 1, 3, 0, 8, 0x50, 1, 2, 3, 4, 5, 6, 7}
	if id, err := decodeNAA(good); err != nil || len(id) != 8 {
		t.Fatalf("identity %x %v", id, err)
	}
	for _, data := range [][]byte{nil, good[:15], append(append([]byte{}, good...), 0), {0, 0x83, 0, 4, 1, 3, 0, 8}, {0, 0x83, 0, 0}} {
		if _, err := decodeNAA(data); err == nil {
			t.Fatalf("accepted malformed identity %x", data)
		}
	}
}

func TestNormalizedIQN(t *testing.T) {
	for _, name := range []string{"iqn.2026-10.a", "iqn.2026-10.test:disk", "iqn.1993-01.org.example:disk-0"} {
		if !ValidName(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"", "iqn", "iqn.2026-00.test:disk", "iqn.2026-13.test:disk", "iqn.2026-10.:disk", "iqn.2026-10.-test:disk", "iqn.2026-10.test..example:disk", "iqn.2026-10.test:", "iqn.2026-10.Test:disk", "iqn.2026-10.test:disk\x00"} {
		if ValidName(name) {
			t.Fatal("invalid IQN", name)
		}
	}
}

func TestWindowAndResidualBounds(t *testing.T) {
	v := &Volume{cmd: 0xfffffffe, expCmd: 0xfffffffe}
	var p pdu
	p.set(28, 0xfffffffe)
	p.set(32, 1)
	if err := v.window(p); err != nil {
		t.Fatal("valid wrapped window", err)
	}
	p.set(28, 0xffffffff)
	if err := v.window(p); err == nil {
		t.Fatal("unissued command accepted")
	}
	for _, tc := range []struct {
		n, want int
		under   bool
		res     uint32
		short   bool
		good    bool
	}{{16, 252, true, 236, true, true}, {512, 512, false, 0, false, true}, {511, 512, false, 0, false, false}, {511, 512, true, 1, false, false}, {16, 252, true, 235, true, false}, {16, 252, false, 236, true, false}, {513, 512, false, 0, false, false}} {
		if err := transferResult(tc.n, tc.want, tc.under, tc.res, tc.short); (err == nil) != tc.good {
			t.Fatal(tc, err)
		}
	}
}
