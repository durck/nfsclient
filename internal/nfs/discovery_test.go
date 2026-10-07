package nfs

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func discoveryPeer(t *testing.T) (*Client, *int) {
	t.Helper()
	reads := new(int)
	current := ""
	v := peer4WithHandle(t, 0, func(op uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch op {
		case 9:
			readBitmap4(d)
			bitmap4(&e, 1, 8, 20)
			var a encoder
			a.u32(2)
			a.u64(1)
			a.u64(0)
			a.u64(1)
			e.opaque(a)
		case 3:
			d.u32()
			e.u32(3)
			e.u32(3)
		case 26:
			*reads++
			d.u64()
			d.take(8)
			d.u32()
			d.u32()
			readBitmap4(d)
			e = append(e, make([]byte, 8)...)
			if current == "root" {
				for i, name := range []string{"data", "denied", "secure", "remote", "alias"} {
					e.u32(1)
					e.u64(uint64(i + 1))
					e.str(name)
					var a encoder
					if i >= 1 && i <= 3 {
						bitmap4(&e, 11)
						a.u32([]uint32{13, 10016, 10019}[i-1])
					} else {
						bitmap4(&e, 1, 8, 19, 20)
						a.u32(2)
						a.u64(2)
						a.u64(0)
						a.opaque([]byte("data"))
						a.u64(2)
					}
					e.opaque(a)
				}
			}
			e.u32(0)
			e.u32(1)
		default:
			return nil, 0, fmt.Errorf("unexpected discovery operation %d", op)
		}
		return e, 0, nil
	}, func(fh []byte) error { current = string(fh); return nil })
	return v.c, reads
}

func TestDiscoveryCleansMountAfterTimeout(t *testing.T) {
	unmounted := false
	mount := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
		var e encoder
		switch proc {
		case 5:
			e.u32(1)
			e.str("/data")
			e.u32(0)
			e.u32(0)
		case 1:
			d.str()
			e.u32(0)
			e.opaque([]byte("fh"))
			e.u32(1)
			e.u32(1)
		case 3:
			d.str()
			unmounted = true
		default:
			return nil, fmt.Errorf("unexpected mount proc %d", proc)
		}
		return e, nil
	})
	c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
		if proc != 1 {
			return nil, fmt.Errorf("unexpected NFS proc %d", proc)
		}
		d.opaque(64)
		time.Sleep(100 * time.Millisecond)
		var e encoder
		e.u32(0)
		compatibilityAttr(&e)
		return e, nil
	}, true)
	c.mount = mount.mount
	o := DefaultDiscoveryOptions()
	o.Timeout = 50 * time.Millisecond
	r, err := c.Discover(context.Background(), o)
	if err != nil || r.Complete || len(c.mounted) != 0 || !unmounted {
		t.Fatalf("cleanup: %+v %v %v %v", r, err, c.mounted, unmounted)
	}
}

func TestDiscoverLegacyDenialsAndMountTracking(t *testing.T) {
	for _, existing := range []bool{false, true} {
		unmounts := 0
		c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
			var e encoder
			if prog != mountProgram {
				return nil, fmt.Errorf("unexpected program %d", prog)
			}
			switch proc {
			case 5:
				for _, name := range []string{"/denied", "/secure"} {
					e.u32(1)
					e.str(name)
					e.u32(0)
				}
				e.u32(0)
			case 1:
				if d.str() == "/denied" {
					e.u32(13)
				} else {
					e.u32(0)
					e.opaque([]byte("secure"))
					e.u32(1)
					e.u32(390003)
				}
			case 3:
				d.str()
				unmounts++
			default:
				return nil, fmt.Errorf("unexpected MOUNT proc %d", proc)
			}
			return e, nil
		})
		if existing {
			c.mounted["/secure"] = true
		}
		r, err := c.Discover(context.Background(), DefaultDiscoveryOptions())
		if err != nil || r.Complete || len(r.Entries) != 2 || r.Entries[0].Access != "denied" || r.Entries[1].Access != "wrong_security" {
			t.Fatalf("%+v %v", r, err)
		}
		want := 1
		if existing {
			want = 0
		}
		if unmounts != want || c.mounted["/secure"] != existing {
			t.Fatal("changed existing mount tracking", c.mounted, unmounts)
		}
	}
}

func TestDiscoveryPaginationAndMalformedReplies(t *testing.T) {
	for _, mode := range []string{"pages", "budget", "verifier", "repeat", "name", "no-progress", "missing-handle", "file-budget"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			v := peer4(t, 0, func(op uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				if op == 15 {
					d.str()
					return nil, 13, nil
				}
				if op != 26 {
					return nil, 0, fmt.Errorf("unexpected op %d", op)
				}
				calls++
				cookie := d.u64()
				d.take(8)
				d.u32()
				d.u32()
				readBitmap4(d)
				if calls > 2 {
					return nil, 0, fmt.Errorf("unbounded pagination")
				}
				if calls == 2 && cookie != 1 {
					return nil, 0, fmt.Errorf("cookie not advanced: %d", cookie)
				}
				verifier := uint64(7)
				if mode == "verifier" && calls == 2 {
					verifier = 8
				}
				e.u64(verifier)
				if mode != "no-progress" {
					e.u32(1)
					e.u64(uint64(calls))
					name := fmt.Sprintf("dir%d", calls)
					if mode == "repeat" {
						name = "same"
					}
					if mode == "name" {
						name = "bad/path"
					}
					e.str(name)
					var a encoder
					if mode == "missing-handle" {
						bitmap4(&e, 1)
						a.u32(2)
					} else {
						bitmap4(&e, 1, 19)
						typ := uint32(2)
						if mode == "file-budget" {
							typ = 1
						}
						a.u32(typ)
						a.opaque([]byte(name))
					}
					e.opaque(a)
				}
				e.u32(0)
				if calls == 2 || mode == "missing-handle" {
					e.u32(1)
				} else {
					e.u32(0)
				}
				return e, 0, nil
			})
			limit := 10
			if mode == "budget" || mode == "file-budget" {
				limit = 1
			}
			entries, used, err := v.discoveryChildren(context.Background(), []byte("root"), limit)
			switch mode {
			case "pages":
				if err != nil || len(entries) != 2 || used != 2 {
					t.Fatalf("%+v %d %v", entries, used, err)
				}
			case "missing-handle":
				if err != nil || len(entries) != 1 || entries[0].Err != Status(13) {
					t.Fatalf("%+v %v", entries, err)
				}
			default:
				if err == nil {
					t.Fatal("expected partial/error result")
				}
				if strings.Contains(mode, "budget") && (used != 1 || calls != 1 || len(entries) != 1) {
					t.Fatalf("budget exceeded: %d/%d/%d", used, calls, len(entries))
				}
			}
		})
	}
}

func TestDiscoverNamespacePartialAndIdentity(t *testing.T) {
	c, reads := discoveryPeer(t)
	c.Auth = Auth{UID: 123, GID: 456, Groups: []uint32{789}}
	before := c.Auth
	o := DefaultDiscoveryOptions()
	o.MaxDepth = 3
	r, err := c.Discover(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || len(r.Entries) != 6 || *reads != 2 {
		t.Fatalf("report=%+v reads=%d", r, *reads)
	}
	states := map[string]string{}
	for _, e := range r.Entries {
		states[e.Path] = e.Access
	}
	if states["/denied"] != "denied" || states["/secure"] != "wrong_security" || states["/remote"] != "referral" || states["/data"] != "accessible" {
		t.Fatal(states)
	}
	if !reflect.DeepEqual(before, c.Auth) || string(c.v4.root) != "root" {
		t.Fatal("discovery changed session identity or root")
	}
	if !r.Entries[1].FilesystemBoundary {
		t.Fatal("missing filesystem boundary")
	}
}

func TestDiscoverLimitsAndCancellation(t *testing.T) {
	for _, limit := range []int{1, 3} {
		c, _ := discoveryPeer(t)
		o := DefaultDiscoveryOptions()
		o.MaxEntries = limit
		r, err := c.Discover(context.Background(), o)
		if err != nil || r.Complete || len(r.Entries) > limit || len(r.Issues) == 0 {
			t.Fatalf("%+v %v", r, err)
		}
	}
	c, reads := discoveryPeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := c.Discover(ctx, DefaultDiscoveryOptions())
	if err != nil || r.Complete || *reads != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDiscoveryErrorClassification(t *testing.T) {
	for status, want := range map[Status]string{13: "denied", 1: "denied", 2: "not_found", 10016: "wrong_security", 10019: "referral", 5: "error"} {
		if got := DiscoveryErrorStatus(fmt.Errorf("wrapped: %w", status)); got != want {
			t.Fatalf("%d: %s", status, got)
		}
	}
}
