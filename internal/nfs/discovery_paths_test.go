package nfs

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func knownPathPeer(t *testing.T, list bool, denyRootAttrs ...bool) (*Client, *[]string) {
	t.Helper()
	current := "root"
	var lookups []string
	v := peer4WithHandle(t, 0, func(op uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch op {
		case 15:
			name := d.str()
			lookups = append(lookups, current+"/"+name)
			switch name {
			case "secure":
				return nil, 10016, nil
			case "remote":
				return nil, 10019, nil
			case "missing":
				return nil, 2, nil
			}
			current = name
		case 10:
			e.opaque([]byte(current))
		case 9:
			readBitmap4(d)
			if current == "root" && len(denyRootAttrs) > 0 && denyRootAttrs[0] {
				return nil, 13, nil
			}
			bitmap4(&e, 1)
			var a encoder
			typ := uint32(2)
			if current == "link" {
				typ = 5
			}
			a.u32(typ)
			e.opaque(a)
		case 3:
			d.u32()
			e.u32(3)
			e.u32(3)
		case 33:
			if d.str() != "secure" {
				return nil, 0, fmt.Errorf("wrong SECINFO name")
			}
			e.u32(1)
			e.u32(6)
			e.opaque(krb5OID)
			e.u32(0)
			e.u32(3)
		case 26:
			d.u64()
			d.take(8)
			d.u32()
			d.u32()
			readBitmap4(d)
			if !list {
				return nil, 13, nil
			}
			e.u64(0)
			if current == "root" {
				e.u32(1)
				e.u64(1)
				e.str("hidden")
				bitmap4(&e, 1, 19)
				var a encoder
				a.u32(2)
				a.opaque([]byte("hidden"))
				e.opaque(a)
			}
			e.u32(0)
			e.u32(1)
		default:
			return nil, 0, fmt.Errorf("unexpected discovery operation (write, referral or symlink follow): %d", op)
		}
		return e, 0, nil
	}, func(fh []byte) error { current = string(fh); return nil })
	return v.c, &lookups
}

func TestDiscoveryKnownPathsSurviveDeniedReadDir(t *testing.T) {
	c, lookups := knownPathPeer(t, false)
	c.Auth = Auth{UID: 123, GID: 456, Groups: []uint32{789}}
	c.security = "krb5i"
	before := c.Auth
	o := DefaultDiscoveryOptions()
	o.Paths = []string{"/missing", "/secure", "/remote", "/hidden/data", "/link/child"}
	r, err := c.Discover(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{"/missing": "not_found", "/secure": "wrong_security", "/remote": "referral", "/hidden/data": "accessible", "/link/child": "error"} {
		i := r.index(p)
		if i < 0 || r.Entries[i].Access != want {
			t.Fatalf("%s: %+v", p, r)
		}
	}
	secure := r.Entries[r.index("/secure")]
	if !secure.SecurityBoundary || !reflect.DeepEqual(secure.AdvertisedSecurity, []string{"krb5p"}) || !r.Entries[r.index("/remote")].Referral {
		t.Fatalf("missing boundary evidence: %+v", r)
	}
	if strings.Contains(strings.Join(*lookups, ","), "link/child") {
		t.Fatal("followed symlink")
	}
	if r.Complete || r.Entries[0].Traversal != "denied" {
		t.Fatalf("READDIR denial hidden: %+v", r)
	}
	if !reflect.DeepEqual(before, c.Auth) || c.Security() != "krb5i" || string(c.v4.root) != "root" {
		t.Fatal("changed identity, security or root")
	}
	data, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(data), `"sources":["known_path"]`) || !strings.Contains(string(data), `"advertised_security":["krb5p"]`) {
		t.Fatalf("JSON evidence missing: %s %v", data, err)
	}
}

func TestDiscoveryKnownPathProvenanceAndBudget(t *testing.T) {
	c, lookups := knownPathPeer(t, true)
	o := DefaultDiscoveryOptions()
	o.Paths = []string{"/hidden", "/hidden/", "/"}
	r, err := c.Discover(context.Background(), o)
	if err != nil || len(*lookups) != 1 || len(r.Entries) != 2 {
		t.Fatalf("dedup: %+v %v %v", r, *lookups, err)
	}
	if !reflect.DeepEqual(r.Entries[1].Sources, []string{"known_path", "namespace"}) || !reflect.DeepEqual(r.Entries[0].Sources, []string{"namespace", "known_path"}) {
		t.Fatal(r.Entries)
	}
	c, lookups = knownPathPeer(t, false)
	o.MaxEntries = 3
	o.Paths = []string{"/a/b/c", "/other"}
	r, err = c.Discover(context.Background(), o)
	if err != nil || r.Complete || len(*lookups) != 2 || len(r.Entries) > 3 || r.Entries[1].Access != "entry_limit" {
		t.Fatalf("budget: %+v %v %v", r, *lookups, err)
	}
}

func TestDiscoveryRejectsInvalidKnownPathsBeforeRPC(t *testing.T) {
	for _, p := range []string{"relative", "/a/../b", "/a\x00b", "/" + strings.Repeat("a/", 65), "/" + strings.Repeat("a", 4096)} {
		c := &Client{}
		o := DefaultDiscoveryOptions()
		o.Paths = []string{p}
		if _, err := c.Discover(context.Background(), o); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
}

func TestDiscoveryRegularFileExecuteReadAndFreshEvidence(t *testing.T) {
	v := peer4(t, 0, func(op uint32, d *decoder) (encoder, Status, error) {
		if op != 3 || d.u32() != 33 {
			return nil, 0, fmt.Errorf("expected READ|EXECUTE ACCESS")
		}
		var e encoder
		e.u32(33)
		e.u32(32)
		return e, 0, nil
	})
	yes := true
	e := DiscoveredExport{Access: "wrong_security", Error: "old failure", CanList: &yes, CanTraverse: &yes, SecurityBoundary: true, Referral: true, AdvertisedSecurity: []string{"krb5p"}, Traversal: "wrong_security"}
	v.c.discoveryAccess(context.Background(), Node{Handle: []byte("file"), Attr: Attr{Type: 1}}, &e)
	if e.Access != "accessible" || e.Error != "" || e.SecurityBoundary || e.Referral || len(e.AdvertisedSecurity) != 0 || e.Traversal != "" || e.CanList != nil || e.CanTraverse != nil {
		t.Fatalf("stale or incorrect ACCESS evidence: %+v", e)
	}
}

func TestDiscoveryUnavailableRootDoesNotLookupEmptyHandle(t *testing.T) {
	calls := 0
	v := peer4(t, 0, func(op uint32, d *decoder) (encoder, Status, error) {
		calls++
		if op != 9 {
			return nil, 0, fmt.Errorf("lookup attempted without root handle: %d", op)
		}
		readBitmap4(d)
		return nil, 13, nil
	})
	v.root = nil
	o := DefaultDiscoveryOptions()
	o.Paths = []string{"/known", "/"}
	r, err := v.c.Discover(context.Background(), o)
	if err != nil || calls != 1 || len(r.Entries) != 2 || r.Entries[1].Access != "denied" || !strings.Contains(r.Entries[1].Error, "server root unavailable") {
		t.Fatalf("%+v %v calls=%d", r, err, calls)
	}
	c, lookups := knownPathPeer(t, false, true)
	o.Paths = []string{"/known"}
	r, err = c.Discover(context.Background(), o)
	if err != nil || len(*lookups) != 1 || len(r.Entries) != 2 || r.Entries[1].Access != "accessible" {
		t.Fatalf("known path suppressed despite valid root handle: %+v %v", r, err)
	}
}

func TestDiscoveryKnownLegacyLongestExportAndUnknownMount(t *testing.T) {
	var mounts, lookups []string
	c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
		var e encoder
		if prog == mountProgram {
			switch proc {
			case 5:
				for _, p := range []string{"/data", "/data/nested"} {
					e.u32(1)
					e.str(p)
					e.u32(0)
				}
				e.u32(0)
			case 1:
				p := d.str()
				mounts = append(mounts, p)
				if p == "/unknown/file" {
					e.u32(13)
				} else {
					e.u32(0)
					e.opaque([]byte(p))
					e.u32(1)
					e.u32(1)
				}
			case 3:
				d.str()
			default:
				return nil, fmt.Errorf("unexpected mount operation %d", proc)
			}
		} else {
			switch proc {
			case 1:
				d.opaque(64)
				e.u32(0)
				compatibilityAttr(&e)
			case 3:
				parent, name := string(d.opaque(64)), d.str()
				lookups = append(lookups, parent+"/"+name)
				e.u32(0)
				e.opaque([]byte(name))
				e.u32(1)
				compatibilityAttr(&e)
				e.u32(0)
			case 4:
				d.opaque(64)
				requested := d.u32()
				e.u32(0)
				e.u32(0)
				e.u32(requested)
			default:
				return nil, fmt.Errorf("unexpected NFS operation %d", proc)
			}
		}
		return e, nil
	})
	o := DefaultDiscoveryOptions()
	o.Paths = []string{"/data/nested/file", "/data/nested", "/unknown/file"}
	r, err := c.Discover(context.Background(), o)
	if err != nil || r.Complete || len(c.mounted) != 0 {
		t.Fatalf("report: %+v %v", r, err)
	}
	if !reflect.DeepEqual(lookups, []string{"/data/nested/file"}) || mounts[0] != "/data/nested" {
		t.Fatalf("did not use longest export: %v %v", mounts, lookups)
	}
	if !reflect.DeepEqual(r.Entries[r.index("/data/nested")].Sources, []string{"known_path", "mountd"}) {
		t.Fatal(r.Entries)
	}
	if !strings.Contains(r.Entries[r.index("/unknown/file")].Error, "cannot infer a hidden mount root") {
		t.Fatal(r.Entries)
	}
}
