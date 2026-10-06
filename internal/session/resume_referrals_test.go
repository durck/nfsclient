package session

import (
	"errors"
	"fmt"
	"nfsclient/internal/nfs"
	"slices"
	"testing"
)

func TestReferralMovedOnly(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nfs.Status(10019), true}, {fmt.Errorf("lookup: %w", nfs.Status(10019)), true},
		{errors.Join(nfs.Status(10019), nfs.Status(10019)), true},
		{errors.Join(nfs.Status(10019), errors.New("cleanup failed")), false},
		{errors.Join(nfs.Status(10019), nfs.Status(10011)), false},
		{nfs.ErrConnectionLost, false}, {nil, false},
	} {
		if got := referralMovedOnly(c.err); got != c.want {
			t.Fatal("wrong transition authority", c.err, got)
		}
	}
}

func TestReferralPathRemapping(t *testing.T) {
	for _, mode := range []string{"valid", "root-empty", "different-depth", "prefix", "unapproved", "substring", "dot", "too-deep"} {
		t.Run(mode, func(t *testing.T) {
			loc := nfs.FileLocations{Root: []string{"data", "junction"}, Locations: []nfs.FileLocation{{Servers: []string{"untrusted.test", "approved.test"}, Root: []string{"relocated"}}}}
			physical := []string{"data", "junction", "dir", "file"}
			approved := []ReferralTarget{{Server: "approved.test", Target: nfs.ReadReplica{Address: "127.0.0.1:2049", SPN: "nfs/approved.test"}}}
			want := []string{"relocated", "dir", "file"}
			switch mode {
			case "root-empty":
				loc.Root = nil
				want = append([]string{"relocated"}, physical...)
			case "different-depth":
				loc.Locations[0].Root = []string{"a", "b", "c"}
				want = []string{"a", "b", "c", "dir", "file"}
			case "prefix":
				loc.Root = []string{"another"}
			case "unapproved":
				approved[0].Server = "other.test"
			case "substring":
				physical[1] = "junction-extra"
			case "dot":
				loc.Locations[0].Root = []string{".."}
			case "too-deep":
				loc.Locations[0].Root = make([]string, 65)
				for i := range loc.Locations[0].Root {
					loc.Locations[0].Root[i] = "a"
				}
			}
			target, path, err := referralDestination(loc, physical, approved)
			valid := mode == "valid" || mode == "root-empty" || mode == "different-depth"
			if (err == nil) != valid {
				t.Fatal("wrong path decision", err)
			}
			if valid && (target != approved[0].Target || !slices.Equal(path, want)) {
				t.Fatal("wrong remapping")
			}
		})
	}
}
