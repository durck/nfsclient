package nfs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoveryListingEvidence(t *testing.T) {
	for _, depth := range []int{1, 3} {
		c, _ := discoveryPeer(t)
		o := DefaultDiscoveryOptions()
		o.MaxDepth = depth
		r, err := c.Discover(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		entries := map[string]DiscoveredExport{}
		for _, e := range r.Entries {
			entries[e.Path] = e
		}
		root := entries["/"]
		if root.ListedEntries == nil || *root.ListedEntries != 5 || root.ListingComplete == nil || !*root.ListingComplete {
			t.Fatalf("root evidence: %+v", root)
		}
		data := entries["/data"]
		if depth == 1 {
			if data.ListedEntries != nil || data.ListingComplete != nil || !strings.Contains(data.ListingDescription(), "unknown") {
				t.Fatalf("unvisited directory claimed listing: %+v", data)
			}
		} else if data.ListedEntries == nil || *data.ListedEntries != 0 || data.ListingComplete == nil || !*data.ListingComplete || !strings.HasPrefix(data.ListingDescription(), "empty") {
			t.Fatalf("empty directory missing evidence: %+v", data)
		}
		for _, name := range []string{"/denied", "/secure", "/remote"} {
			e := entries[name]
			if e.ListedEntries != nil || e.ListingComplete != nil || strings.HasPrefix(e.ListingDescription(), "empty") {
				t.Fatalf("unobserved %s marked empty: %+v", name, e)
			}
		}
	}
}

func TestDiscoveryPartialListingNeverClaimsEmpty(t *testing.T) {
	c, _ := discoveryPeer(t)
	o := DefaultDiscoveryOptions()
	o.MaxEntries = 3
	r, err := c.Discover(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	e := r.Entries[0]
	if e.ListedEntries == nil || *e.ListedEntries != 2 || e.ListingComplete == nil || *e.ListingComplete || !strings.HasPrefix(e.ListingDescription(), "incomplete") {
		t.Fatalf("partial evidence: %+v", e)
	}
	b, err := json.Marshal(e)
	if err != nil || !strings.Contains(string(b), `"listing_complete":false`) {
		t.Fatalf("JSON lost false: %s %v", b, err)
	}
	zero, complete := 0, true
	e.ListedEntries, e.ListingComplete = &zero, &complete
	b, err = json.Marshal(e)
	if err != nil || !strings.Contains(string(b), `"listed_entries":0`) {
		t.Fatalf("JSON lost zero: %s %v", b, err)
	}
}
