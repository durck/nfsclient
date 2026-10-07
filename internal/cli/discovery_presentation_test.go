package cli

import (
	"bytes"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
)

func TestDiscoveryPresentationExplainsEvidence(t *testing.T) {
	zero, done := 0, true
	r := nfs.DiscoveryReport{Version: "4.1", Identity: "test", Entries: []nfs.DiscoveredExport{
		{Export: nfs.Export{Path: "/empty"}, Sources: []string{"namespace"}, ListedEntries: &zero, ListingComplete: &done},
		{Export: nfs.Export{Path: "/unknown"}, Sources: []string{"known_path"}, Traversal: "depth_limit"},
		{Export: nfs.Export{Path: "/protected"}, Access: "wrong_security", Traversal: "wrong_security"},
	}}
	var out bytes.Buffer
	s := &Shell{Out: &out}
	if err := s.printDiscovery(r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"empty (READDIR", "contents unknown", "depth limit reached", "requires a different security", "Partial discovery", "mountd = advertised", "? = unknown"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q: %s", want, &out)
		}
	}
	out.Reset()
	if err := s.printDiscovery(nfs.DiscoveryReport{Complete: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "does not prove") {
		t.Fatal(out.String())
	}
}
