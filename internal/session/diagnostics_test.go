package session

import (
	"context"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
)

func TestHandleRejectsTrailingSlashBeforeResolution(t *testing.T) {
	// An unconnected client must not perform LOOKUP/READLINK for link/.
	s := &Session{Client: &nfs.Client{}, Export: "/data", CWD: "/", Root: nfs.Node{Handle: []byte{1}, Attr: nfs.Attr{Type: 2}}}
	for _, name := range []string{"link/", "directory/link/", "", "bad\x00name"} {
		if _, err := s.HandlePath(context.Background(), name); err == nil || !strings.Contains(err.Error(), "exact path") {
			t.Fatalf("accepted ambiguous handle path %q: %v", name, err)
		}
	}
	for _, name := range []string{"/", "."} {
		if r, err := s.HandlePath(context.Background(), name); err != nil || r.Handle != "01" {
			t.Fatalf("root handle %q: %+v %v", name, r, err)
		}
	}
}
