package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
)

func TestAccessCommandPinsIdentity(t *testing.T) {
	sh, root, out := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	s := sh.Session
	s.AutoUID, s.AutoUIDScan = true, true
	auth := s.Client.Auth
	auth.UID, auth.GID, auth.Groups = 31337, 31338, []uint32{42}
	s.Client.Auth = auth
	for _, cmd := range []string{"access file", "access file --json"} {
		out.Reset()
		if _, err := sh.Execute(context.Background(), cmd); err != nil {
			t.Fatal(err)
		}
		if !s.AutoUID || !s.AutoUIDScan || !reflect.DeepEqual(auth, s.Client.Auth) {
			t.Fatal("inspection changed identity")
		}
		if strings.Contains(cmd, "--json") {
			var r struct {
				nfs.AccessReport
				Actions map[string]string `json:"actions"`
			}
			if err := json.Unmarshal(out.Bytes(), &r); err != nil || !r.Available || len(r.Actions) != 6 || r.Identity != s.Client.Identity() {
				t.Fatalf("%s %v", out, err)
			}
		} else if !strings.Contains(out.String(), "Server observation") {
			t.Fatal(out.String())
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "file"))
	if err != nil || string(data) != "preserved" {
		t.Fatal(string(data), err)
	}
	for _, cmd := range []string{"access", "access a b", "access --bad file"} {
		if _, err := sh.Execute(context.Background(), cmd); err == nil {
			t.Fatal("accepted", cmd)
		}
	}
}
