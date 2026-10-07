package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestHandleDiagnosticsOpaqueBytesAndIdentity(t *testing.T) {
	sh, root, out := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	n, _, err := sh.Session.Resolve(context.Background(), "file", false)
	if err != nil {
		t.Fatal(err)
	}
	sh.Session.AutoUID, sh.Session.AutoUIDScan = true, true
	sh.Session.Client.Auth = nfs.Auth{UID: 31337, GID: 31338, Groups: []uint32{42}}
	auth := sh.Session.Client.Auth
	for _, args := range [][]string{{"file", "--json"}, {"--json", "file"}, {"file"}} {
		out.Reset()
		if err := sh.handle(context.Background(), args); err != nil {
			t.Fatal(err)
		}
		if !sh.Session.AutoUID || !sh.Session.AutoUIDScan || !reflect.DeepEqual(auth, sh.Session.Client.Auth) {
			t.Fatal("handle changed caller identity")
		}
		if len(args) == 2 {
			var r struct {
				session.HandleReport
				Connection nfs.ConnectionInfo `json:"connection"`
			}
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			decoded, err := hex.DecodeString(r.Handle)
			if err != nil || !bytes.Equal(decoded, n.Handle) || r.Bytes != len(n.Handle) || r.Path != "/file" || r.Encoding != "hex" || r.Connection.Identity != sh.Session.Client.Identity() || r.Connection.Peer == "" || r.Connection.Version != "3" {
				t.Fatalf("%+v %v", r, err)
			}
		} else if !strings.Contains(out.String(), hex.EncodeToString(n.Handle)) || !strings.Contains(out.String(), "Connected peer:") {
			t.Fatal(out.String())
		}
	}
	out.Reset()
	// Include zeroes, non-UTF8 bytes and uneven XDR alignment: no memory dump or padding.
	sh.Session.Root.Handle = []byte{0, 1, 0xff, 0x80, 0}
	if err := sh.handle(context.Background(), []string{"--json"}); err != nil {
		t.Fatal(err)
	}
	var r session.HandleReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Handle != "0001ff8000" || r.Bytes != 5 || r.Path != "/" {
		t.Fatalf("%+v %v", r, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "file"))
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("content changed: %s %v", data, err)
	}
	if err := sh.handle(context.Background(), []string{"missing"}); err == nil {
		t.Fatal("missing path accepted")
	}
	if !sh.Session.AutoUID || !reflect.DeepEqual(auth, sh.Session.Client.Auth) {
		t.Fatal("failure changed identity")
	}
}

func TestDiagnosticUsageBeforeSession(t *testing.T) {
	sh := &Shell{}
	ctx := context.Background()
	for _, args := range [][]string{{"a", "b"}, {"--import", "abcd"}, {"--json", "--json"}, {"--bad"}} {
		if err := sh.handle(ctx, args); err == nil {
			t.Fatal("invalid handle arguments accepted", args)
		}
	}
	for _, args := range [][]string{{"path"}, {"--bad"}, {"--json", "--json"}} {
		if err := sh.mounts(ctx, args); err == nil {
			t.Fatal("invalid mounts arguments accepted", args)
		}
	}
}

func TestMountDiagnosticsUnavailableJSON(t *testing.T) {
	var out bytes.Buffer
	sh := &Shell{Session: &session.Session{Client: &nfs.Client{}}, Out: &out}
	if err := sh.mounts(context.Background(), []string{"--json"}); err == nil {
		t.Fatal("absent daemon accepted")
	}
	var r nfs.MountReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Available || r.Complete || r.Error == "" || r.Entries == nil {
		t.Fatalf("%+v %v", r, err)
	}
}
