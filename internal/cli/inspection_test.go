package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
)

func TestInspectionCommandsLegacyAndOfflineOptIn(t *testing.T) {
	sh, root, out := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	sh.Session.AutoUID, sh.Session.AutoUIDScan = true, true
	sh.Session.Client.Auth.UID = 777
	before := sh.Session.Client.Auth
	for _, command := range []string{"info --json", "capabilities file --json", "stat --offline file", "ls --offline"} {
		out.Reset()
		if _, err := sh.Execute(context.Background(), command); err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		if !sh.Session.AutoUID || !sh.Session.AutoUIDScan || !reflect.DeepEqual(before, sh.Session.Client.Auth) {
			t.Fatal("inspection changed caller identity", command)
		}
		if command == "ls --offline" {
			if !strings.Contains(out.String(), "[unknown]") {
				t.Fatal(out.String())
			}
		} else {
			var value map[string]any
			if err := json.Unmarshal(out.Bytes(), &value); err != nil {
				t.Fatal(command, err)
			}
			if command == "stat --offline file" && value["offline"] != "unknown" {
				t.Fatal(value)
			}
		}
	}
	if err := sh.capabilities(context.Background(), []string{"missing"}); err == nil {
		t.Fatal("missing path succeeded")
	}
	if !sh.Session.AutoUID || !sh.Session.AutoUIDScan || !reflect.DeepEqual(before, sh.Session.Client.Auth) {
		t.Fatal("failed inspection changed caller identity")
	}
	out.Reset()
	if _, err := sh.Execute(context.Background(), "stat file"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"offline"`) {
		t.Fatal("ordinary stat added optional metadata", out.String())
	}
	data, err := os.ReadFile(filepath.Join(root, "file"))
	if err != nil || string(data) != "unchanged" {
		t.Fatal(string(data), err)
	}
}

func TestOfflineDisplayDoesNotSuggestUnknownIsOnline(t *testing.T) {
	var out bytes.Buffer
	sh := &Shell{Out: &out}
	entries := []nfs.Entry{}
	for _, state := range []nfs.OfflineState{nfs.OfflineOnline, nfs.OfflineOffline, nfs.OfflineUnknown} {
		entries = append(entries, nfs.Entry{Name: string(state), Node: nfs.Node{Attr: nfs.Attr{Type: 1, Offline: state}}})
	}
	if err := sh.printEntries(entries); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"online [online]", "offline [offline]", "unknown [unknown]"} {
		if !strings.Contains(out.String(), marker) {
			t.Fatal(out.String())
		}
	}
}

func TestInspectionUsageRejectsBeforeSession(t *testing.T) {
	s := &Shell{}
	ctx := context.Background()
	for _, err := range []error{s.info(ctx, []string{"extra"}), s.capabilities(ctx, []string{"a", "b"}), s.statWithOffline(ctx, []string{"--offline"}), s.listWithOffline(ctx, []string{"--offline", "--offline"}), s.listWithOffline(ctx, []string{"--offline", "a", "b"})} {
		if err == nil {
			t.Fatal("invalid inspection syntax accepted")
		}
	}
	if _, _, err := inspectionPath([]string{"--bad"}, "--json", false); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if p, found, err := inspectionPath([]string{"--offline", "--", "--bad"}, "--offline", true); err != nil || !found || p != "--bad" {
		t.Fatal(p, found, err)
	}
}
