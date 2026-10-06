package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// The same wire oracle exercises the public startup/mount/command path in
// process by default and the packaged executable in the release checkpoint.
func TestLegacyACLRelease(t *testing.T) {
	for _, version := range []uint32{2, 3} {
		for _, typ := range []uint32{1, 2} {
			for _, fault := range []string{"success", "lost-reply"} {
				t.Run(fmt.Sprintf("v%d/type%d/%s", version, typ, fault), func(t *testing.T) {
					port, peer := legacyACLListener(t, version, typ)
					base := []string{"127.0.0.1", "--nfs-version", strconv.Itoa(int(version)), "--nfs-port", strconv.Itoa(port), "--mount-port", strconv.Itoa(port), "--export", "/", "--uid", "32123", "--gid", "32124", "--groups", "32125", "--auto-uid=false", "--auto-escape=false", "--color", "never"}
					path := filepath.Join(t.TempDir(), "policy.json")
					quoted := strconv.Quote(filepath.ToSlash(path))
					if out, err := runKerberosCLI(t, append(append([]string{}, base...), "-c", "getacl target "+quoted)); err != nil {
						t.Fatalf("export: %v: %s", err, out)
					}
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var doc legacyACLDocument
					if err := json.Unmarshal(raw, &doc); err != nil || !reflect.DeepEqual(doc, legacyTestDocument(version, typ)) {
						t.Fatalf("exported policy mismatch: %s: %v", raw, err)
					}
					doc.Access[1].Perm = 3
					doc.Default = []legacyACLEntry{}
					raw, _ = json.Marshal(doc)
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					peer.mu.Lock()
					peer.fault = fault
					peer.mu.Unlock()
					out, err := runKerberosCLI(t, append(append([]string{}, base...), "-c", "setacl target "+quoted))
					if (err == nil) != (fault == "success") {
						t.Fatalf("import: %v: %s", err, out)
					}
					peer.mu.Lock()
					defer peer.mu.Unlock()
					if peer.sets != 1 || !reflect.DeepEqual(peer.doc, doc) {
						t.Fatalf("mutation repeated or policy differs: sets=%d policy=%+v", peer.sets, peer.doc)
					}
				})
			}
		}
	}
}
