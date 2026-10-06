package gssapi

import (
	stdcontext "context"
	"errors"
	"testing"
)

type persistentKeyringFixture struct {
	*keyringFixture
	uid              uint32
	calls            int
	missing, changed bool
}

func (f *persistentKeyringFixture) persistent(uid uint32) (int, error) {
	f.calls++
	if uid != f.uid || f.missing {
		return 0, errors.New("persistent anchor unavailable")
	}
	if f.changed && f.calls > 1 {
		return 8, nil
	}
	return 1, nil
}

func TestKEYRINGPersistentSelection(t *testing.T) {
	for _, mode := range []string{"success", "foreign-uid", "missing", "foreign-ring", "foreign-credential", "membership-change", "credential-change", "path-change", "anchor-change", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := &persistentKeyringFixture{keyringFixture: newKeyringFixture(mode), uid: 1000, missing: mode == "missing", changed: mode == "anchor-change"}
			f.descriptions[2] = kernelKeyDescription{"keyring", "_krb", 1000}
			selection, err := parseKeyringName("KEYRING:persistent:1000:cache")
			if err != nil {
				t.Fatal(err)
			}
			uid := uint32(1000)
			if mode == "foreign-uid" {
				uid = 2000
			}
			ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			cache, err := readKeyringSnapshot(ctx, f, selection, uid)
			if (err == nil) != (mode == "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			if mode == "success" && (cache.DefaultPrincipal.Realm != "NFS.TEST" || len(cache.Credentials) != 1 || f.calls != 2) {
				t.Fatal("wrong cache or missing repeated anchor check")
			}
			if (mode == "foreign-uid" || mode == "cancel") && f.calls != 0 {
				t.Fatal("foreign/canceled selection touched kernel anchor")
			}
		})
	}
}

func TestKEYRINGPersistentNeverUsesOrdinaryCollection(t *testing.T) {
	f := &persistentKeyringFixture{keyringFixture: newKeyringFixture("success"), uid: 1000}
	if _, err := readKeyringSnapshot(stdcontext.Background(), f, keyringSelection{"persistent", "1000", "cache"}, 1000); err == nil {
		t.Fatal("accepted _krb_collection instead of persistent _krb")
	}
}
