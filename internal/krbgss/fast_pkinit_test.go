package gssapi

import (
	"bytes"
	stdcontext "context"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFASTPKINITSelection(t *testing.T) {
	armor := filepath.Join(t.TempDir(), "armor")
	for _, tc := range []struct {
		name, helper, armor string
		required, valid     bool
	}{
		{"combined", "", armor, true, true}, {"standalone", "", "", false, true},
		{"missing", "", "", true, false}, {"relative", "", "armor", true, false},
		{"unused", "", armor, false, false}, {"helper", armor, armor, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePKINITFAST(tc.helper, tc.armor, tc.required); (err == nil) != tc.valid {
				t.Fatalf("selection: %v", err)
			}
		})
	}
}

func TestFASTPKINITNativeGSS(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PUREGO_AS_NATIVE") != "1" {
		t.Skip("requires disposable MIT PKINIT KDC")
	}
	dir := os.Getenv("NFS_VIEWER_PUREGO_AS_FILES")
	cfg, err := os.ReadFile(os.Getenv("NFS_VIEWER_PUREGO_AS_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"integrity", "privacy"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Second)
			defer cancel()
			i, err := NewInitiator(WithConfig[Initiator](string(cfg)), WithRealm[Initiator]("NFS.TEST"), WithUsername[Initiator]("root"), WithNetworkContext(ctx), WithRequiredFAST("", filepath.Join(dir, "alice.ccache")), WithPKINIT("", PKINITFiles{Cert: filepath.Join(dir, "client.crt"), Key: filepath.Join(dir, "client.key"), CA: filepath.Join(dir, "ca.crt"), CRL: filepath.Join(dir, "clean.crl")}))
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			a, err := NewAcceptor(WithKeytab[Acceptor](filepath.Join(dir, "server.keytab")))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			flags := gssapi.ContextFlagMutual | gssapi.ContextFlagInteg | gssapi.ContextFlagConf
			token, more, err := i.Initiate("nfs/server.nfs.test", flags, nil)
			if err != nil || !more {
				t.Fatal("init", err)
			}
			reply, more, err := a.Accept(token)
			if err != nil || more {
				t.Fatal("accept", err)
			}
			_, more, err = i.Initiate("nfs/server.nfs.test", flags, reply)
			if err != nil || more || !i.Established() {
				t.Fatal("mutual", err)
			}
			data := []byte("FAST + certificate authenticated RPC payload")
			if mode == "integrity" {
				mic, err := i.MakeSignature(data)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.VerifySignature(data, mic); err != nil {
					t.Fatal(err)
				}
			} else {
				sealed, err := i.Seal(data)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := a.Unseal(sealed)
				if err != nil || !bytes.Equal(plain, data) {
					t.Fatal("privacy", err)
				}
			}
		})
	}
}
