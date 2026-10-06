package nfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/krbconfig"
)

func TestKerberosSplitConfigAuthenticationAndChangedRenewal(t *testing.T) {
	for _, fault := range []string{"included-file", "directory-member", "reconnect"} {
		t.Run(fault, func(t *testing.T) {
			k, key := autoCredentials(t)
			original, err := os.ReadFile(k.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			parts := filepath.Join(filepath.Dir(k.ConfigFile), "parts")
			if err := os.Mkdir(parts, 0700); err != nil {
				t.Fatal(err)
			}
			child := filepath.Join(parts, "realm.conf")
			if err := os.WriteFile(child, original, 0600); err != nil {
				t.Fatal(err)
			}
			root := "includedir " + parts + "\n[capaths]\n NFS.TEST = {\n OTHER.TEST = .\n }\n"
			if err := os.WriteFile(k.ConfigFile, []byte(root), 0600); err != nil {
				t.Fatal(err)
			}
			p := &autoPeer{t: t, keytab: key, target: "4.2"}
			port, stop := p.listen()
			defer stop()
			c, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "auto", Security: "krb5p", Kerberos: k, NFSPort: port, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.config.Kerberos.configSnapshot == nil || !strings.Contains(c.nfs.kerberos.config.configSnapshot.Text(), "[capaths]") {
				t.Fatal("snapshot lost")
			}
			if fault == "directory-member" {
				if err := os.WriteFile(filepath.Join(parts, "new.conf"), []byte("[realms]\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(child, append(original, []byte("\n# changed selected input\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "reconnect" {
				fresh, e := c.Reconnect(context.Background())
				err = e
				if fresh != nil {
					fresh.Close()
					t.Fatal("changed policy reconnected")
				}
			} else {
				c.nfs.mu.Lock()
				c.nfs.gss.renewAt = time.Now().Add(-time.Second)
				c.nfs.mu.Unlock()
				_, err = c.GetAttr(context.Background(), []byte("root"))
			}
			if !errors.Is(err, krbconfig.ErrChanged) {
				t.Fatalf("changed dependency adopted: %v", err)
			}
			c.Close()
			stop()
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.init != 1 {
				t.Fatalf("changed configuration reached new GSS authentication: %d", p.init)
			}
			if p.accepted != p.closed {
				t.Fatalf("leaked connection %d/%d", p.accepted, p.closed)
			}
		})
	}
}

func TestKerberosRecoveryProfileBindsIncludes(t *testing.T) {
	dir := t.TempDir()
	root, child := filepath.Join(dir, "root"), filepath.Join(dir, "child")
	if err := os.WriteFile(root, []byte("include "+child), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("[libdefaults]\n default_realm = HOME\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Host: "server.test", Version: "4.2", Security: "krb5p", Kerberos: KerberosConfig{ConfigFile: root, Principal: "user@HOME", SPN: "nfs/server.test"}}
	before, err := lockProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := krbconfig.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pinned := cfg
	pinned.Kerberos.configSnapshot = snapshot
	if err := os.WriteFile(child, []byte("[libdefaults]\n default_realm = OTHER\n"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := lockProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("recovery identity ignored included policy")
	}
	if _, err := lockProfile(pinned); !errors.Is(err, krbconfig.ErrChanged) {
		t.Fatalf("pinned recovery silently adopted policy: %v", err)
	}
}
