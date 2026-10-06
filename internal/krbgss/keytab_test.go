package gssapi

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	upstream "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestKeytabErrorsDoNotExposeKeys(t *testing.T) {
	kt := keytab.New()
	for _, name := range []string{"alice", "bob"} {
		if err := kt.AddEntry(name, "NFS.TEST", "synthetic-test-only", time.Now(), 1, 18); err != nil {
			t.Fatal(err)
		}
	}
	marker := bytes.Repeat([]byte{0x6b}, 32)
	kt.Entries[0].Key.KeyValue = marker
	valid, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic.keytab")
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readKeytab(path); err != nil || len(got.Entries) != 2 {
		t.Fatal("valid keytab could not be loaded")
	}
	// The malformed second record must not expose the first, complete key.
	broken := valid[:len(valid)-1]
	if !bytes.Contains(broken, marker) {
		t.Fatal("invalid synthetic fixture")
	}
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(krb5KTName, "FILE:"+path)
	t.Setenv(krb5ClientKTName, "FILE:"+path)
	ticket := messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: types.NewPrincipalName(2, "nfs/server.test"), EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic opaque ticket")}}
	token, err := spnego.NewKRB5TokenAPREQ(&upstream.Client{Credentials: credentials.New("alice", "NFS.TEST")}, ticket, types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	apreq, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for name, load := range map[string]func() error{
		"direct":         func() error { _, err := readKeytab(path); return err },
		"ambient-server": func() error { _, err := loadKeytab(logr.Discard()); return err },
		"ambient-client": func() error { _, err := loadClientKeytab(logr.Discard()); return err },
		"initiator": func() error {
			_, err := NewInitiator(WithConfig[Initiator]("[libdefaults]\n default_realm = NFS.TEST\n"), WithRealm[Initiator]("NFS.TEST"), WithUsername[Initiator]("alice"), WithKeytab[Initiator](path))
			return err
		},
		"acceptor": func() error {
			acceptor, err := NewAcceptor(WithKeytab[Acceptor](path))
			if err != nil {
				return err
			}
			defer acceptor.Close()
			_, _, err = acceptor.Accept(apreq)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := load()
			if err == nil {
				t.Fatal("corrupt keytab accepted")
			}
			if bytes.Contains([]byte(err.Error()), marker) {
				t.Fatal("error exposed synthetic key bytes")
			}
			if !strings.Contains(err.Error(), "invalid keytab encoding") {
				t.Fatal("missing sanitized keytab diagnostic")
			}
		})
	}
}

func TestKeytabFilesystemErrorPreserved(t *testing.T) {
	_, err := readKeytab(filepath.Join(t.TempDir(), "missing.keytab"))
	var pathErr *os.PathError
	if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) {
		t.Fatal("safe filesystem error was not preserved")
	}
}
