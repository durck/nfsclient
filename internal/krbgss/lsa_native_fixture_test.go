package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"github.com/go-logr/logr"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"math"
	client "nfs-viewer/internal/krbclient"
	"os"
	"testing"
	"time"
)

func TestLSAImportedNativeGSS(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LSA_MIT_FIXTURE") != "1" {
		t.Skip("requires disposable native MIT tickets through independent LSA buffers")
	}
	for _, service := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(service, func(t *testing.T) {
			source, err := readCCache(os.Getenv("NFS_VIEWER_LSA_MIT_CACHE"))
			if err != nil {
				t.Fatal(err)
			}
			defer clearNativeCache(source)
			cred, ok := source.GetEntry(types.NewPrincipalName(2, "krbtgt/NFS.TEST"))
			if !ok {
				t.Fatal("missing native fixture TGT")
			}
			var ticket messages.Ticket
			if err := ticket.Unmarshal(cred.Ticket); err != nil {
				t.Fatal(err)
			}
			q := lsaQueryFixture(8, 1)
			x := 72
			stamp := func(t time.Time) uint64 {
				if t.IsZero() {
					return 0
				}
				return 116444736000000000 + uint64(t.Unix())*10000000
			}
			binary.LittleEndian.PutUint64(q.b[x:], stamp(cred.StartTime))
			binary.LittleEndian.PutUint64(q.b[x+8:], stamp(cred.EndTime))
			binary.LittleEndian.PutUint64(q.b[x+16:], stamp(cred.RenewTill))
			binary.LittleEndian.PutUint32(q.b[x+24:], uint32(ticket.EncPart.EType))
			binary.LittleEndian.PutUint32(q.b[x+28:], binary.BigEndian.Uint32(cred.TicketFlags.Bytes))
			m, err := selectLSATicket(q, "root@NFS.TEST")
			if err != nil {
				t.Fatal(err)
			}
			b := lsaExternalFixture(t, 8, m)
			f := lsaWire{b.b, 8, b.base}
			binary.LittleEndian.PutUint32(f.b[72:], uint32(cred.Key.KeyType))
			binary.LittleEndian.PutUint32(f.b[76:], uint32(len(cred.Key.KeyValue)))
			p := f.data(cred.Key.KeyValue)
			f.ptr(80, p)
			p = f.data(cred.Ticket)
			binary.LittleEndian.PutUint32(f.b[136:], uint32(len(cred.Ticket)))
			f.ptr(144, p)
			b.b = f.b
			clone := func(b lsaBuffer) lsaBuffer { b.b = bytes.Clone(b.b); return b }
			provider := &fixtureLSAProvider{queryBuffers: []lsaBuffer{q, clone(q)}, retrieveBuffers: []lsaBuffer{b, clone(b)}}
			imported, err := readLSAWith(stdcontext.Background(), "root@NFS.TEST", provider)
			if err != nil {
				t.Fatal(err)
			}
			defer clearNativeCache(imported)
			conf, err := config.Load(os.Getenv("NFS_VIEWER_KRB5_CONFIG"))
			if err != nil {
				t.Fatal(err)
			}
			cl, err := client.NewFromCCache(imported, conf, client.DisablePAFXFAST(true))
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Destroy()
			i := &Initiator{context: context{sequenceMask: math.MaxUint32, logger: logr.Discard()}, client: cl}
			spn := types.NewPrincipalName(2, "nfs/server.nfs.test")
			a, err := NewAcceptor(WithKeytab[Acceptor]("/etc/krb5.keytab"), WithServicePrincipal[Acceptor](&spn))
			if err != nil {
				t.Fatal(err)
			}
			flags := gssapi.ContextFlagMutual | gssapi.ContextFlagReplay | gssapi.ContextFlagSequence
			if service != "krb5" {
				flags |= gssapi.ContextFlagInteg
			}
			if service == "krb5p" {
				flags |= gssapi.ContextFlagConf
			}
			request, _, err := i.Initiate("nfs@server.nfs.test", flags, nil)
			if err != nil {
				t.Fatal(err)
			}
			reply, _, err := a.Accept(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = i.Initiate("nfs@server.nfs.test", flags, reply); err != nil {
				t.Fatal(err)
			}
			if !i.established || !a.established || i.peerName != "nfs/server.nfs.test@NFS.TEST" || a.peerName != "root@NFS.TEST" {
				t.Fatal("native GSS identities not established")
			}
			payload := []byte{0, 255, 128, 'L', 'S', 'A'}
			if service != "krb5" {
				mic, err := i.MakeSignature(payload)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.VerifySignature(payload, mic); err != nil {
					t.Fatal(err)
				}
			}
			if service == "krb5p" {
				sealed, err := i.Seal(payload)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := a.Unseal(sealed)
				if err != nil || !bytes.Equal(plain, payload) {
					t.Fatal("native imported-cache privacy", err)
				}
			}
		})
	}
}
