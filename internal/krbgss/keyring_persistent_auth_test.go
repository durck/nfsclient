package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	client "nfs-viewer/internal/krbclient"
	"nfs-viewer/internal/testutil/kdcfixture"
)

// The kernel-facing source is deterministic; TGS replies, service tickets and
// mutual GSS/sign/seal exchanges below use actual Kerberos cryptography.
func TestKEYRINGPersistentAuthenticationLifecycle(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	kt := keytab.New()
	if err := kt.AddEntry("nfs/server.nfs.test", "NFS.TEST", "test-only-persistent", now, 1, 18); err != nil {
		t.Fatal(err)
	}
	ticket, serviceKey, err := messages.NewTicket(types.NewPrincipalName(1, "root"), "NFS.TEST", types.NewPrincipalName(2, "nfs/server.nfs.test"), "NFS.TEST", types.NewKrbFlags(), kt, 18, 1, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.keytab")
	kb, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, kb, 0600); err != nil {
		t.Fatal(err)
	}
	var keyMu sync.Mutex
	tgtKey := bytes.Repeat([]byte{0x42}, 32)
	kdc := kdcfixture.Start(t, func(_ string, wire []byte) []byte {
		var req messages.TGSReq
		if err := req.Unmarshal(wire); err != nil {
			t.Error(err)
			return nil
		}
		if req.ReqBody.SName.PrincipalNameString() != "nfs/server.nfs.test" {
			t.Error("changed SPN")
			return nil
		}
		part := messages.EncKDCRepPart{Key: serviceKey, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), RenewTill: now.Add(time.Hour), SRealm: "NFS.TEST", SName: ticket.SName}
		plain, err := part.Marshal()
		if err != nil {
			t.Error(err)
			return nil
		}
		keyMu.Lock()
		key := bytes.Clone(tgtKey)
		keyMu.Unlock()
		encrypted, err := crypto.GetEncryptedData(plain, types.EncryptionKey{KeyType: 18, KeyValue: key}, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
		if err != nil {
			t.Error(err)
			return nil
		}
		reply := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 13, CRealm: "NFS.TEST", CName: types.NewPrincipalName(1, "root"), Ticket: ticket, EncPart: encrypted}}
		out, err := reply.Marshal()
		if err != nil {
			t.Error(err)
			return nil
		}
		return out
	})
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{kdc.Address}}}
	for _, mode := range []string{"initial", "refresh", "principal-change", "expired-tgt", "missing-tgt", "missing-cache"} {
		t.Run(mode, func(t *testing.T) {
			before := kdc.TCP.Load()
			wire := renewalCacheWire(t, time.Now().Add(time.Hour))
			if mode == "expired-tgt" {
				wire = renewalCacheWire(t, time.Now().Add(-time.Minute))
			}
			if mode == "principal-change" {
				wire = bytes.ReplaceAll(wire, []byte("root"), []byte("user"))
			}
			if mode == "refresh" {
				keyMu.Lock()
				tgtKey = bytes.Repeat([]byte{0x43}, 32)
				keyMu.Unlock()
				wire = bytes.Replace(wire, bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x43}, 32), 1)
			}
			r := &cacheReader{b: wire[4:]}
			r.principal()
			if r.err != nil {
				t.Fatal(r.err)
			}
			n := len(wire) - len(r.b)
			f := &persistentKeyringFixture{keyringFixture: newKeyringFixture("success"), uid: 1000}
			f.descriptions[2] = kernelKeyDescription{"keyring", "_krb", 1000}
			f.payload[4] = bytes.Clone(wire[4:n])
			f.payload[5] = bytes.Clone(wire[n:])
			if mode == "missing-cache" {
				f.descriptions[3] = kernelKeyDescription{"keyring", "another-cache", 1000}
			}
			if mode == "missing-tgt" {
				f.mode = "empty"
			}
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 3*time.Second)
			defer cancel()
			cache, err := readKeyringSnapshot(ctx, f, keyringSelection{"persistent", "1000", "cache"}, 1000)
			good := mode == "initial" || mode == "refresh"
			if err != nil {
				if good {
					t.Fatal(err)
				}
				if kdc.TCP.Load() != before {
					t.Fatal("failed snapshot contacted KDC")
				}
				return
			}
			defer clearNativeCache(cache)
			i := &Initiator{context: context{logger: logr.Discard(), sequenceMask: math.MaxUint32}, logger: logr.Discard(), username: "root", domain: "NFS.TEST", ccache: "KEYRING:persistent:1000:cache", networkContext: ctx}
			i.client, err = i.newSelectedCacheClient(cache, cfg, []func(*client.Settings){client.NetworkContext(ctx)})
			if i.client != nil {
				defer i.Close()
			}
			if !good {
				if err == nil {
					t.Fatal("bad cache accepted")
				}
				if mode == "expired-tgt" && !strings.Contains(err.Error(), "expired") {
					t.Fatal(err)
				}
				if kdc.TCP.Load() != before {
					t.Fatal("bad credential contacted KDC")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = i.client.AffirmLogin(); err != nil {
				t.Fatal(err)
			}
			flags := gssapi.ContextFlagMutual | gssapi.ContextFlagInteg | gssapi.ContextFlagConf
			request, more, err := i.Initiate("nfs/server.nfs.test", flags, nil)
			if err != nil || !more {
				t.Fatal("initial GSS", err)
			}
			a, err := NewAcceptor(WithKeytab[Acceptor](path))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			reply, more, err := a.Accept(request)
			if err != nil || more {
				t.Fatal("accept GSS", err)
			}
			if _, more, err = i.Initiate("nfs/server.nfs.test", flags, reply); err != nil || more || !i.Established() {
				t.Fatal("mutual GSS", err)
			}
			message := binary.BigEndian.AppendUint32(nil, 123)
			mic, err := i.MakeSignature(message)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.VerifySignature(message, mic); err != nil {
				t.Fatal(err)
			}
			sealed, err := i.Seal(message)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := a.Unseal(sealed)
			if err != nil || !bytes.Equal(plain, message) {
				t.Fatal("privacy", err)
			}
			if kdc.TCP.Load() != before+1 {
				t.Fatal("expected fresh TGS exchange from selected snapshot")
			}
		})
	}
}
