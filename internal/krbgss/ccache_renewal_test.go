package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfsclient/internal/testutil/kdcfixture"
)

func renewalCacheWire(t *testing.T, end time.Time) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	ticket := messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: types.NewPrincipalName(2, "krbtgt/NFS.TEST"), EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic TGT")}}
	wire, err := ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{5, 4, 0, 0}
	b = cachePrincipal(b, "NFS.TEST", "root")
	b = cachePrincipal(b, "NFS.TEST", "root")
	b = cachePrincipal(b, "NFS.TEST", "krbtgt", "NFS.TEST")
	b = binary.BigEndian.AppendUint16(b, 18)
	b = cacheData(b, bytes.Repeat([]byte{0x42}, 32))
	for _, v := range []int64{now.Unix(), now.Unix(), end.Unix(), now.Add(time.Hour).Unix()} {
		b = binary.BigEndian.AppendUint32(b, uint32(v))
	}
	b = append(b, 0, 0, 0x80, 0, 0) // is_skey=false; RFC ticket flag 8 (renewable).
	b = append(b, make([]byte, 8)...)
	b = cacheData(b, wire)
	return cacheData(b, nil)
}

func renewalKDC(t *testing.T, old *credentials.Credential, silent bool) *kdcfixture.Server {
	t.Helper()
	return kdcfixture.Start(t, func(_ string, b []byte) []byte {
		if silent {
			return nil
		}
		var req messages.TGSReq
		if err := req.Unmarshal(b); err != nil {
			t.Error(err)
			return nil
		}
		if !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renew) {
			t.Error("not a renewal")
		}
		p := messages.EncKDCRepPart{Key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x63}, 32)}, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: old.AuthTime, StartTime: time.Now().UTC().Truncate(time.Second), EndTime: old.EndTime.Add(time.Minute), RenewTill: old.RenewTill, SRealm: "NFS.TEST", SName: old.Server.PrincipalName}
		types.SetFlag(&p.Flags, flags.Renewable)
		r := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 13, CRealm: "NFS.TEST", CName: old.Client.PrincipalName, Ticket: messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: old.Server.PrincipalName, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic renewed TGT")}}}}
		plain, err := p.Marshal()
		if err != nil {
			t.Error(err)
			return nil
		}
		r.EncPart, err = crypto.GetEncryptedData(plain, old.Key, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
		if err != nil {
			t.Error(err)
			return nil
		}
		wire, err := r.Marshal()
		if err != nil {
			t.Error(err)
			return nil
		}
		return wire
	})
}

func TestFileCacheRenewalIdleAndContextReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected.ccache")
	wire := renewalCacheWire(t, time.Now().Add(4*time.Second))
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	cache, err := readCCache(path)
	if err != nil {
		t.Fatal(err)
	}
	oldEnd := cache.Credentials[0].EndTime
	server := renewalKDC(t, cache.Credentials[0], false)
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{server.Address}}}
	m := NewFileCacheRenewal()
	defer m.Close()
	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 10*time.Second)
	defer cancel()
	first, err := m.load(ctx, path, "root@NFS.TEST", cache, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	clearNativeCache(first)
	// No foreground operation is made while the original FILE TGT expires.
	deadline := time.NewTimer(time.Until(oldEnd.Add(100 * time.Millisecond)))
	defer deadline.Stop()
	select {
	case <-deadline.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if server.TCP.Load() != 1 {
		m.mu.Lock()
		d, a := m.delayLocked()
		retry := m.retry
		failure := m.failure
		m.mu.Unlock()
		t.Fatalf("idle renewal requests=%d, want 1 (delay=%v active=%v retry=%v failure=%v)", server.TCP.Load(), d, a, retry, failure)
	}
	// Context replacement re-reads the now-expired source and must retain the
	// renewed ticket owned by this live connection, not restart from that source.
	loaded, err := readCCache(path)
	if err != nil {
		t.Fatal(err)
	}
	next, err := m.load(ctx, path, "root@NFS.TEST", loaded, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Credentials[0].EndTime.After(oldEnd) {
		t.Fatal("renewal lost across context replacement")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("externally owned FILE cache changed")
	}
	clearNativeCache(next)
	// Independent snapshots must not alias the retained renewal key/ticket.
	next, err = m.load(ctx, path, "root@NFS.TEST", loaded, cfg, nil)
	if err != nil || len(next.Credentials[0].Key.KeyValue) != 32 || bytes.Equal(next.Credentials[0].Key.KeyValue, make([]byte, 32)) {
		t.Fatal("caller cleared retained credentials")
	}
	m.Close()
	if _, err = m.load(ctx, path, "root@NFS.TEST", loaded, cfg, nil); err == nil {
		t.Fatal("closed owner reused")
	}
}

func TestFileCacheRenewalCloseCancelsKDC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected.ccache")
	wire := renewalCacheWire(t, time.Now().Add(3*time.Second))
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	cache, err := readCCache(path)
	if err != nil {
		t.Fatal(err)
	}
	server := renewalKDC(t, cache.Credentials[0], true)
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{server.Address}}}
	m := NewFileCacheRenewal()
	defer m.Close()
	if _, err = m.load(stdcontext.Background(), path, "root@NFS.TEST", cache, cfg, nil); err != nil {
		t.Fatal(err)
	}
	limit := time.Now().Add(4 * time.Second)
	for server.TCP.Load() == 0 && time.Now().Before(limit) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.TCP.Load() == 0 {
		t.Fatal("idle renewal never started")
	}
	start := time.Now()
	m.Close()
	if time.Since(start) > time.Second {
		t.Fatal("Close did not cancel active renewal")
	}
}

func TestFileCacheRenewalCloseCancelsForeground(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected.ccache")
	wire := renewalCacheWire(t, time.Now().Add(20*time.Second))
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	cache, err := readCCache(path)
	if err != nil {
		t.Fatal(err)
	}
	// A long original lifetime puts this still-valid TGT in its renewal margin.
	cache.Credentials[0].StartTime = time.Now().Add(-time.Hour)
	cache.Credentials[0].AuthTime = cache.Credentials[0].StartTime
	server := renewalKDC(t, cache.Credentials[0], true)
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{server.Address}}}
	m := NewFileCacheRenewal()
	defer m.Close()
	done := make(chan error, 1)
	go func() { _, err := m.load(stdcontext.Background(), path, "root@NFS.TEST", cache, cfg, nil); done <- err }()
	limit := time.Now().Add(time.Second)
	for server.TCP.Load() == 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if server.TCP.Load() == 0 {
		t.Fatal("foreground renewal never started")
	}
	start := time.Now()
	m.Close()
	if time.Since(start) > time.Second {
		t.Fatal("Close did not cancel foreground renewal")
	}
	if err := <-done; err == nil {
		t.Fatal("canceled foreground renewal succeeded")
	}
}

func TestFileCacheRenewalNativeMIT(t *testing.T) {
	path, confPath := os.Getenv("NFS_VIEWER_TGT_RENEW_CACHE"), os.Getenv("NFS_VIEWER_TGT_RENEW_CONFIG")
	if path == "" || confPath == "" {
		t.Skip("explicit disposable renewable MIT cache/config required")
	}
	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := readCCache(path)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := cache.GetEntry(types.NewPrincipalName(2, "krbtgt/NFS.TEST"))
	if !ok {
		t.Fatal("native fixture needs NFS.TEST home TGT")
	}
	if !types.IsFlagSet(&e.TicketFlags, flags.Renewable) || time.Until(e.EndTime) > 30*time.Second || time.Until(e.EndTime) < 2*time.Second || !e.RenewTill.After(e.EndTime) {
		t.Fatal("native fixture needs fresh 3..30-second renewable TGT")
	}
	originalEnd := e.EndTime
	m := NewFileCacheRenewal()
	defer m.Close()
	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 45*time.Second)
	defer cancel()
	options := []Option[Initiator]{WithConfig[Initiator](string(conf)), WithRealm[Initiator]("NFS.TEST"), WithUsername[Initiator](cache.DefaultPrincipal.PrincipalName.PrincipalNameString()), WithCCache(path), WithNetworkContext(ctx), WithFileCacheRenewal(m)}
	first, err := NewInitiator(options...)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = first.Initiate("nfs@server.nfs.test", 0, nil); err != nil {
		first.Close()
		t.Fatal(err)
	}
	first.Close()
	timer := time.NewTimer(time.Until(originalEnd.Add(time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	next, err := NewInitiator(options...)
	if err != nil {
		m.mu.Lock()
		failure := m.failure
		m.mu.Unlock()
		t.Fatalf("context replacement: %v; background renewal: %v", err, failure)
	}
	defer next.Close()
	if _, _, err = next.Initiate("nfs@server.nfs.test", 0, nil); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	renewed := m.homeLocked().EndTime
	m.mu.Unlock()
	if !renewed.After(originalEnd) {
		t.Fatal("MIT TGT lifetime did not advance")
	}
	unchanged, err := readCCache(path)
	if err != nil {
		t.Fatal(err)
	}
	old, ok := unchanged.GetEntry(types.NewPrincipalName(2, "krbtgt/NFS.TEST"))
	if !ok || !old.EndTime.Equal(originalEnd) {
		t.Fatal("input cache was rewritten")
	}
}
