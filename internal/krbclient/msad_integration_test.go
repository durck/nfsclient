package client

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	msadRealm     = "MSAD.NFS.TEST"
	msadKDC       = "192.0.2.10:88"
	msadAbsentSPN = "nfs/nfs-viewer-missing.msad.nfs.test"
)

func msadServicePrincipal(t *testing.T) string {
	t.Helper()
	switch os.Getenv("NFS_VIEWER_MSAD_PROFILE") {
	case "", "legacy":
		return "nfs/nfs.msad.nfs.test"
	case "interop":
		return "nfs/nfs-interop.msad.nfs.test"
	default:
		t.Fatal("unknown explicit Microsoft AD fixture profile")
		return ""
	}
}

func msadUser(t *testing.T, alias string) string {
	t.Helper()
	msadServicePrincipal(t) // Validate the fixed profile before network activity.
	if os.Getenv("NFS_VIEWER_MSAD_PROFILE") == "interop" && (alias == "alice" || alias == "bob") {
		return "nv-" + alias
	}
	return alias
}

// This is an explicit, isolated Windows AD fixture, not an NFS or PAC
// authorization test. It neither discovers credentials nor writes cache files.
// Run it inside an authorized fixture guest; the observer listens on loopback
// and forwards unchanged Kerberos messages only to the pinned isolated DC.
func TestMicrosoftADKerberosClient(t *testing.T) {
	if os.Getenv("NFS_VIEWER_MSAD_KRBCLIENT") != "1" {
		t.Skip("requires the explicitly configured isolated Microsoft AD fixture")
	}
	paths := make(map[string]string)
	for _, name := range []string{"CONFIG", "ALICE_KEYTAB", "BOB_KEYTAB", "ALICE_CCACHE", "BOB_CCACHE", "SERVICE_KEYTAB"} {
		paths[name] = msadFixturePath(t, "NFS_VIEWER_MSAD_KRB5_"+name, strings.HasSuffix(name, "CCACHE"))
	}
	// Validate the supplied endpoint before opening any network socket.
	msadConfig(t, paths["CONFIG"], "", "tcp", 18)
	serviceKeys, err := keytab.Load(paths["SERVICE_KEYTAB"])
	if err != nil {
		t.Fatal("cannot load explicitly supplied service keytab")
	}
	for _, network := range []string{"tcp", "udp-preferred"} {
		t.Run(network, func(t *testing.T) {
			for _, et := range []struct {
				name string
				id   int32
			}{{"aes128", 17}, {"aes256", 18}} {
				t.Run(et.name, func(t *testing.T) {
					for _, user := range []string{"alice", "bob"} {
						t.Run(user, func(t *testing.T) {
							for _, source := range []string{"keytab", "ccache"} {
								t.Run(source, func(t *testing.T) {
									msadClientProfile(t, paths, serviceKeys, network, et.id, user, source)
								})
							}
						})
					}
				})
			}
			t.Run("cache-principal-mismatch", func(t *testing.T) {
				msadCacheMismatch(t, paths, network)
			})
		})
	}
}

// The joined guest already owns this credential. This separate gate permits
// machine-account Kerberos checks without loading ordinary-user or service keys.
// It proves no NFS operation, PAC authorization, or service-ticket decryption.
func TestMicrosoftADMachineKerberos(t *testing.T) {
	if os.Getenv("NFS_VIEWER_MSAD_MACHINE") != "1" {
		t.Skip("requires the explicitly configured isolated AD machine fixture")
	}
	paths := map[string]string{
		"CONFIG":      msadFixturePath(t, "NFS_VIEWER_MSAD_KRB5_CONFIG", false),
		"NFS$_KEYTAB": msadFixturePath(t, "NFS_VIEWER_MSAD_MACHINE_KEYTAB", false),
	}
	msadConfig(t, paths["CONFIG"], "", "tcp", 18)
	for _, network := range []string{"tcp", "udp-preferred"} {
		t.Run(network, func(t *testing.T) {
			for _, et := range []struct {
				name string
				id   int32
			}{{"aes128", 17}, {"aes256", 18}} {
				t.Run(et.name, func(t *testing.T) {
					msadClientProfile(t, paths, nil, network, et.id, "NFS$", "keytab")
				})
			}
		})
	}
}

func msadFixturePath(t *testing.T, env string, cache bool) string {
	t.Helper()
	p := os.Getenv(env)
	if cache {
		p = strings.TrimPrefix(p, "FILE:")
	}
	if !filepath.IsAbs(p) {
		t.Fatalf("%s must name an explicit absolute fixture file", env)
	}
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxKDCMessage {
		t.Fatalf("%s must name a nonempty bounded regular fixture file", env)
	}
	return p
}

func msadConfig(t *testing.T, path, relay, network string, et int32) *config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal("cannot parse explicit fixture Kerberos configuration")
	}
	if cfg.LibDefaults.DefaultRealm != msadRealm || len(cfg.Realms) != 1 || cfg.Realms[0].Realm != msadRealm || len(cfg.Realms[0].KDC) != 1 {
		t.Fatal("fixture configuration must contain only the pinned AD realm and one KDC")
	}
	if dc := cfg.Realms[0].KDC[0]; dc != msadKDC && dc != "192.0.2.10" {
		t.Fatal("fixture configuration KDC is not the pinned isolated DC")
	}
	for _, realm := range cfg.DomainRealm {
		if realm != msadRealm {
			t.Fatal("fixture domain mapping escapes the pinned realm")
		}
	}
	// Explicit endpoints and no DNS prevent accidental contact with other KDCs.
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.DNSCanonicalizeHostname = false
	cfg.LibDefaults.RDNS = false
	cfg.LibDefaults.Canonicalize = false
	cfg.LibDefaults.AllowWeakCrypto = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	if network == "udp-preferred" {
		cfg.LibDefaults.UDPPreferenceLimit = 32700
	}
	name := "aes256-cts-hmac-sha1-96"
	if et == 17 {
		name = "aes128-cts-hmac-sha1-96"
	}
	cfg.LibDefaults.DefaultTGSEnctypes = []string{name}
	cfg.LibDefaults.DefaultTktEnctypes = []string{name}
	cfg.LibDefaults.PermittedEnctypes = []string{name}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{et}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{et}
	cfg.LibDefaults.PermittedEnctypeIDs = []int32{et}
	if relay != "" {
		cfg.Realms[0].KDC = []string{relay}
	}
	return cfg
}

func msadLoadCache(t *testing.T, path, user string) *credentials.CCache {
	t.Helper()
	cc, err := credentials.LoadCCache(path)
	if err != nil {
		t.Fatal("cannot load explicit MIT FILE fixture cache")
	}
	if cc.GetClientRealm() != msadRealm || !cc.GetClientPrincipalName().Equal(types.NewPrincipalName(1, user)) {
		t.Fatal("fixture FILE cache has an unexpected selected principal")
	}
	return cc
}

func msadIdentity(t *testing.T, cl *Client, user string) {
	t.Helper()
	if cl.Credentials.Realm() != msadRealm || cl.Credentials.UserName() != user || !cl.Credentials.CName().Equal(types.NewPrincipalName(1, user)) {
		t.Fatal("selected client identity changed")
	}
}

func msadAESKey(t *testing.T, key types.EncryptionKey, expected int32) {
	t.Helper()
	n := map[int32]int{17: 16, 18: 32}[key.KeyType]
	if n == 0 || len(key.KeyValue) != n || (expected != 0 && key.KeyType != expected) {
		t.Fatal("unexpected AES session key type or length")
	}
}

func msadClientProfile(t *testing.T, paths map[string]string, serviceKeys *keytab.Keytab, network string, et int32, user, source string) {
	field := strings.ToUpper(user)
	user = msadUser(t, user)
	msadSPN := msadServicePrincipal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	relay := msadStartRelay(t, ctx)
	cfg := msadConfig(t, paths["CONFIG"], relay.address(), network, et)
	var cl *Client
	if source == "keytab" {
		kt, err := keytab.Load(paths[field+"_KEYTAB"])
		if err != nil {
			t.Fatal("cannot load explicit user keytab")
		}
		if _, _, err := kt.GetEncryptionKey(types.NewPrincipalName(1, user), msadRealm, 0, et); err != nil {
			t.Fatal("explicit user keytab lacks requested AES principal key")
		}
		cl = NewWithKeytab(user, msadRealm, kt, cfg, NetworkContext(ctx), DisablePAFXFAST(true))
	} else {
		var err error
		cl, err = NewFromCCache(msadLoadCache(t, paths[field+"_CCACHE"], user), cfg, NetworkContext(ctx), DisablePAFXFAST(true))
		if cl != nil {
			defer cl.Destroy()
		}
		if err != nil {
			t.Fatal("explicit FILE TGT import failed")
		}
	}
	if source == "keytab" {
		defer cl.Destroy()
	}
	msadIdentity(t, cl, user)
	if err := cl.AffirmLogin(); err != nil {
		t.Fatalf("AS/TGT setup failed (%T); observer=%s", err, relay.jsonStats())
	}
	tgt, tgtKey, err := cl.sessionTGT(msadRealm)
	if err != nil || tgt.Realm != msadRealm || !tgt.SName.Equal(types.NewPrincipalName(2, "krbtgt/"+msadRealm)) {
		t.Fatal("home TGT identity validation failed")
	}
	wantTGT := int32(0) // MIT FILE TGT can use either AES type already issued.
	if source == "keytab" {
		wantTGT = et
	}
	msadAESKey(t, tgtKey, wantTGT)
	tgtBytes, err := tgt.Marshal()
	if err != nil {
		t.Fatal("cannot measure home TGT")
	}
	before := relay.snapshot()
	ticket, sessionKey, err := cl.GetServiceTicket(msadSPN)
	if err != nil {
		t.Fatalf("fresh service TGS failed (%T); observer=%s", err, relay.jsonStats())
	}
	if ticket.Realm != msadRealm || !ticket.SName.Equal(types.NewPrincipalName(2, msadSPN)) || (ticket.EncPart.EType != 17 && ticket.EncPart.EType != 18) {
		t.Fatal("service ticket has unexpected realm, SPN or encryption type")
	}
	msadAESKey(t, sessionKey, et)
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		t.Fatal("cannot measure service ticket")
	}
	if serviceKeys != nil {
		decoded := ticket
		if err := decoded.DecryptEncPart(serviceKeys, nil); err != nil {
			t.Fatal("independent service-keytab ticket decryption failed")
		}
		p := decoded.DecryptedEncPart
		if p.CRealm != msadRealm || !p.CName.Equal(types.NewPrincipalName(1, user)) || p.Key.KeyType != sessionKey.KeyType || subtle.ConstantTimeCompare(p.Key.KeyValue, sessionKey.KeyValue) != 1 {
			t.Fatal("decrypted service ticket client or session key differs from the verified TGS reply")
		}
		now := time.Now()
		validAt := p.StartTime
		if p.AuthTime.After(validAt) {
			validAt = p.AuthTime
		}
		// Observe validity at the actual start time rather than assuming both
		// isolated VM clocks tick over a whole second at the same instant.
		if delay := validAt.Sub(now); delay > 0 && delay <= 2*time.Second {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
			now = time.Now()
		}
		if p.AuthTime.IsZero() || p.AuthTime.After(now) || (!p.StartTime.IsZero() && p.StartTime.After(now)) || !p.EndTime.After(now) {
			t.Fatalf("decrypted service ticket lifetime is not currently valid: now=%s auth=%s start=%s end=%s", now, p.AuthTime, p.StartTime, p.EndTime)
		}
	}
	after := relay.snapshot()
	if after.TGSRequests <= before.TGSRequests || after.TGSReplies <= before.TGSReplies {
		t.Fatal("service acquisition did not perform a fresh observed TGS exchange")
	}
	if source == "keytab" {
		if after.ASRequests == 0 || after.ASReplyETypes[et] == 0 || len(after.ASReplyETypes) != 1 {
			t.Fatal("keytab acquisition did not authenticate an AS reply using the requested AES type")
		}
	} else if cl.Credentials.HasKeytab() || cl.Credentials.HasPassword() || after.ASRequests != 0 {
		t.Fatal("FILE client performed AS exchange or gained fallback credentials")
	}
	msadIdentity(t, cl, user)
	badTicket, _, err := cl.GetServiceTicket(msadAbsentSPN)
	negative := relay.snapshot()
	if err == nil || badTicket.TktVNO != 0 || negative.Errors[errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN] <= after.Errors[errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN] || negative.ASRequests != after.ASRequests {
		t.Fatal("absent SPN was not rejected by the KDC without credential fallback")
	}
	msadIdentity(t, cl, user)
	if _, _, ok := cl.GetCachedTicket(msadAbsentSPN); ok {
		t.Fatal("failed SPN was cached")
	}
	if cached, key, ok := cl.GetCachedTicket(msadSPN); !ok || cached.Realm != ticket.Realm || !cached.SName.Equal(ticket.SName) || key.KeyType != sessionKey.KeyType || subtle.ConstantTimeCompare(key.KeyValue, sessionKey.KeyValue) != 1 {
		t.Fatal("failed SPN changed the already verified service credential")
	}
	relay.requireTransport(t, network)
	t.Logf("MSAD_KRB_CLIENT principal=%s@%s spn=%s source=%s requested_etype=%d tgt_session_etype=%d service_session_etype=%d service_ticket_etype=%d tgt_bytes=%d service_ticket_bytes=%d independently_decrypted=%t missing_spn_error=7 observer=%s", user, msadRealm, msadSPN, source, et, tgtKey.KeyType, sessionKey.KeyType, ticket.EncPart.EType, len(tgtBytes), len(ticketBytes), serviceKeys != nil, relay.jsonStats())
}

func msadCacheMismatch(t *testing.T, paths map[string]string, network string) {
	alice, bob, msadSPN := msadUser(t, "alice"), msadUser(t, "bob"), msadServicePrincipal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	relay := msadStartRelay(t, ctx)
	cfg := msadConfig(t, paths["CONFIG"], relay.address(), network, 18)
	cc := msadLoadCache(t, paths["ALICE_CCACHE"], alice)
	valid, err := NewFromCCache(cc, cfg, NetworkContext(ctx), DisablePAFXFAST(true))
	if valid != nil {
		defer valid.Destroy()
	}
	if err != nil {
		t.Fatal("baseline Alice FILE TGT is invalid")
	}
	if _, _, err := valid.GetServiceTicket(msadSPN); err != nil {
		t.Fatalf("baseline Alice FILE TGT cannot obtain a service ticket (%T)", err)
	}
	msadIdentity(t, valid, alice)
	before := relay.snapshot()
	// Change only in-memory selected principal; retain Alice's actual TGT and key.
	mismatch := *cc
	mismatch.DefaultPrincipal.PrincipalName = types.NewPrincipalName(1, bob)
	cl, err := NewFromCCache(&mismatch, cfg, NetworkContext(ctx), DisablePAFXFAST(true))
	if cl != nil {
		defer cl.Destroy()
	}
	if err == nil {
		msadIdentity(t, cl, bob)
		if cl.Credentials.HasKeytab() || cl.Credentials.HasPassword() {
			t.Fatal("mismatched cache acquired fallback credentials")
		}
		ticket, _, exchangeErr := cl.GetServiceTicket(msadSPN)
		stats := relay.snapshot()
		// KRB_AP_ERR_BADMATCH identifies the expected KDC mismatch rejection;
		// network timeouts or an unrelated setup failure do not satisfy the test.
		if exchangeErr == nil || ticket.TktVNO != 0 || stats.TGSRequests <= before.TGSRequests || stats.Errors[errorcode.KRB_AP_ERR_BADMATCH] <= before.Errors[errorcode.KRB_AP_ERR_BADMATCH] {
			t.Fatalf("mismatched FILE principal did not produce KDC BADMATCH; observer=%s", relay.jsonStats())
		}
		msadIdentity(t, cl, bob)
		if _, _, ok := cl.GetCachedTicket(msadSPN); ok {
			t.Fatal("mismatched identity acquired a service credential")
		}
		relay.requireTransport(t, network)
	}
	if relay.snapshot().ASRequests != 0 {
		t.Fatal("cache mismatch performed an AS fallback")
	}
	if !cc.GetClientPrincipalName().Equal(types.NewPrincipalName(1, alice)) {
		t.Fatal("negative test changed original cache identity")
	}
	t.Logf("MSAD_KRB_CACHE_MISMATCH selected=%s@%s tgt_owner=%s@%s local_rejection=%t observer=%s", bob, msadRealm, alice, msadRealm, err != nil, relay.jsonStats())
}

// The observer never logs request bodies, ciphertext, keys or credential paths.
type msadRelayStats struct {
	TCPRequests     int           `json:"tcp_requests"`
	UDPRequests     int           `json:"udp_requests"`
	ASRequests      int           `json:"as_requests"`
	TGSRequests     int           `json:"tgs_requests"`
	TGSReplies      int           `json:"tgs_replies"`
	MaxRequestBytes int           `json:"max_request_bytes"`
	MaxReplyBytes   int           `json:"max_reply_bytes"`
	Failures        int           `json:"relay_failures"`
	ASReplyETypes   map[int32]int `json:"as_reply_etypes"`
	Errors          map[int32]int `json:"kdc_errors"`
}

type msadRelay struct {
	ctx    context.Context
	cancel context.CancelFunc
	tcp    net.Listener
	udp    *net.UDPConn
	wg     sync.WaitGroup
	mu     sync.Mutex
	stats  msadRelayStats
	slots  chan struct{}
}

func msadStartRelay(t *testing.T, parent context.Context) *msadRelay {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot start fixture loopback TCP observer")
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcp.Addr().(*net.TCPAddr).Port})
	if err != nil {
		tcp.Close()
		t.Fatal("cannot start fixture loopback UDP observer")
	}
	ctx, cancel := context.WithCancel(parent)
	r := &msadRelay{ctx: ctx, cancel: cancel, tcp: tcp, udp: udp, slots: make(chan struct{}, 8), stats: msadRelayStats{ASReplyETypes: make(map[int32]int), Errors: make(map[int32]int)}}
	stop := context.AfterFunc(ctx, func() { tcp.Close(); udp.Close() })
	r.wg.Add(2)
	go r.serveTCP()
	go r.serveUDP()
	t.Cleanup(func() { cancel(); tcp.Close(); udp.Close(); stop(); r.wg.Wait() })
	return r
}

func (r *msadRelay) address() string { return r.tcp.Addr().String() }

func (r *msadRelay) snapshot() msadRelayStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	s.Errors = make(map[int32]int)
	s.ASReplyETypes = make(map[int32]int)
	for k, v := range r.stats.Errors {
		s.Errors[k] = v
	}
	for k, v := range r.stats.ASReplyETypes {
		s.ASReplyETypes[k] = v
	}
	return s
}

func (r *msadRelay) jsonStats() string { b, _ := json.Marshal(r.snapshot()); return string(b) }

func (r *msadRelay) requireTransport(t *testing.T, network string) {
	t.Helper()
	s := r.snapshot()
	if s.Failures != 0 || (network == "tcp" && (s.TCPRequests == 0 || s.UDPRequests != 0)) || (network == "udp-preferred" && s.UDPRequests == 0) {
		t.Fatalf("transport observation failed: %s", r.jsonStats())
	}
}

func (r *msadRelay) failed() { r.mu.Lock(); r.stats.Failures++; r.mu.Unlock() }

func (r *msadRelay) request(network string, b []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stats.TCPRequests+r.stats.UDPRequests >= 128 {
		r.stats.Failures++
		return false
	}
	if network == "tcp" {
		r.stats.TCPRequests++
	} else {
		r.stats.UDPRequests++
	}
	if len(b) > r.stats.MaxRequestBytes {
		r.stats.MaxRequestBytes = len(b)
	}
	if len(b) > 0 {
		switch b[0] {
		case 0x6a:
			r.stats.ASRequests++
		case 0x6c:
			r.stats.TGSRequests++
		}
	}
	return true
}

func (r *msadRelay) reply(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(b) > r.stats.MaxReplyBytes {
		r.stats.MaxReplyBytes = len(b)
	}
	if len(b) == 0 {
		r.stats.Failures++
		return
	}
	switch b[0] {
	case 0x6b:
		var rep messages.ASRep
		if rep.Unmarshal(b) != nil {
			r.stats.Failures++
			return
		}
		r.stats.ASReplyETypes[rep.EncPart.EType]++
	case 0x6d:
		r.stats.TGSReplies++
	case 0x7e:
		var rep messages.KRBError
		if rep.Unmarshal(b) != nil {
			r.stats.Failures++
			return
		}
		r.stats.Errors[rep.ErrorCode]++
	}
}

func (r *msadRelay) serveTCP() {
	defer r.wg.Done()
	for {
		conn, err := r.tcp.Accept()
		if err != nil {
			if r.ctx.Err() == nil {
				r.failed()
			}
			return
		}
		select {
		case r.slots <- struct{}{}:
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				defer func() { <-r.slots }()
				defer conn.Close()
				stop := context.AfterFunc(r.ctx, func() { conn.Close() })
				defer stop()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				request, err := msadReadFrame(conn)
				if err == nil && r.request("tcp", request) {
					var reply []byte
					reply, err = r.exchange("tcp", request)
					if err == nil {
						r.reply(reply)
						err = msadWriteFrame(conn, reply)
					}
				}
				if err != nil && r.ctx.Err() == nil {
					r.failed()
				}
			}()
		default:
			conn.Close()
			r.failed()
		}
	}
}

func (r *msadRelay) serveUDP() {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, peer, err := r.udp.ReadFromUDP(buf)
		if err != nil {
			if r.ctx.Err() == nil {
				r.failed()
			}
			return
		}
		if !r.request("udp", buf[:n]) {
			continue
		}
		reply, err := r.exchange("udp", buf[:n])
		if err == nil {
			r.reply(reply)
			_, err = r.udp.WriteToUDP(reply, peer)
		}
		if err != nil && r.ctx.Err() == nil {
			r.failed()
		}
	}
}

func (r *msadRelay) exchange(network string, request []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network+"4", msadKDC)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	if network == "tcp" {
		if err := msadWriteFrame(conn, request); err != nil {
			return nil, err
		}
		return msadReadFrame(conn)
	}
	if n, err := conn.Write(request); err != nil {
		return nil, err
	} else if n != len(request) {
		return nil, io.ErrShortWrite
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	return buf[:n], err
}

func msadReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxKDCMessage {
		return nil, errors.New("fixture KDC frame exceeds bounds")
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return b, err
}

func msadWriteFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > maxKDCMessage {
		return errors.New("fixture KDC frame exceeds bounds")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	_, err := io.Copy(w, io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(b)))
	return err
}

func TestMSADKDCFrameBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		valid bool
	}{
		{"valid", []byte{0, 0, 0, 3, 1, 2, 3}, true},
		{"empty-header", nil, false},
		{"short-header", []byte{0, 0, 0}, false},
		{"empty-body", []byte{0, 0, 0, 0}, false},
		{"short-body", []byte{0, 0, 0, 3, 1, 2}, false},
		{"oversized", []byte{0, 64, 0, 1}, false},
		{"high-bit", []byte{128, 0, 0, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := msadReadFrame(bytes.NewReader(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("frame validity=%t, expected %t", err == nil, tc.valid)
			}
			if tc.valid {
				var roundtrip bytes.Buffer
				if err := msadWriteFrame(&roundtrip, body); err != nil || !bytes.Equal(roundtrip.Bytes(), tc.input) {
					t.Fatal("frame relay changed bytes")
				}
			}
		})
	}
	for _, n := range []int{0, maxKDCMessage + 1} {
		t.Run(fmt.Sprintf("write-size-%d", n), func(t *testing.T) {
			var dst bytes.Buffer
			if msadWriteFrame(&dst, make([]byte, n)) == nil || dst.Len() != 0 {
				t.Fatal("invalid frame wrote bytes")
			}
		})
	}
}
