package nfs

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"nfs-viewer/internal/krbconfig"
	bgss "nfs-viewer/internal/krbgss"
	"nfs-viewer/internal/resolve"
)

// KerberosConfig requires explicit credentials; no ambient password or cache lookup.
type KerberosConfig struct {
	Provider                                   string // Empty/portable uses explicit files; sspi selects current Windows logon.
	configSnapshot                             *krbconfig.Snapshot
	ConfigFile, Keytab, CCache, Principal, SPN string
	KCMSocket                                  string
	ASAlias                                    string
	EnterpriseUPN, ASStartRealm                string
	ASReferralRealms                           []string
	ASHelper, FASTArmor                        string
	RequireFAST                                bool
	PKINIT                                     bgss.PKINITFiles
	DNS                                        resolve.Config
	// RPCVersion is explicit RPCSEC_GSS v3 for protected NFSv4.2 COPY.
	// Zero and one retain the default v1 profile.
	RPCVersion uint32
}

func (c *Client) Security() string {
	if c.security == "" {
		return "sys"
	}
	return c.security
}

func (c *Client) Identity() string {
	if c.Security() != "sys" {
		return c.principal + " (" + c.Security() + ")"
	}
	return fmt.Sprintf("UID %d  /  GID %d  (AUTH_SYS)", c.Auth.UID, c.Auth.GID)
}

func validateSecurity(cfg *Config) error {
	if cfg.Security == "" {
		cfg.Security = "sys"
	}
	k := cfg.Kerberos
	if k.Provider != "" && k.Provider != "portable" && k.Provider != "sspi" {
		return errors.New("kerberos provider must be portable or sspi")
	}
	if k.Provider == "sspi" {
		return validateSSPIProfile(cfg)
	}
	if k.RPCVersion != 0 && k.RPCVersion != 1 && k.RPCVersion != 3 {
		return errors.New("RPCSEC_GSS version must be 1 or 3")
	}
	if k.RPCVersion == 3 && (cfg.Security != "krb5p" || cfg.Version != "4.2" || cfg.Transport != "" && cfg.Transport != "tcp" || cfg.PNFS) {
		return errors.New("RPCSEC_GSS v3 requires explicit NFSv4.2 krb5p/TCP without pNFS")
	}
	switch cfg.Security {
	case "sys":
		if k.ConfigFile != "" || k.Keytab != "" || k.CCache != "" || k.Principal != "" || k.SPN != "" || k.KCMSocket != "" || k.ASAlias != "" || k.EnterpriseUPN != "" || k.ASStartRealm != "" || len(k.ASReferralRealms) > 0 || k.ASHelper != "" || k.FASTArmor != "" || k.RequireFAST || k.PKINIT.Selected() {
			return errors.New("kerberos options require --sec krb5, krb5i or krb5p")
		}
	case "krb5", "krb5i", "krb5p":
		switch cfg.Version {
		case "", "auto", "2", "3", "4", "4.0", "4.1", "4.2":
		default:
			return errors.New("kerberos requires NFSv2, NFSv3 or NFSv4; no authentication downgrade is allowed")
		}
		if k.ConfigFile == "" || (k.Keytab == "" && k.CCache == "" && !k.PKINIT.Selected()) || k.SPN == "" {
			return errors.New("kerberos requires --krb5-config, --principal, --spn and explicit keytab, ccache or PKINIT identity")
		}
		if k.Keytab != "" && k.CCache != "" {
			return errors.New("select exactly one of --keytab or --ccache")
		}
		if err := bgss.ValidateCCacheSelection(k.CCache, k.KCMSocket); err != nil {
			return err
		}

		user, realm, ok := strings.Cut(k.Principal, "@")
		if !ok || user == "" || realm == "" || strings.Contains(realm, "@") {
			return errors.New("kerberos principal must be NAME@REALM")
		}
		if k.ASAlias != "" {
			if k.Keytab == "" || k.CCache != "" {
				return errors.New("--as-alias requires an explicit canonical keytab")
			}
			if err := bgss.ValidateASAlias(k.ASAlias, realm); err != nil {
				return err
			}
		}
		if k.EnterpriseUPN != "" || k.ASStartRealm != "" || len(k.ASReferralRealms) > 0 {
			if k.ASAlias != "" || k.Keytab == "" || k.CCache != "" {
				return errors.New("enterprise AS requires only an explicit canonical keytab")
			}
			if err := bgss.ValidateEnterpriseAS(k.EnterpriseUPN, k.ASStartRealm, realm, k.ASReferralRealms); err != nil {
				return err
			}
			cfg.Kerberos.ASReferralRealms = append([]string(nil), k.ASReferralRealms...)
		}
		if k.RequireFAST && !k.PKINIT.Selected() && (k.Keytab == "" || k.CCache != "" || k.ASAlias != "" || k.EnterpriseUPN != "") {
			return errors.New("required FAST needs only an explicit canonical keytab")
		}
		if k.PKINIT.Selected() {
			if k.Keytab != "" || k.CCache != "" || k.ASAlias != "" || k.EnterpriseUPN != "" || k.ASStartRealm != "" || len(k.ASReferralRealms) > 0 {
				return errors.New("PKINIT selects only an explicit canonical certificate identity")
			}
			if err := bgss.ValidatePKINITFAST(k.ASHelper, k.FASTArmor, k.RequireFAST); err != nil {
				return err
			}
			if err := bgss.ValidatePKINIT(k.ASHelper, k.PKINIT); err != nil {
				return err
			}
		} else if err := bgss.ValidateNativeAS(k.ASHelper, k.FASTArmor, k.RequireFAST); err != nil {
			return err
		}
		if !strings.HasPrefix(k.SPN, "nfs/") || len(k.SPN) <= 4 || strings.Contains(k.SPN, "@") {
			return errors.New("kerberos SPN must be nfs/server-hostname (realm comes from Kerberos configuration)")
		}
		if cfg.Version == "" {
			cfg.Version = "3" // Preserve the omitted API default; explicit auto negotiates.
		}
	default:
		return errors.New("--sec must be sys, krb5, krb5i or krb5p")
	}
	return nil
}

type micContext interface {
	MakeSignature([]byte) ([]byte, error)
	VerifySignature([]byte, []byte) error
}

type rpcGSS struct {
	context     micContext
	handle      []byte
	seq         uint32
	window      uint32
	service     uint32 // zero preserves the default authentication-only service
	established bool
	expiry      time.Time
	renewAt     time.Time
	nfsVersion  uint32
	rpcVersion  uint32
	replyHeader []byte
	parent      *rpcGSS // Child handles share the mechanism, never its ownership.
}

func (g *rpcGSS) protocolVersion() uint32 {
	if g.rpcVersion == 3 {
		return 3
	}
	return 1
}

type kerberosSession struct {
	config    KerberosConfig
	security  string
	version   uint32
	cleanup   func()
	renewals  uint64
	fileCache *bgss.FileCacheRenewal
	ctx       context.Context
	cancel    context.CancelFunc
}

func (s *kerberosSession) cancelWork() {
	if s.cancel != nil {
		s.cancel()
	}
	s.fileCache.Cancel()
}

// Published independently of the RPC mutex so Close can interrupt KDC work
// while a foreground RPC or background lease renewal owns that mutex.
type kerberosCancellation struct{ cancel func() }

func (c *Client) authenticateKerberos(ctx context.Context, cfg Config) error {
	if cfg.Security != "krb5" && cfg.Security != "krb5i" && cfg.Security != "krb5p" {
		return nil
	}
	c.security, c.principal = cfg.Security, cfg.Kerberos.Principal
	var err error
	c.closeKerberos, err = c.nfs.establishKerberos(ctx, cfg.Kerberos, cfg.Security, c.nfsVersion())
	if err == nil {
		c.cancelKerberos.Store(&kerberosCancellation{cancel: c.nfs.kerberos.cancelWork})
	}
	return err
}

// checkExpiry is called under rpcClient.mu, before sending or consuming a reply.
func (g *rpcGSS) checkExpiry(now time.Time) error {
	if !g.expiry.IsZero() && !now.Before(g.expiry) {
		g.established = false
		return errors.New("kerberos context expired; session closed, reconnect (no request replay)")
	}
	return nil
}

// KerberosExpiry is the authenticated service ticket endtime, not a lifetime estimate.
func (c *Client) KerberosExpiry() time.Time {
	if c.nfs == nil {
		return time.Time{}
	}
	c.nfs.mu.Lock()
	defer c.nfs.mu.Unlock()
	if c.nfs.gss == nil {
		return time.Time{}
	}
	return c.nfs.gss.expiry
}

func (c *Client) KerberosRenewals() uint64 {
	if c.nfs == nil {
		return 0
	}
	c.nfs.mu.Lock()
	defer c.nfs.mu.Unlock()
	if c.nfs.kerberos == nil {
		return 0
	}
	return c.nfs.kerberos.renewals
}

// RFC 2203: sign XID through credential, then append the verifier. Service
// none authenticates the call header, NOT the plaintext arguments/results.
func (g *rpcGSS) encode(e *encoder, procedure uint32) error {
	init := procedure == 1 || procedure == 2
	if !init {
		if err := g.checkExpiry(time.Now()); err != nil {
			return err
		}
		if !g.established {
			return errors.New("RPCSEC_GSS context is not established")
		}
		if g.seq >= 0x7fffffff {
			return errors.New("RPCSEC_GSS sequence exhausted; reconnect")
		}
		g.seq++
	}
	var credential encoder
	credential.u32(g.protocolVersion())
	credential.u32(procedure)
	credential.u32(g.seq)
	service := uint32(1) // control calls have no protected procedure arguments
	if (procedure == 0 || procedure == 5 || procedure == 6) && g.service >= 2 {
		service = g.service
	}
	credential.u32(service)
	credential.opaque(g.handle)
	if len(credential) > 400 {
		return errors.New("RPCSEC_GSS context handle exceeds credential limit")
	}
	e.u32(6)
	e.opaque(credential)
	if g.protocolVersion() == 3 {
		g.replyHeader = append(g.replyHeader[:0], (*e)...)
		binary.BigEndian.PutUint32(g.replyHeader[4:8], 1)
	}
	if init {
		e.u32(0)
		e.u32(0)
		return nil
	}
	mic, err := g.context.MakeSignature(*e)
	if err != nil {
		return fmt.Errorf("RPCSEC_GSS request signature: %w", err)
	}
	if len(mic) > 400 {
		return errors.New("RPCSEC_GSS verifier exceeds RPC limit")
	}
	e.u32(6)
	e.opaque(mic)
	return nil
}

func (g *rpcGSS) verify(d *decoder, sequence uint32) error {
	if err := g.checkExpiry(time.Now()); err != nil {
		return err
	}
	if d.verifierFlavor != 6 {
		return errors.New("missing RPCSEC_GSS reply verifier")
	}
	signed := binary.BigEndian.AppendUint32(nil, sequence)
	if g.protocolVersion() == 3 {
		if len(g.replyHeader) < 32 {
			return errors.New("missing RPCSEC_GSS v3 request binding")
		}
		signed = g.replyHeader
	}
	if err := g.context.VerifySignature(signed, d.verifier); err != nil {
		// The dependency's checksum error includes MIC bytes; keep them out of logs.
		return errors.New("RPCSEC_GSS reply signature verification failed")
	}
	return nil
}

// RFC 2203 section 5.3.2.2: the MIC covers the sequence and XDR arguments,
// excluding the enclosing opaque length and padding.
func (g *rpcGSS) protect(args encoder) (encoder, error) {
	if g.service == 3 {
		sealer, ok := g.context.(interface{ Seal([]byte) ([]byte, error) })
		if !ok {
			return nil, errors.New("GSS privacy is unavailable")
		}
		if len(args) > maxRecord-4 {
			return nil, errors.New("RPCSEC_GSS arguments exceed record limit")
		}
		body := binary.BigEndian.AppendUint32(nil, g.seq)
		body = append(body, args...)
		token, err := sealer.Seal(body)
		clear(body)
		if err != nil {
			return nil, err
		}
		var wrapped encoder
		wrapped.opaque(token)
		return wrapped, nil
	}
	if g.service != 2 {
		return args, nil
	}
	if len(args) > maxRecord-4 {
		return nil, errors.New("RPCSEC_GSS arguments exceed record limit")
	}
	var body encoder
	body.u32(g.seq)
	body = append(body, args...)
	mic, err := g.context.MakeSignature(body)
	if err != nil {
		return nil, errors.New("RPCSEC_GSS argument signature failed")
	}
	if len(mic) > 400 {
		return nil, errors.New("RPCSEC_GSS checksum exceeds supported limit")
	}
	var wrapped encoder
	wrapped.opaque(body)
	wrapped.opaque(mic)
	return wrapped, nil
}

// Never expose unverified result bytes to the NFS decoder or file writer.
func (g *rpcGSS) unprotect(d *decoder) error {
	if g.service == 3 {
		sealer, ok := g.context.(interface{ Unseal([]byte) ([]byte, error) })
		if !ok {
			return errors.New("GSS privacy is unavailable")
		}
		token := d.opaque(maxRecord)
		if d.err != nil {
			return fmt.Errorf("RPCSEC_GSS privacy framing: %w", d.err)
		}
		if len(d.b) != 0 {
			return errors.New("trailing RPCSEC_GSS privacy data")
		}
		body, err := sealer.Unseal(token)
		if err != nil {
			return fmt.Errorf("RPCSEC_GSS privacy: %w", err)
		}
		if len(body) < 4 || len(body)%4 != 0 || binary.BigEndian.Uint32(body) != g.seq {
			clear(body)
			return errors.New("RPCSEC_GSS privacy result sequence or length mismatch")
		}
		d.b = body[4:]
		return nil
	}
	if g.service != 2 {
		return nil
	}
	body := d.opaque(maxRecord)
	mic := d.opaque(400)
	if d.err != nil {
		return fmt.Errorf("RPCSEC_GSS integrity framing: %w", d.err)
	}
	if len(d.b) != 0 || len(body) < 4 || len(body)%4 != 0 {
		return errors.New("invalid RPCSEC_GSS integrity body")
	}
	if err := g.context.VerifySignature(body, mic); err != nil {
		return errors.New("RPCSEC_GSS result signature verification failed")
	}
	if binary.BigEndian.Uint32(body) != g.seq {
		return errors.New("RPCSEC_GSS result sequence mismatch")
	}
	d.b = body[4:]
	return nil
}

func (c *rpcClient) establishKerberos(ctx context.Context, k KerberosConfig, security string, nfsVersion uint32) (_ func(), resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// lcd may change the process cwd. Resolve explicit credential/config paths
	// once so subsequent authentication uses the originally selected files.
	cacheIsKCM := strings.HasPrefix(k.CCache, "KCM:") || strings.HasPrefix(k.CCache, "KEYRING:") || strings.HasPrefix(k.CCache, "MSLSA:")
	if k.CCache != "" {
		k.CCache = strings.TrimPrefix(k.CCache, "FILE:")
	}
	for _, p := range []*string{&k.ConfigFile, &k.Keytab, &k.CCache} {
		if *p == "" {
			continue
		}
		if p == &k.CCache && cacheIsKCM {
			continue
		}
		absolute, err := filepath.Abs(*p)
		if err != nil {
			return nil, err
		}
		*p = absolute
	}
	if k.Provider != "sspi" && k.configSnapshot == nil {
		var err error
		k.configSnapshot, err = krbconfig.Load(k.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("read Kerberos configuration: %w", err)
		}
	} else if k.Provider != "sspi" {
		if err := k.configSnapshot.Verify(); err != nil {
			return nil, err
		}
	}
	s := &kerberosSession{config: k, security: security, version: nfsVersion}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if k.CCache != "" && !cacheIsKCM {
		s.fileCache = bgss.NewFileCacheRenewal()
	}
	c.kerberos = s
	cleanup, err := c.establishKerberosLocked(ctx, k, security, nfsVersion)
	if err != nil {
		s.cancelWork()
		s.fileCache.Close()
		c.kerberos = nil
		return nil, err
	}
	s.cleanup = cleanup
	return func() {
		// Join credential renewal before taking the RPC mutex; renewal never
		// sends NFS requests and cannot hold this connection alive after Close.
		s.cancelWork()
		s.fileCache.Close()
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		if c.kerberos.cleanup != nil {
			c.kerberos.cleanup()
			c.kerberos.cleanup = nil
		}
	}, nil
}

func (c *rpcClient) establishKerberosLocked(ctx context.Context, k KerberosConfig, security string, nfsVersion uint32) (_ func(), resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if c.kerberos != nil && c.kerberos.ctx != nil {
		stop := context.AfterFunc(c.kerberos.ctx, cancel)
		defer stop()
	}
	defer func() {
		if resultErr != nil {
			cause := ctx.Err()
			// A socket deadline can fire just before the context timer callback.
			if deadline, ok := ctx.Deadline(); cause == nil && ok && !time.Now().Before(deadline) {
				cause = context.DeadlineExceeded
			}
			if cause != nil {
				resultErr = fmt.Errorf("kerberos setup: %w", cause)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if k.Provider == "sspi" {
		initiator, err := newSSPIInitiator(ctx, k)
		if err != nil {
			return nil, err
		}
		return c.establishGSSInitiatorLocked(ctx, k, security, nfsVersion, initiator)
	}
	// Internal recovery callers may supply a freshly selected profile. Capture
	// it once too; subsequent attempts retain and verify the same snapshot.
	if k.configSnapshot == nil {
		var err error
		k.configSnapshot, err = krbconfig.Load(k.ConfigFile)
		if err != nil {
			return nil, err
		}
		if c.kerberos != nil {
			c.kerberos.config.configSnapshot = k.configSnapshot
		}
	}
	if err := k.configSnapshot.Verify(); err != nil {
		return nil, err
	}
	user, realm, _ := strings.Cut(k.Principal, "@")
	options := []bgss.Option[bgss.Initiator]{bgss.WithConfigSnapshot(k.configSnapshot), bgss.WithRealm[bgss.Initiator](realm), bgss.WithUsername[bgss.Initiator](user), bgss.WithNetworkContext(ctx)}
	options = append(options, bgss.WithDNS(k.DNS))
	if k.ASAlias != "" {
		options = append(options, bgss.WithASAlias(k.ASAlias))
	}
	if k.EnterpriseUPN != "" {
		options = append(options, bgss.WithEnterpriseAS(k.EnterpriseUPN, k.ASStartRealm, k.ASReferralRealms))
	}
	if k.RequireFAST {
		options = append(options, bgss.WithRequiredFAST(k.ASHelper, k.FASTArmor))
	}
	if k.PKINIT.Selected() {
		options = append(options, bgss.WithPKINIT(k.ASHelper, k.PKINIT))
	}
	if secured, ok := c.conn.(*tls.Conn); ok {
		binding, err := tlsGSSBinding(secured)
		if err != nil {
			return nil, err
		}
		options = append(options, bgss.WithChannelBinding[bgss.Initiator](binding))
	}
	if k.CCache != "" {
		options = append(options, bgss.WithCCache(k.CCache))
		if c.kerberos != nil && c.kerberos.fileCache != nil {
			options = append(options, bgss.WithFileCacheRenewal(c.kerberos.fileCache))
		}
		if k.KCMSocket != "" {
			options = append(options, bgss.WithKCMSocket(k.KCMSocket))
		}
	} else if !k.PKINIT.Selected() {
		options = append(options, bgss.WithKeytab[bgss.Initiator](k.Keytab))
	}
	initiator, err := bgss.NewInitiator(options...)
	if err != nil {
		return nil, fmt.Errorf("kerberos login: %w", err)
	}
	return c.establishGSSInitiatorLocked(ctx, k, security, nfsVersion, initiator)
}

func (c *rpcClient) establishGSSInitiatorLocked(ctx context.Context, k KerberosConfig, security string, nfsVersion uint32, initiator kerberosInitiator) (_ func(), resultErr error) {
	cleanup := func() { _ = initiator.Close() }
	success := false
	defer func() {
		if !success {
			cleanup()
			c.closeLocked()
		}
	}()
	c.gss = &rpcGSS{context: initiator, nfsVersion: nfsVersion, rpcVersion: k.RPCVersion}
	if security == "krb5i" {
		c.gss.service = 2
	}
	if security == "krb5p" {
		c.gss.service = 3
	}
	flags := gssapi.ContextFlagMutual | gssapi.ContextFlagInteg
	if security == "krb5p" {
		flags |= gssapi.ContextFlagConf
	}
	token, more, err := initiator.Initiate(k.SPN, flags, nil)
	if err != nil {
		return nil, fmt.Errorf("kerberos service ticket: %w", err)
	}
	if !more {
		return nil, errors.New("kerberos mutual authentication did not request a server token")
	}
	// Kerberos AP_REQ/AP_REP completes in one exchange. Other GSS mechanisms and
	// multi-round negotiation are intentionally unsupported, never downgraded.
	var args encoder
	args.opaque(token)
	d, err := c.callLocked(ctx, nfsProgram, nfsVersion, 0, nil, args, 1)
	if err != nil {
		return nil, fmt.Errorf("RPCSEC_GSS INIT: %w", err)
	}
	handle := append([]byte(nil), d.opaque(380)...)
	major, minor, window := d.u32(), d.u32(), d.u32()
	serverToken := d.opaque(1 << 20)
	if d.err != nil {
		return nil, d.err
	}
	if major != 0 {
		return nil, fmt.Errorf("RPCSEC_GSS INIT rejected or incomplete (major=%d minor=%d)", major, minor)
	}
	if len(d.b) != 0 || len(handle) == 0 || window == 0 {
		return nil, errors.New("invalid RPCSEC_GSS INIT response")
	}
	finalToken, more, err := initiator.Initiate(k.SPN, flags, serverToken)
	if err != nil {
		return nil, fmt.Errorf("kerberos server authentication: %w", err)
	}
	if more || len(finalToken) != 0 || !initiator.Established() {
		return nil, errors.New("incomplete Kerberos mutual authentication")
	}
	if err := c.gss.verify(d, window); err != nil {
		return nil, err
	}
	if security == "krb5p" {
		if err := initiator.CanSeal(); err != nil {
			return nil, err
		}
	}
	c.gss.handle, c.gss.established, c.gss.window = handle, true, window
	c.gss.expiry = initiator.Expiry()
	if err := c.gss.checkExpiry(time.Now()); err != nil {
		return nil, err
	}
	// Adapt to short tickets without authenticating on every RPC. Long tickets
	// renew at most 30 seconds early, within one RPC timeout of their endtime.
	margin := min(time.Until(c.gss.expiry)/5, 30*time.Second, c.timeout)
	c.gss.renewAt = c.gss.expiry.Add(-margin)
	if k.Provider != "sspi" {
		if err := k.configSnapshot.Verify(); err != nil {
			return nil, err
		}
	}
	success = true
	return cleanup, nil
}

// Renew only before sending a new operation, never in response to a failed RPC.
// Keep the same transport, SPN, principal, protection and NFS session/state IDs.
func (c *rpcClient) renewKerberosLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.closing || c.kerberos == nil || c.gss == nil {
		return nil
	}
	old := c.gss
	if !old.established {
		c.closeLocked()
		return errors.New("kerberos context unavailable; reconnect (no request replay)")
	}
	// The session owner checks/renews before assembling SEQUENCE. Rechecking
	// here could rotate underneath its slot or recursively enter v4.mu.
	if expected, _ := ctx.Value(backchannelContextKey{}).(*rpcGSS); c.backchannel != nil && expected == old {
		return nil
	}
	if c.backchannelRenewing {
		return errors.New("callback context renewal in progress; request not sent")
	}
	if time.Now().Before(old.renewAt) && old.seq < 0x7ffffffe {
		return nil
	}
	if c.pinnedBackchannelGSS {
		c.closeLocked()
		return errors.New("backchannel Kerberos context needs renewal; reconnect explicitly without replay")
	}
	s := c.kerberos
	oldCleanup := s.cleanup
	s.cleanup = nil
	if oldCleanup != nil {
		defer oldCleanup()
	}
	cleanup, err := c.establishKerberosLocked(ctx, s.config, s.security, s.version)
	if err != nil {
		c.closeLocked()
		return fmt.Errorf("kerberos renewal failed; pending NFS request not sent, reconnect: %w", err)
	}
	s.cleanup = cleanup
	fresh := c.gss
	// Expired contexts cannot sign DESTROY; let the server expire those. A
	// live old context is destroyed once, under the same overall deadline.
	if time.Now().Before(old.expiry) && old.seq < 0x7fffffff {
		c.gss = old
		_, err = c.callLocked(ctx, nfsProgram, old.nfsVersion, 0, nil, nil, 3)
		c.gss = fresh
		if err != nil {
			c.closeLocked()
			cleanup()
			s.cleanup = nil
			return fmt.Errorf("kerberos previous context teardown failed; pending NFS request not sent, reconnect: %w", err)
		}
	}
	s.renewals++
	return nil
}

func (c *rpcClient) destroyKerberos(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.gss == nil || !c.gss.established {
		return
	}
	_, _ = c.callLocked(ctx, nfsProgram, c.gss.nfsVersion, 0, nil, nil, 3)
	c.gss.established = false
}
