package gssapi

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"path/filepath"
	"strings"
	"time"

	stdcontext "context"
	"github.com/go-logr/logr"
	upstreamclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	ianaflags "github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	client "nfsclient/internal/krbclient"
	"nfsclient/internal/krbconfig"
	"nfsclient/internal/resolve"
)

// Initiator represents the client side of the GSSAPI protocol.
type Initiator struct {
	context

	config              string
	configProvided      bool
	configSnapshot      *krbconfig.Snapshot
	domain              string
	username            string
	password            string
	keytab              *string
	ccache              string
	fileRenewal         *FileCacheRenewal
	kcmSocket           string
	asAlias             string
	enterpriseUPN       string
	asStartRealm        string
	asRealms            []string
	asHelper, fastArmor string
	requireFAST         bool
	pkinit              PKINITFiles

	client         *client.Client
	networkContext stdcontext.Context
	dns            resolve.Config

	logger logr.Logger
}

func (ctx *Initiator) loadConfig() (*config.Config, *client.CAPaths, error) {
	text := ctx.config
	if !ctx.configProvided && text == "" {
		path, err := findFile(ctx.logger, krb5Config, []string{"/etc/krb5.conf"})
		if err != nil {
			return nil, nil, err
		}
		snapshot, err := krbconfig.Load(path)
		if err != nil {
			return nil, nil, err
		}
		ctx.configSnapshot = snapshot
		text = snapshot.Text()
	}
	if ctx.configSnapshot != nil {
		if err := ctx.configSnapshot.Verify(); err != nil {
			return nil, nil, err
		}
		text = ctx.configSnapshot.Text()
	}
	text, err := krbconfig.Normalize(text)
	if err != nil {
		return nil, nil, err
	}
	paths, err := client.ParseCAPaths(text)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.NewFromString(text)
	return cfg, paths, err
}

func (ctx *Initiator) usePassword() bool {
	return ctx.domain != "" && ctx.username != "" && ctx.password != ""
}

func (ctx *Initiator) useKeytab() bool {
	return ctx.domain != "" && ctx.username != "" && ctx.keytab != nil
}

func (ctx *Initiator) newClient() (*client.Client, error) {
	if err := ValidateCCacheSelection(ctx.ccache, ctx.kcmSocket); err != nil {
		return nil, err
	}
	cfg, paths, err := ctx.loadConfig()
	if err != nil {
		return nil, err
	}

	settings := []func(*client.Settings){
		client.DisablePAFXFAST(true),
		client.NetworkContext(ctx.networkContext),
		client.DNS(ctx.dns),
		client.TrustPaths(paths),
	}
	if ctx.asAlias != "" {
		if _, err := client.ValidateASAlias(ctx.asAlias, ctx.domain); err != nil {
			return nil, err
		}
		if !ctx.useKeytab() || ctx.keytab == nil || *ctx.keytab == "" || ctx.ccache != "" {
			return nil, errors.New("--as-alias requires an explicit canonical keytab")
		}
		settings = append(settings, client.ProtectedASAlias(ctx.asAlias))
	}
	if ctx.enterpriseUPN != "" || ctx.asStartRealm != "" || len(ctx.asRealms) > 0 {
		if ctx.asAlias != "" || !ctx.useKeytab() || ctx.keytab == nil || *ctx.keytab == "" || ctx.ccache != "" {
			return nil, errors.New("enterprise AS requires only an explicit canonical keytab")
		}
		if err := client.ValidateEnterpriseAS(ctx.enterpriseUPN, ctx.asStartRealm, ctx.domain, ctx.asRealms); err != nil {
			return nil, err
		}
		settings = append(settings, client.EnterpriseAS(ctx.enterpriseUPN, ctx.asStartRealm, ctx.asRealms))
	}
	if ctx.pkinit.Selected() {
		if ctx.keytab != nil || ctx.ccache != "" || ctx.password != "" || ctx.asAlias != "" || ctx.enterpriseUPN != "" || ctx.asStartRealm != "" || len(ctx.asRealms) > 0 {
			return nil, errors.New("PKINIT selects only an explicit canonical certificate identity")
		}
		if err := ValidatePKINITFAST(ctx.asHelper, ctx.fastArmor, ctx.requireFAST); err != nil {
			return nil, err
		}
		if err := ValidatePKINIT(ctx.asHelper, ctx.pkinit); err != nil {
			return nil, err
		}
		if !ctx.configProvided {
			return nil, errors.New("PKINIT needs explicit Kerberos configuration")
		}
		if ctx.asHelper == "" {
			cl := client.NewWithPassword(ctx.username, ctx.domain, "", cfg, settings...)
			files := client.PKINITIdentity{Cert: ctx.pkinit.Cert, Key: ctx.pkinit.Key, CA: ctx.pkinit.CA, CRL: ctx.pkinit.CRL}
			var loginErr error
			if ctx.requireFAST {
				armor, err := credentials.LoadCCache(strings.TrimPrefix(ctx.fastArmor, "FILE:"))
				if err != nil {
					cl.Destroy()
					return nil, err
				}
				defer clearNativeCache(armor)
				loginErr = cl.LoginFASTPKINIT(files, armor)
			} else {
				loginErr = cl.LoginPKINIT(files)
			}
			if loginErr != nil {
				cl.Destroy()
				return nil, loginErr
			}
			return cl, nil
		}
		nativeConfig, err := nativeASConfiguration(cfg, ctx.domain)
		if err != nil {
			return nil, err
		}
		nativeConfig += "[libdefaults]\n pkinit_eku_checking = kpKDC\n pkinit_dh_min_bits = 2048\n preferred_preauth_types = 16\n[plugins]\n clpreauth = {\n  enable_only = pkinit\n }\n"
		cache, err := runPKINIT(ctx.networkContext, ctx.asHelper, ctx.username+"@"+ctx.domain, nativeConfig, ctx.pkinit)
		if err != nil {
			return nil, err
		}
		cl, err := client.NewFromCCache(cache, cfg, settings...)
		if err != nil {
			clearNativeCache(cache)
			if cl != nil {
				cl.Destroy()
			}
		}
		return cl, err
	}
	if err := ValidateNativeAS(ctx.asHelper, ctx.fastArmor, ctx.requireFAST); err != nil {
		return nil, err
	}
	if ctx.requireFAST {
		if !ctx.useKeytab() || ctx.keytab == nil || *ctx.keytab == "" || ctx.ccache != "" || ctx.asAlias != "" || ctx.enterpriseUPN != "" {
			return nil, errors.New("required FAST needs only an explicit canonical keytab")
		}
		if !ctx.configProvided {
			return nil, errors.New("required FAST needs explicit Kerberos configuration")
		}
		if ctx.asHelper == "" {
			armor, err := credentials.LoadCCache(strings.TrimPrefix(ctx.fastArmor, "FILE:"))
			if err != nil {
				return nil, err
			}
			defer clearNativeCache(armor)
			kt, err := keytab.Load(*ctx.keytab)
			if err != nil {
				return nil, err
			}
			cl := client.NewWithKeytab(ctx.username, ctx.domain, kt, cfg, settings...)
			if err := cl.LoginFAST(armor); err != nil {
				cl.Destroy()
				return nil, err
			}
			return cl, nil
		}
		nativeConfig, err := nativeASConfiguration(cfg, ctx.domain)
		if err != nil {
			return nil, err
		}
		keyPath, err := filepath.Abs(*ctx.keytab)
		if err != nil {
			return nil, err
		}
		cache, err := runRequiredFAST(ctx.networkContext, ctx.asHelper, ctx.fastArmor, keyPath, ctx.username+"@"+ctx.domain, nativeConfig)
		if err != nil {
			return nil, err
		}
		return client.NewFromCCache(cache, cfg, settings...)
	}

	switch {
	case ctx.ccache != "":
		cache, err := readSelectedCCache(ctx.networkContext, ctx.ccache, ctx.kcmSocket, ctx.username+"@"+ctx.domain)
		if err != nil {
			return nil, err
		}
		return ctx.newSelectedCacheClient(cache, cfg, settings)
	case ctx.usePassword():
		return client.NewWithPassword(ctx.username, ctx.domain, ctx.password, cfg, settings...), nil
	case ctx.useKeytab():
		var kt *keytab.Keytab

		if *ctx.keytab != "" {
			kt, err = readKeytab(*ctx.keytab)
		} else {
			kt, err = loadClientKeytab(ctx.logger)
		}

		if err != nil {
			return nil, err
		}

		return client.NewWithKeytab(ctx.username, ctx.domain, kt, cfg, settings...), nil
	}

	ctx.logger.Info("using default session")

	cache, err := loadCCache(ctx.logger)
	if err != nil {
		return nil, err
	}

	return client.NewFromCCache(cache, cfg, settings...)
}

// NewInitiator returns a new Initiator.
func NewInitiator(options ...Option[Initiator]) (*Initiator, error) {
	ctx := &Initiator{
		context: context{
			sequenceMask: math.MaxUint32,
			logger:       logr.Discard(),
		},
		logger: logr.Discard(),
	}

	var err error

	for _, option := range options {
		if err = option(ctx); err != nil {
			return nil, err
		}
	}

	if ctx.client, err = ctx.newClient(); err != nil {
		return nil, err
	}

	if err = ctx.client.AffirmLogin(); err != nil {
		ctx.client.Destroy()
		return nil, err
	}

	return ctx, nil
}

// Close releases any resources held by the Initiator.
func (ctx *Initiator) Close() error {
	ctx.client.Destroy()

	return nil
}

// Initiate creates a new context targeting the service with the desired flags
// along with the initial input token, which will initially be nil. The output
// token is returned and whether another round is required.
//
//nolint:cyclop,funlen
func (ctx *Initiator) Initiate(service string, flags int, input []byte) ([]byte, bool, error) {
	if ctx.configSnapshot != nil {
		if err := ctx.configSnapshot.Verify(); err != nil {
			return nil, false, err
		}
	}
	if ctx.established {
		return nil, false, nil
	}

	var err error

	//nolint:nestif
	if len(input) == 0 {
		ctx.flags = flags & supportedFlags

		var ticket messages.Ticket

		if ticket, ctx.key, err = ctx.client.GetServiceTicket(strings.ReplaceAll(service, "@", "/")); err != nil {
			return nil, false, err
		}

		var ok bool
		ctx.expiry, ok = ctx.client.ServiceTicketExpiry(ticket.SName.PrincipalNameString())
		if !ok || !time.Now().Before(ctx.expiry) {
			return nil, false, errors.New("service ticket is expired or has no authenticated expiry")
		}
		ctx.peerName = fmt.Sprintf("%s@%s", ticket.SName.PrincipalNameString(), ticket.Realm)

		f := make([]int, 0, bits.OnesCount(uint(ctx.flags)))

		for i := 0; i < bits.Len(supportedFlags); i++ {
			if ctx.flags&(1<<i) != 0 {
				f = append(f, 1<<i)
			}
		}

		apreq, err := spnego.NewKRB5TokenAPREQ(&upstreamclient.Client{Credentials: ctx.client.Credentials}, ticket, ctx.key, f, nil)
		if err != nil {
			return nil, false, err
		}

		if ctx.doMutual() {
			types.SetFlag(&apreq.APReq.APOptions, ianaflags.APOptionMutualRequired)
		}

		if err = apreq.APReq.DecryptAuthenticator(ctx.key); err != nil {
			return nil, false, err
		}
		if ctx.channelBinding != nil {
			auth := apreq.APReq.Authenticator
			hash := channelBindingHash(ctx.channelBinding)
			if len(auth.Cksum.Checksum) != 24 {
				return nil, false, errors.New("unexpected generated GSS authenticator checksum")
			}
			copy(auth.Cksum.Checksum[4:20], hash[:])
			bound, err := messages.NewAPReq(ticket, ctx.key, auth)
			if err != nil {
				return nil, false, err
			}
			bound.APOptions = apreq.APReq.APOptions
			bound.Authenticator = auth
			apreq.APReq = bound
		}

		ctx.sequenceNumber = uint64(apreq.APReq.Authenticator.SeqNumber)

		ctx.ctime = apreq.APReq.Authenticator.CTime
		ctx.cusec = apreq.APReq.Authenticator.Cusec

		output, err := apreq.Marshal()
		if err != nil {
			return nil, false, err
		}

		if !ctx.doMutual() {
			ctx.established = true
			ctx.baseSequenceNumber = ctx.sequenceNumber
		}

		return output, true, nil
	}

	if !ctx.doMutual() {
		return nil, false, errors.New("not mutual")
	}

	var aprep spnego.KRB5Token
	if err = aprep.Unmarshal(input); err != nil {
		return nil, false, err
	}

	if aprep.IsKRBError() {
		return nil, false, errors.New("received Kerberos error")
	}

	if !aprep.IsAPRep() {
		return nil, false, errors.New("didn't receive an AP-REP")
	}

	b, err := crypto.DecryptEncPart(aprep.APRep.EncPart, ctx.key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, false, krberror.Errorf(err, krberror.DecryptingError, "error decrypting AP-REP enc-part")
	}

	var payload messages.EncAPRepPart
	if err = payload.Unmarshal(b); err != nil {
		return nil, false, krberror.Errorf(err, krberror.EncodingError, "error unmarshalling decrypted AP-REP enc-part")
	}

	ctx.baseSequenceNumber = uint64(payload.SequenceNumber)

	if payload.Subkey.KeyType != 0 {
		ctx.peerSubkey = payload.Subkey
	}

	// Use Round()) to strip off any monotonic clock reading
	if !ctx.ctime.Round(0).Equal(payload.CTime.UTC()) || ctx.cusec != payload.Cusec {
		return nil, false, errors.New("mutual failed")
	}

	ctx.established = true

	return nil, false, nil
}

// WithNetworkContext supplies the caller-owned KDC setup deadline and cancellation.
func WithNetworkContext(networkContext stdcontext.Context) Option[Initiator] {
	return func(c *Initiator) error { c.networkContext = networkContext; return nil }
}

// WithDNS configures KDC discovery without changing process-global DNS settings.
func WithDNS(cfg resolve.Config) Option[Initiator] {
	return func(c *Initiator) error {
		if err := cfg.Validate(); err != nil {
			return err
		}
		c.dns = cfg
		return nil
	}
}

// WithCCache selects one explicit credential cache; ambient caches are not consulted.
func WithCCache(path string) Option[Initiator] {
	return func(c *Initiator) error { c.ccache = path; return nil }
}

func WithKCMSocket(path string) Option[Initiator] {
	return func(c *Initiator) error { c.kcmSocket = path; return nil }
}

func WithASAlias(alias string) Option[Initiator] {
	return func(c *Initiator) error { c.asAlias = alias; return nil }
}

func WithEnterpriseAS(upn, start string, realms []string) Option[Initiator] {
	return func(c *Initiator) error {
		c.enterpriseUPN = upn
		c.asStartRealm = start
		c.asRealms = append([]string(nil), realms...)
		return nil
	}
}

func WithRequiredFAST(helper, armor string) Option[Initiator] {
	return func(c *Initiator) error { c.asHelper = helper; c.fastArmor = armor; c.requireFAST = true; return nil }
}
