package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// CopyFromOptions authorizes a destination address and the literal source
// endpoints it may receive. These are server-visible addresses, not NAT
// replacements: RFC 7862 requires the returned source list to remain intact.
type CopyFromOptions struct {
	Destination   string
	SourceServers []string
	SourceSPN     string
	CopyUser      string
	SourceTLSName string
}

// ConnectCopySource opens a separate explicit AUTH_SYS source. Protected callers
// use ConnectCopySourceOptions with an explicit source SPN and mapped username.
func (c *Client) ConnectCopySource(ctx context.Context, endpoint string) (*Client, error) {
	return c.ConnectCopySourceOptions(ctx, endpoint, CopyFromOptions{})
}

func (c *Client) ConnectCopySourceOptions(ctx context.Context, endpoint string, o CopyFromOptions) (*Client, error) {
	if err := validateCopySecurityOptions(o); err != nil {
		return nil, err
	}
	if c.config != nil && c.config.OffloadJournal != "" {
		record, err := InspectOffloadJournal(c.config.OffloadJournal)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil && record.Pending && record.Phase == "issued" {
			return nil, ErrOffloadPending
		}
	}
	canonical, err := pnfsEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if c.config == nil || c.v4 == nil || c.v4.minor != 2 || c.v4.recall == nil || !c.v4.recall.offloadEnabled || c.Transport() != "tcp" {
		return nil, errors.New("copyfrom requires --offload and explicit NFSv4.2/TCP")
	}
	a, _ := netip.ParseAddrPort(canonical)
	if c.Security() == "krb5p" && c.config.Kerberos.RPCVersion == 3 {
		if o.SourceSPN == "" || o.CopyUser == "" {
			return nil, errors.New("secure copyfrom needs explicit source SPN and mapped COPY username")
		}
		if c.TLSActive() && o.SourceTLSName == "" {
			return nil, errors.New("secure COPY over TLS requires an explicit source TLS name")
		}
		cfg := *c.config
		cfg.Host, cfg.NFSPort = a.Addr().String(), int(a.Port())
		cfg.PNFS, cfg.Offload = false, false
		cfg.OffloadJournal = ""
		cfg.OffloadSessionRecovery, cfg.OffloadReconcile = false, false
		c.nfs.mu.Lock()
		if c.nfs.kerberos != nil {
			cfg.Kerberos = c.nfs.kerberos.config
		}
		c.nfs.mu.Unlock()
		cfg.Kerberos.SPN = o.SourceSPN
		cfg.TLS.ServerName = o.SourceTLSName
		if o.SourceTLSName != "" && !cfg.TLS.Enabled {
			return nil, errors.New("source TLS name requires TLS")
		}
		return Connect(ctx, cfg)
	}
	if c.Security() != "sys" || c.TLSActive() || o.SourceSPN != "" || o.CopyUser != "" || o.SourceTLSName != "" {
		return nil, errors.New("secure copyfrom requires RPCSEC_GSS v3 privacy; no fallback")
	}
	auth := c.Auth
	auth.Groups = append([]uint32(nil), auth.Groups...)
	return Connect(ctx, Config{Host: a.Addr().String(), NFSPort: int(a.Port()), Version: "4.2", Transport: "tcp", Security: "sys", Auth: auth, Timeout: c.config.Timeout, ReservedPort: c.config.ReservedPort})
}

func ValidateCopyFromOptions(o CopyFromOptions) error {
	if err := validateCopySecurityOptions(o); err != nil {
		return err
	}
	if _, err := pnfsEndpoint(o.Destination); err != nil {
		return fmt.Errorf("COPY destination: %w", err)
	}
	if len(o.SourceServers) == 0 || len(o.SourceServers) > 64 {
		return errors.New("COPY needs 1..64 approved source IP:port endpoints")
	}
	seen := map[string]bool{}
	for _, server := range o.SourceServers {
		endpoint, err := pnfsEndpoint(server)
		if err != nil {
			return fmt.Errorf("COPY source: %w", err)
		}
		if seen[endpoint] {
			return errors.New("duplicate COPY source endpoint")
		}
		seen[endpoint] = true
	}
	return nil
}

func validateCopySecurityOptions(o CopyFromOptions) error {
	if (o.SourceSPN == "") != (o.CopyUser == "") || o.SourceTLSName != "" && o.SourceSPN == "" {
		return errors.New("source SPN and COPY username must be supplied together")
	}
	if o.SourceSPN != "" && (!strings.HasPrefix(o.SourceSPN, "nfs/") || len(o.SourceSPN) <= 4 || len(o.SourceSPN) > 258 || strings.ContainsAny(o.SourceSPN[4:], "/@ \t\r\n\x00")) {
		return errors.New("COPY source SPN must be nfs/server-hostname")
	}
	user, domain, named := strings.Cut(o.CopyUser, "@")
	if len(o.CopyUser) > 1024 || !utf8.ValidString(o.CopyUser) || strings.ContainsAny(o.CopyUser, "\x00\r\n\t ") || o.CopyUser != "" && (!named || user == "" || domain == "" || strings.Contains(domain, "@")) {
		return errors.New("invalid mapped COPY username")
	}
	if len(o.SourceTLSName) > 253 || strings.ContainsAny(o.SourceTLSName, "\x00\r\n\t /@") {
		return errors.New("invalid COPY source TLS name")
	}
	return nil
}

func copyNetaddr(endpoint string) encoder {
	a, _ := netip.ParseAddrPort(endpoint)
	var e encoder
	e.u32(3) // NL4_NETADDR: no implicit hostname resolution by the destination.
	network := "tcp"
	if a.Addr().Unmap().Is6() {
		network = "tcp6"
	}
	e.str(network)
	e.str(fmt.Sprintf("%s.%d.%d", a.Addr().Unmap(), a.Port()>>8, a.Port()&255))
	return e
}

type copyGrant struct {
	id                     []byte
	locations              encoder
	endpoints              []string
	expires                time.Time
	recorded, proofExpires time.Time
}

func decodeCopyGrant(d *decoder, started time.Time) (g copyGrant) {
	g.recorded = time.Now()
	seconds, nanos := d.u64(), d.u32()
	if seconds > 1<<63-1 || nanos >= 1e9 {
		d.err = errors.New("invalid COPY_NOTIFY lease")
		return
	}
	if seconds != 0 || nanos != 0 {
		// The operation's own wait is at most 24h; cap larger grants safely.
		g.expires = started.Add(time.Duration(min(seconds, 86400))*time.Second + time.Duration(nanos))
		if seconds <= uint64((1<<63-1-int64(nanos))/int64(time.Second)) {
			g.proofExpires = g.recorded.Add(time.Duration(seconds)*time.Second + time.Duration(nanos))
		}
	}
	g.id = bytes.Clone(d.take(16))
	if bytes.Equal(g.id, make([]byte, 16)) || bytes.Equal(g.id, bytes.Repeat([]byte{255}, 16)) {
		d.err = errors.New("invalid COPY_NOTIFY authorization stateid")
		return
	}
	count := d.u32()
	if count == 0 || count > 64 {
		d.err = errors.New("COPY_NOTIFY source count must be 1..64")
		return
	}
	g.locations.u32(count)
	for range count {
		kind := d.u32()
		g.locations.u32(kind)
		switch kind {
		case 1, 2:
			g.locations.str(d.str())
			g.endpoints = append(g.endpoints, "") // Parsed, but not approved for forwarding.
		case 3:
			network, address := d.str(), d.str()
			g.locations.str(network)
			g.locations.str(address)
			endpoint, _ := universalEndpoint(network, address)
			g.endpoints = append(g.endpoints, endpoint)
		default:
			d.err = errors.New("invalid COPY_NOTIFY location discriminant")
			return
		}
	}
	return
}

func (v *v4Client) revokeCopyGrant(fh, id []byte, children ...*rpcGSS) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := v.compoundGSS(ctx, optionalGSSChild(children), fh4(fh), op4(66, encoder(id), nil)); err != nil {
		v.stateLost.Store(true)
		v.c.nfs.mu.Lock()
		v.c.nfs.closeLocked()
		v.c.nfs.mu.Unlock()
		return fmt.Errorf("COPY source authorization revocation unverified; reconnect; no replay: %w", err)
	}
	return nil
}

// CopyRangeFrom performs one inter-server COPY and waits for completion. Both
// clients must be serialized by the caller. Errors can follow partial writes;
// neither the COPY nor an uncertain authorization is replayed. This bounded
// profile uses either AUTH_SYS/TCP without TLS or matching RPCSEC_GSSv3 privacy
// identities with scoped privileges. Both servers must support the chosen profile.
func (c *Client) CopyRangeFrom(ctx context.Context, sourceClient *Client, source, destination []byte, sourceOffset, destinationOffset, length uint64, wait time.Duration, o CopyFromOptions) (copied uint64, resultErr error) {
	if c.config != nil && c.config.OffloadReconcile {
		return 0, errors.New("automatic reconciliation recording supports synchronous intra-server COPY/CLONE only")
	}
	if sourceClient == nil || sourceClient == c || c.v4 == nil || sourceClient.v4 == nil || c.v4.minor != 2 || sourceClient.v4.minor != 2 {
		return 0, errors.New("inter-server COPY requires two distinct NFSv4.2 clients")
	}
	secure := c.Security() == "krb5p" && sourceClient.Security() == "krb5p" && c.principal != "" && c.principal == sourceClient.principal && c.config != nil && sourceClient.config != nil && c.config.Kerberos.RPCVersion == 3 && sourceClient.config.Kerberos.RPCVersion == 3
	for _, client := range []*Client{c, sourceClient} {
		if client.Transport() != "tcp" || !secure && (client.Security() != "sys" || client.TLSActive()) {
			return 0, errors.New("inter-server COPY currently requires AUTH_SYS/TCP without TLS or matching RPCSEC_GSS v3 privacy identities")
		}
	}
	if len(source) == 0 || len(source) > 128 || len(destination) == 0 || len(destination) > 128 {
		return 0, errors.New("invalid COPY file handle")
	}
	if err := ValidateCopyRange(sourceOffset, destinationOffset, length); err != nil {
		return 0, err
	}
	if err := ValidateOffloadWait(wait); err != nil {
		return 0, err
	}
	if err := ValidateCopyFromOptions(o); err != nil {
		return 0, err
	}
	if secure {
		if o.SourceSPN == "" || o.CopyUser == "" || sourceClient.config == nil || sourceClient.config.Kerberos.SPN != o.SourceSPN {
			return 0, errors.New("secure COPY requires the explicitly authenticated source SPN and mapped username")
		}
		if c.TLSActive() != sourceClient.TLSActive() || c.TLSActive() && (o.SourceTLSName == "" || sourceClient.config.TLS.ServerName != o.SourceTLSName) || !sourceClient.TLSActive() && o.SourceTLSName != "" {
			return 0, errors.New("secure COPY source TLS policy must match the explicit destination policy")
		}
	} else if o.SourceSPN != "" || o.CopyUser != "" || o.SourceTLSName != "" {
		return 0, errors.New("COPY privilege options require RPCSEC_GSS v3 privacy")
	}
	approved := map[string]bool{}
	for _, server := range o.SourceServers {
		endpoint, _ := pnfsEndpoint(server)
		approved[endpoint] = true
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	v, sv := c.v4, sourceClient.v4
	var parent, sourceParent, child, sourceChild *rpcGSS
	var secret []byte
	if secure {
		if c.nfs == nil || sourceClient.nfs == nil {
			return 0, errors.New("secure COPY requires two authenticated parent connections")
		}
		defer func() {
			// Control-procedure uncertainty also invalidates retained NFS state,
			// even when no NFS compound was sent on the affected connection.
			for _, client := range []*Client{c, sourceClient} {
				client.nfs.mu.Lock()
				closed := client.nfs.closed
				client.nfs.mu.Unlock()
				if closed {
					client.v4.stateLost.Store(true)
				}
			}
		}()
		var release, releaseSource func()
		var err error
		parent, release, err = c.nfs.pinCopyParent(ctx)
		if err != nil {
			return 0, err
		}
		defer release()
		sourceParent, releaseSource, err = sourceClient.nfs.pinCopyParent(ctx)
		if err != nil {
			return 0, err
		}
		defer releaseSource()
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return 0, err
		}
		defer clear(secret)
	}
	end, err := v.beginOffload(offloadIntent{Operation: "copyfrom", Source: source, Destination: destination, SourceOffset: sourceOffset, Offset: destinationOffset, Length: length, SourceProfile: sourceClient.offloadProfile(), SourceTarget: sourceClient.offloadTarget()})
	if err != nil {
		return 0, err
	}
	defer end(&resultErr)
	ctx, restoreSource, err := v.trackOffloadEndpoint(ctx, sv, "source")
	if err != nil {
		return 0, err
	}
	defer restoreSource()
	if err := c.prepareOffloadExpectation(ctx, sourceClient, source, destination, sourceOffset, destinationOffset, length, nil); err != nil {
		return 0, err
	}
	if err := sv.checkLockedIO(source, 1); err != nil {
		return 0, err
	}
	if err := v.checkLockedIO(destination, 2); err != nil {
		return 0, err
	}
	srcState, closeSource, err := sv.offloadOpenIO(ctx, source, 1)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeSource()) }()
	dstState, closeDestination, err := v.offloadOpenIO(ctx, destination, 2)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeDestination()) }()
	if err := v.issueOffload(); err != nil {
		return 0, err
	}
	if secure {
		var privilege encoder
		privilege.opaque(secret)
		privilege = append(privilege, copyNetaddr(o.Destination)...)
		privilege.str(o.CopyUser)
		sourceChild, err = sourceClient.nfs.createCopyPrivilege(ctx, sourceParent, "copy_from_auth", privilege)
		clear(privilege)
		if err != nil {
			return 0, err
		}
		defer func() { resultErr = errors.Join(resultErr, sourceClient.nfs.destroyGSSChild(sourceChild)) }()
	}
	e := append(encoder(nil), srcState...)
	e = append(e, copyNetaddr(o.Destination)...)
	started := time.Now()
	var grant copyGrant
	if err := sv.compoundGSS(ctx, sourceChild, fh4(source), op4(61, e, func(d *decoder) { grant = decodeCopyGrant(d, started) })); err != nil {
		var status Status
		if errors.As(err, &status) {
			return 0, err
		}
		return 0, fmt.Errorf("COPY_NOTIFY outcome unverified; source authorization may remain active; no replay: %w", err)
	}
	defer func() {
		err := sv.revokeCopyGrant(source, grant.id, sourceChild)
		if err == nil {
			err = v.recordSourceGrant(grant, true)
		}
		resultErr = errors.Join(resultErr, err)
	}()
	if err := v.recordSourceGrant(grant, false); err != nil {
		return 0, err
	}
	for _, endpoint := range grant.endpoints {
		if endpoint == "" || !approved[endpoint] {
			return 0, errors.New("COPY_NOTIFY returned an unapproved source address; COPY not issued")
		}
	}
	if !grant.expires.IsZero() && !time.Now().Before(grant.expires) {
		return 0, errors.New("COPY_NOTIFY authorization expired before COPY")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := sv.checkLockedIO(source, 1); err != nil {
		return 0, err
	}
	if err := v.checkLockedIO(destination, 2); err != nil {
		return 0, err
	}
	if secure {
		var privilege encoder
		privilege.opaque(secret)
		privilege = append(privilege, grant.locations...)
		privilege.str(o.CopyUser)
		child, err = c.nfs.createCopyPrivilege(ctx, parent, "copy_to_auth", privilege)
		clear(privilege)
		if err != nil {
			return 0, err
		}
		defer func() { resultErr = errors.Join(resultErr, c.nfs.destroyGSSChild(child)) }()
	}
	e = append(encoder(nil), grant.id...)
	e = append(e, dstState...)
	e.u64(sourceOffset)
	e.u64(destinationOffset)
	e.u64(length)
	e.u32(1)
	e.u32(0)
	e = append(e, grant.locations...)
	var reply offloadReply
	if err := v.compoundGSS(ctx, child, fh4(source), op4(32, nil, nil), fh4(destination), op4(60, e, func(d *decoder) {
		reply = decodeOffloadReply(d)
		consecutive, synchronous := d.boolean(), d.boolean()
		if !consecutive || synchronous != (len(reply.id) == 0) || reply.count > length {
			d.err = errors.New("invalid inter-server COPY result")
		}
	})); err != nil {
		var status Status
		if errors.As(err, &status) {
			return 0, err
		}
		return 0, fmt.Errorf("inter-server COPY outcome unverified; destination may have changed; no replay: %w", err)
	}
	reply, err = v.awaitOffload(ctx, destination, reply, length, child)
	if err != nil {
		return 0, err
	}
	if err := sv.checkLockedIO(source, 1); err != nil {
		return reply.count, err
	}
	return v.finishOffload(ctx, destination, destinationOffset, length, reply)
}
