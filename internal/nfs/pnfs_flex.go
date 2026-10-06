package nfs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"strconv"
)

// Flex Files supports loose NFSv3 and tight NFSv4.1/4.2 devices over TCP.
// MDS state, recalls and publication stay v4.1+.
type flexLayout struct {
	stripe   uint64
	mirrors  [][]*flexDS
	selected []*flexDS
	flags    uint32
}

type flexDS struct {
	device, state    []byte
	efficiency       uint32
	handles          [][]byte
	uid, gid         uint32
	owner, group     string
	major, minor     uint32
	endpoints        []string
	handle           []byte
	rsize, wsize     uint32
	deviceGeneration uint64
}

func flexNumericID(s string) (uint32, error) {
	if s == "" || len(s) > 10 || len(s) > 1 && s[0] == '0' {
		return 0, errors.New("flex Files requires canonical numeric synthetic UID/GID")
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("flex Files requires numeric synthetic UID/GID")
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

func decodeFlexLayout(d *decoder) *flexLayout {
	l := &flexLayout{stripe: d.u64()}
	mirrors := d.u32()
	if mirrors < 1 || mirrors > 8 {
		d.err = errors.New("flex Files requires 1..8 mirrors")
		return l
	}
	total, width := uint32(0), uint32(0)
	for i := uint32(0); i < mirrors; i++ {
		count := d.u32()
		total += count
		if count < 1 || count > 64 || total > 64 || i > 0 && count != width {
			d.err = errors.New("invalid Flex Files stripe count or total DS limit")
			return l
		}
		width = count
		mirror := make([]*flexDS, 0, count)
		for j := uint32(0); j < count; j++ {
			ds := &flexDS{device: append([]byte(nil), d.take(16)...), efficiency: d.u32(), state: append([]byte(nil), d.take(16)...)}
			versions := d.u32()
			if versions < 1 || versions > 8 {
				d.err = errors.New("flex Files requires 1..8 version handles")
				return l
			}
			for k := uint32(0); k < versions; k++ {
				h := d.opaque(128)
				if len(h) == 0 {
					d.err = errors.New("empty Flex Files handle")
					return l
				}
				ds.handles = append(ds.handles, append([]byte(nil), h...))
			}
			ds.owner, ds.group = string(d.opaque(1024)), string(d.opaque(1024))
			if d.err != nil {
				return l
			}
			mirror = append(mirror, ds)
		}
		l.mirrors = append(l.mirrors, mirror)
	}
	l.flags = d.u32()
	d.u32() // Statistics collection is optional; no periodic timer.
	if d.err != nil {
		return l
	}
	if len(d.b) != 0 || l.flags & ^uint32(15) != 0 || width == 1 && l.stripe != 0 || width > 1 && (l.stripe == 0 || l.stripe > math.MaxUint64/uint64(width)) {
		d.err = errors.New("invalid Flex Files stripe unit, flags or trailing data")
		return l
	}
	// Equal stripe widths make sums comparable. Ties keep advertised order.
	var best uint64
	for i, mirror := range l.mirrors {
		var score uint64
		for _, ds := range mirror {
			score += uint64(ds.efficiency)
		}
		if i == 0 || score > best {
			best = score
			l.selected = mirror
		}
	}
	return l
}

func decodeFlexDevice(d *decoder, ds *flexDS, options PNFSOptions) {
	paths := d.u32()
	if paths < 1 || paths > 8 {
		d.err = errors.New("flex Files requires 1..8 device paths")
		return
	}
	for i := uint32(0); i < paths; i++ {
		network, address := d.str(), d.str()
		endpoint, err := universalEndpoint(network, address)
		if err != nil {
			d.err = err
			return
		}
		if target, ok := options.DataServers[endpoint]; ok && !slices.Contains(ds.endpoints, target) {
			ds.endpoints = append(ds.endpoints, target)
		}
	}
	versions := d.u32()
	// Stock FreeBSD 14.4 advertises tight 4.2/4.1 but sends only the first
	// handle. Accept that exact shape, using index zero exclusively; never
	// invent a handle for the second version or retry with another protocol.
	freeBSDPrefix := versions == 2 && len(ds.handles) == 1
	if versions != uint32(len(ds.handles)) && !freeBSDPrefix {
		d.err = errors.New("flex Files version/handle counts differ")
		return
	}
	for i := uint32(0); i < versions; i++ {
		major, minor, rsize, wsize := d.u32(), d.u32(), d.u32(), d.u32()
		tight := d.boolean()
		if freeBSDPrefix && (major != 4 || minor != 2-i || !tight || i == 0 && rsize == 0) {
			d.err = errors.New("unsupported Flex Files version/handle prefix")
			return
		}
		if major == 3 && (minor != 0 || tight) {
			d.err = errors.New("invalid NFSv3 Flex Files coupling")
			return
		}
		supported := major == 3 && minor == 0 && !tight || major == 4 && (minor == 1 || minor == 2) && tight
		if ds.handle == nil && supported && rsize != 0 && i < uint32(len(ds.handles)) {
			if major == 3 && len(ds.handles[i]) > 64 {
				d.err = errors.New("NFSv3 Flex Files handle exceeds 64 bytes")
				return
			}
			ds.handle, ds.rsize = ds.handles[i], rsize
			ds.wsize = wsize
			ds.major, ds.minor = major, minor
		}
	}
	if d.err != nil {
		return
	}
	if len(d.b) != 0 || ds.handle == nil {
		d.err = errors.New("flex Files requires loose NFSv3 or tight NFSv4.1/4.2 over TCP")
		return
	}
}

func (v *v4Client) prepareFlexDevices(ctx context.Context, l *flexLayout, o PNFSOptions) error {
	for _, ds := range l.selected {
		if _, err := v.fetchFlexDevice(ctx, ds, o); err != nil {
			return err
		}
		if len(ds.endpoints) == 0 {
			return errors.New("unapproved Flex Files data server")
		}
		// RFC 8435 5.1: tight coupling MUST ignore synthetic owner/group.
		// Local identity restrictions must not invalidate a decoded MDS reply.
		if ds.major == 3 {
			if v.c.Security() != "sys" || v.c.config.Security != "" && v.c.config.Security != "sys" {
				return errors.New("kerberos Flex Files requires tightly coupled NFSv4 data servers")
			}
			var err error
			ds.uid, err = flexNumericID(ds.owner)
			if err != nil {
				return err
			}
			ds.gid, err = flexNumericID(ds.group)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *v4Client) fetchFlexDevice(ctx context.Context, ds *flexDS, o PNFSOptions) ([]byte, error) {
	var generation uint64
	if o.RefreshDevices {
		v.recall.mu.Lock()
		generation = v.recall.devices[string(ds.device)].generation
		v.recall.mu.Unlock()
	}
	e := append(encoder(nil), ds.device...)
	e.u32(4)
	e.u32(32768)
	if o.RefreshDevices {
		bitmap4(&e, 1, 2)
	} else {
		e.u32(0)
	}
	var body []byte
	var notifications []uint32
	op := op4(47, e, func(d *decoder) {
		if d.u32() != 4 {
			d.err = errors.New("unexpected Flex Files device type")
			return
		}
		body = d.opaque(32768)
		sub := &decoder{b: body}
		decodeFlexDevice(sub, ds, o)
		if sub.err != nil {
			d.err = sub.err
			return
		}
		notifications = readBitmap4(d)
		if !o.RefreshDevices && len(notifications) != 0 {
			d.err = errors.New("unsolicited Flex Files device notification")
		}
	})
	var status Status
	op.result = func(s Status) { status = s }
	op.failure = func(d *decoder) {
		if status == 10005 {
			d.u32()
		}
	}
	if err := v.compound(ctx, op); err != nil {
		return nil, err
	}
	if o.RefreshDevices && !slices.Equal(notifications, []uint32{1, 2}) {
		return nil, errors.New("flex server did not accept both requested device notifications")
	}
	ds.deviceGeneration = generation
	return body, nil
}

func (l *flexLayout) position(offset uint64) (*flexDS, uint64) {
	if len(l.selected) == 1 {
		return l.selected[0], math.MaxUint64 - offset
	}
	stripe := offset / l.stripe
	return l.selected[stripe%uint64(len(l.selected))], l.stripe - offset%l.stripe
}

func (c *Client) pnfsFlexServers(ctx context.Context, policies map[string]*tls.Config, authConfigs map[string]Config, usable func() error) (func(*flexDS) (*Client, string, error), func(*pnfsRead) error, func(*pnfsRead), func()) {
	type key struct {
		endpoint     string
		uid, gid     uint32
		major, minor uint32
	}
	clients := map[key]*Client{}
	failed := map[string]error{}
	closePool := func() {
		for _, ds := range clients {
			ds.Close()
		}
	}
	get := func(component *flexDS, expected *createSessionKey) (*Client, string, error) {
		protected := c.Security() != "sys" || c.config.Security != "" && c.config.Security != "sys"
		if protected && component.major != 4 {
			return nil, "", errors.New("kerberos Flex Files requires tightly coupled NFSv4 data servers")
		}
		var errs []error
		for _, endpoint := range component.endpoints {
			auth, authenticated := authConfigs[endpoint]
			if protected && (!authenticated || auth.Security != c.Security() || auth.Kerberos.Principal != c.principal || auth.Kerberos.SPN == "") {
				return nil, "", errors.New("flex Files DS requires the original Kerberos identity, service and an explicit SPN")
			}
			if err := errors.Join(ctx.Err(), usable()); err != nil {
				return nil, "", err
			}
			k := key{endpoint, component.uid, component.gid, component.major, component.minor}
			if ds := clients[k]; ds != nil {
				if expected != nil && (ds.v4 == nil || ds.v4.serverIdentity == nil || *ds.v4.serverIdentity != *expected) {
					return nil, "", errors.New("flex alternate has a different server identity")
				}
				return ds, endpoint, nil
			}
			if err := failed[endpoint]; err != nil {
				errs = append(errs, err)
				continue
			}
			if len(clients) >= 64 {
				return nil, "", errors.New("flex Files connection/identity limit reached")
			}
			host, port, _ := net.SplitHostPort(endpoint)
			p, _ := strconv.Atoi(port)
			rpc, err := dialRPC(ctx, host, p, c.config.Timeout, c.config.ReservedPort)
			if err != nil {
				failed[endpoint] = err
				errs = append(errs, err)
				continue
			}
			ds := &Client{nfs: rpc, version: "3", Auth: Auth{UID: component.uid, GID: component.gid}, ReadSize: c.ReadSize, WriteSize: c.WriteSize}
			if component.major == 4 {
				ds.version, ds.Auth = fmt.Sprintf("4.%d", component.minor), c.Auth
			}
			if policy := policies[endpoint]; policy != nil {
				if err := rpc.startTLS(ctx, nfsProgram, component.major, policy); err != nil {
					ds.Close()
					return nil, "", err
				}
			}
			if component.major == 4 {
				if authenticated {
					if err := ds.authenticateKerberos(ctx, auth); err != nil {
						ds.Close()
						return nil, "", fmt.Errorf("flex Files DS %s Kerberos: %w", endpoint, err)
					}
				}
				ds.v4 = &v4Client{c: ds, minor: component.minor, exchangeRole: 0x40000, clientNonce: append([]byte(nil), c.v4.clientNonce...), creates: c.v4.sessionSequences()}
				if err := ds.v4.initializeExpected(ctx, expected); err != nil {
					ds.Close()
					return nil, "", err
				}
			}
			if err := errors.Join(ctx.Err(), usable()); err != nil {
				ds.Close()
				return nil, "", err
			}
			clients[k] = ds
			return ds, endpoint, nil
		}
		return nil, "", fmt.Errorf("all approved Flex Files paths failed: %w", errors.Join(errs...))
	}
	retire := func(r *pnfsRead) {
		for k, client := range clients {
			if client == r.ds {
				delete(clients, k)
			}
		}
		failed[r.endpoint] = errors.New("flex DS transport failed during READ")
		r.ds.Close()
	}
	usedRecovery := map[createSessionKey]bool{}
	recoverRead := func(r *pnfsRead) error {
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return err
		}
		if r.flex == nil || r.flex.major != 4 || r.ds.v4 == nil {
			return errors.New("flex read recovery requires tight NFSv4")
		}
		identity := r.ds.v4.serverIdentity
		original, ok := authConfigs[r.endpoint]
		if identity == nil || !ok || (original.Security != "krb5i" && original.Security != "krb5p") || original.Kerberos.SPN == "" {
			return errors.New("flex failed DS has no protected server identity")
		}
		if usedRecovery[*identity] {
			return errors.New("flex read recovery already used for this DS identity")
		}
		usedRecovery[*identity] = true
		retire(r)
		var alternates []string
		for _, endpoint := range r.flex.endpoints {
			if failed[endpoint] != nil {
				continue
			}
			candidate, ok := authConfigs[endpoint]
			if !ok || candidate.Security != original.Security || candidate.Kerberos.SPN != original.Kerberos.SPN || candidate.Kerberos.Principal != original.Kerberos.Principal {
				return errors.New("flex alternate requires original protected identity and SPN")
			}
			alternates = append(alternates, endpoint)
		}
		component := *r.flex
		component.endpoints = alternates
		ds, endpoint, err := get(&component, identity)
		if err != nil {
			return err
		}
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return err
		}
		r.ds, r.endpoint = ds, endpoint
		return nil
	}
	return func(component *flexDS) (*Client, string, error) { return get(component, nil) }, recoverRead, retire, closePool
}

func readFlexComponent(ctx context.Context, r *pnfsRead, usable func() error) error {
	for uint32(len(r.data)) < r.limit {
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return err
		}
		remaining := min(r.limit-uint32(len(r.data)), r.flex.rsize, r.ds.ReadSize, uint32(1<<20))
		if remaining == 0 {
			return errors.New("invalid Flex read request size")
		}
		data, eof, err := readFlexRPC(ctx, r, remaining)
		if err != nil {
			if ctx.Err() == nil {
				r.ioErr = err
			}
			return err
		}
		r.data = append(r.data, data...)
		if eof {
			r.data = append(r.data, make([]byte, int(r.limit)-len(r.data))...)
			break
		}
		if len(data) == 0 {
			r.ioErr = io.ErrNoProgress
			return r.ioErr
		}
	}
	return errors.Join(ctx.Err(), usable())
}

func readFlexRPC(ctx context.Context, r *pnfsRead, remaining uint32) ([]byte, bool, error) {
	if r.flex.major == 4 {
		// Tight coupling uses the layout's global DS stateid, not OPEN state.
		e := append(encoder(nil), r.flex.state...)
		e.u64(r.offset + uint64(len(r.data)))
		e.u32(remaining)
		var data []byte
		var eof bool
		err := r.ds.v4.compound(ctx, fh4(r.handle), op4(25, e, func(d *decoder) {
			eof = d.boolean()
			data = append([]byte(nil), d.opaque(remaining)...)
		}))
		return data, eof, err
	}
	var e encoder
	e.opaque(r.handle)
	e.u64(r.offset + uint64(len(r.data)))
	e.u32(remaining)
	d, err := r.ds.call(ctx, 6, e)
	if err != nil {
		return nil, false, err
	}
	postAttr(d)
	count := d.u32()
	eof := d.boolean()
	data := d.opaque(remaining)
	if d.err != nil {
		return nil, false, d.err
	}
	if count != uint32(len(data)) || len(d.b) != 0 {
		return nil, false, errors.New("invalid Flex Files READ count or trailing data")
	}
	return data, eof, nil
}

type flexIOError struct {
	offset, length uint64
	device         []byte
	status         uint32
	op             uint32
}

func (r *layoutRecall) layoutKind() uint32 {
	if r.layoutType == 0 {
		return 1
	}
	return r.layoutType
}
func (r *layoutRecall) flexReturnBody() encoder {
	if r.layoutKind() != 4 {
		return nil
	}
	var e encoder
	e.u32(uint32(len(r.flexErrors)))
	for _, failure := range r.flexErrors {
		e.u64(failure.offset)
		e.u64(failure.length)
		e = append(e, r.state...)
		e.u32(1)
		e = append(e, failure.device...)
		e.u32(failure.status)
		e.u32(failure.op)
	}
	e.u32(0)
	return e
}
func (v *v4Client) recordFlexError(ds *flexDS, offset, length uint64, err error) {
	v.recordFlexOpError(ds, offset, length, 25, err)
}

func (v *v4Client) recordFlexOpError(ds *flexDS, offset, length uint64, op uint32, err error) {
	if err == nil {
		return
	}
	status := uint32(5)
	var s Status
	var network net.Error
	if errors.As(err, &s) {
		if ds.major == 4 {
			status = uint32(s)
		} else {
			switch uint32(s) {
			case 1, 2, 5, 6, 13, 20, 21, 22, 27, 28, 30, 69, 70, 10001, 10004, 10006, 10007, 10008:
				status = uint32(s)
			}
		}
	} else if retryablePNFSRead(err) || errors.As(err, &network) {
		status = 6
	}
	v.recall.mu.Lock()
	defer v.recall.mu.Unlock()
	// Retain eight recovered transport failures plus a final batch of eight.
	if len(v.recall.flexErrors) < 16 {
		v.recall.flexErrors = append(v.recall.flexErrors, flexIOError{offset, length, append([]byte(nil), ds.device...), status, op})
	}
}
