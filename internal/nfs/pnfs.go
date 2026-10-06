package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"nfsclient/internal/iscsi"
	"slices"
	"strconv"
	"strings"
	"time"
)

// PNFSOptions pins advertised data-server addresses to operator-approved
// literal IP endpoints. It also permits explicit NAT mappings. Neither DNS
// resolution nor arbitrary server-directed network connections are implicit.
type PNFSOptions struct {
	// ObjectWrite approves finite secured writes to existing objects only.
	ObjectWrite      bool
	OSDRequireSecure bool
	blockGeometry    string
	// Layout selects "file" (default), "flex", "block", or "object".
	Layout      string
	DataServers map[string]string
	// BlockVolumes explicitly approves local regular-file volume images.
	// Images are identified by all advertised signatures; reads open them read-only.
	BlockVolumes []string
	// BlockTargets approves iscsi://IP:PORT/IQN/LUN storage, independently of
	// MDS security. BlockInitiator is an explicit normalized initiator IQN.
	BlockSecurity       map[string]iscsi.Security
	BlockTargets        []string
	BlockReadAlternates map[string][]string // Primary URL to ordered, equivalent read-only portals.
	BlockInitiator      string
	// OSDTargets approves OSD-1 LUNs for NOSEC/ALLDATA reads and secured range writes.
	OSDSecurity  map[string]iscsi.Security
	OSDTargets   []string
	OSDInitiator string
	// BlockWrite explicitly authorizes in-place modification of approved volumes.
	// Range writes retain an existing whole-file lock; uploads acquire a temporary one.
	BlockWrite bool
	// BlockJournal enables bounded process-crash recovery for block mutations.
	// BlockResume explicitly reconciles the saved operation using fresh state.
	BlockJournal string
	BlockResume  bool
	// SPNs pins each approved DS target to an explicit Kerberos service principal.
	SPNs map[string]string
	// Extend explicitly permits range writes to grow an existing file. Reads
	// ignore this write-only option; ordinary range writes default to no growth.
	Extend bool
	// TLSNames overrides certificate identities by approved target endpoint.
	// Absent entries use that target's literal IP, never the MDS identity.
	TLSNames map[string]string
	// Parallelism bounds concurrent I/O to distinct approved DS endpoints.
	// Zero selects the sequential default; explicit values are 1..8.
	Parallelism int
	// ReadFailover permits one alternate per authenticated DS identity after
	// transport loss. It requires krb5i/krb5p and is forbidden for writes.
	ReadFailover bool
	// WriteFailover permits exact cached WRITE/COMMIT replay on an authenticated
	// alternate connection bound to the original DS session after disconnect.
	WriteFailover bool
	// MirrorFailover permits one Flex mirror switch per segment after protected
	// READ transport loss. It is separate from same-DS path recovery.
	MirrorFailover bool
	// RefreshDevices permits notification-driven mapping/grant recovery at
	// quiescent read or durable write boundaries, retaining the original lock.
	RefreshDevices bool
	// SessionTrunking binds all approved FILE paths to one shared DS session.
	SessionTrunking bool
}

type fileLayout struct {
	object           *objectLayout
	flex             *flexLayout
	block            []blockExtent
	state, device    []byte
	iomode           uint32
	offset, length   uint64
	endpoints        [][]string
	util, first      uint32
	pattern          uint64
	handles          [][]byte
	indices          []uint32
	servers          [][]string
	deviceGeneration uint64
}

func pnfsEndpoint(s string) (string, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil || a.Port() == 0 || a.Addr().Zone() != "" || a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
		return "", fmt.Errorf("invalid pNFS IP:port endpoint %q", s)
	}
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()).String(), nil
}
func validatePNFSOptions(o PNFSOptions) (PNFSOptions, error) {
	if o.ObjectWrite {
		return o, errors.New("ObjectWrite is accepted only for finite object range writes")
	}
	out := PNFSOptions{Layout: o.Layout, DataServers: map[string]string{}, Parallelism: o.Parallelism, Extend: o.Extend, ReadFailover: o.ReadFailover, WriteFailover: o.WriteFailover, MirrorFailover: o.MirrorFailover, RefreshDevices: o.RefreshDevices, SessionTrunking: o.SessionTrunking}
	if out.Layout == "" {
		out.Layout = "file"
	}
	if out.Layout == "object" {
		return validateObjectOptions(o)
	}
	if o.OSDRequireSecure || len(o.OSDTargets) != 0 || o.OSDInitiator != "" {
		return out, errors.New("OSD targets require the object layout")
	}
	if out.Layout == "block" {
		return validateBlockOptions(o)
	}
	if len(o.BlockReadAlternates) != 0 || len(o.BlockSecurity) != 0 || len(o.OSDSecurity) != 0 || len(o.BlockVolumes) != 0 || len(o.BlockTargets) != 0 || o.BlockInitiator != "" || o.BlockWrite || o.BlockJournal != "" || o.BlockResume {
		return out, errors.New("block volumes require the block layout")
	}
	if out.Layout != "file" && out.Layout != "flex" {
		return out, errors.New("pNFS layout must be file or flex")
	}
	if out.WriteFailover && (out.ReadFailover || out.MirrorFailover || out.SessionTrunking) {
		return out, errors.New("write failover cannot combine with read/mirror failover or session trunking")
	}
	if out.MirrorFailover && (out.Layout != "flex" || out.ReadFailover) {
		return out, errors.New("mirror failover requires Flex and cannot combine with path read failover")
	}
	if out.RefreshDevices && (out.ReadFailover || out.MirrorFailover) {
		return out, errors.New("device refresh cannot combine with read path or mirror failover")
	}
	if out.SessionTrunking && (out.Layout != "file" || out.ReadFailover || out.MirrorFailover || out.RefreshDevices) {
		return out, errors.New("session trunking requires FILE reads without recovery options")
	}
	if out.Parallelism == 0 {
		out.Parallelism = 1
	}
	if out.Parallelism < 1 || out.Parallelism > 8 {
		return out, errors.New("pNFS parallelism must be 1..8")
	}
	if len(o.DataServers) == 0 || len(o.DataServers) > 64 {
		return out, errors.New("pNFS needs 1..64 explicit data-server endpoint mappings")
	}
	for from, to := range o.DataServers {
		a, err := pnfsEndpoint(from)
		if err != nil {
			return out, err
		}
		b, err := pnfsEndpoint(to)
		if err != nil {
			return out, err
		}
		if _, ok := out.DataServers[a]; ok {
			return out, errors.New("duplicate pNFS endpoint")
		}
		out.DataServers[a] = b
	}
	if err := validatePNFSTLSNames(&out, o.TLSNames); err != nil {
		return out, err
	}
	if err := validatePNFSSPNs(&out, o.SPNs); err != nil {
		return out, err
	}
	return out, nil
}
func decodeFileLayout(d *decoder) *fileLayout {
	l := &fileLayout{device: append([]byte(nil), d.take(16)...)}
	l.util = d.u32()
	l.first = d.u32()
	l.pattern = d.u64()
	n := d.u32()
	if n > 64 || l.util&0x3c != 0 || l.util&0xffffffc0 == 0 {
		d.err = errors.New("unsupported file-layout flags, stripe size or handle count")
		return l
	}
	for i := uint32(0); i < n; i++ {
		fh := d.opaque(128)
		if len(fh) == 0 {
			d.err = errors.New("empty pNFS data handle")
		}
		l.handles = append(l.handles, append([]byte(nil), fh...))
	}
	if len(d.b) != 0 {
		d.err = errors.New("trailing file-layout body")
	}
	return l
}
func universalEndpoint(network, address string) (string, error) {
	i := strings.LastIndexByte(address, '.')
	if i < 0 {
		return "", errors.New("invalid pNFS universal address")
	}
	j := strings.LastIndexByte(address[:i], '.')
	if j < 0 {
		return "", errors.New("invalid pNFS universal address")
	}
	hi, e1 := strconv.ParseUint(address[j+1:i], 10, 8)
	lo, e2 := strconv.ParseUint(address[i+1:], 10, 8)
	ip, err := netip.ParseAddr(address[:j])
	if e1 != nil || e2 != nil || err != nil || (network != "tcp" && network != "tcp6") || (network == "tcp" && !ip.Is4()) || (network == "tcp6" && !ip.Is6()) {
		return "", errors.New("unsupported pNFS network address")
	}
	return pnfsEndpoint(netip.AddrPortFrom(ip, uint16(hi*256+lo)).String())
}
func decodeDevice(d *decoder, l *fileLayout) {
	n := d.u32()
	if n < 1 || n > 64 {
		d.err = errors.New("pNFS stripe count limit")
		return
	}
	for i := uint32(0); i < n; i++ {
		l.indices = append(l.indices, d.u32())
	}
	n = d.u32()
	if n < 1 || n > 64 {
		d.err = errors.New("pNFS data-server count limit")
		return
	}
	for i := uint32(0); i < n; i++ {
		paths := d.u32()
		if paths < 1 || paths > 8 {
			d.err = errors.New("pNFS multipath count limit")
			return
		}
		addresses := []string{}
		for j := uint32(0); j < paths; j++ {
			network, address := d.str(), d.str()
			ep, err := universalEndpoint(network, address)
			if err != nil {
				d.err = err
				return
			}
			addresses = append(addresses, ep)
		}
		l.servers = append(l.servers, addresses)
	}
	for _, i := range l.indices {
		if i >= uint32(len(l.servers)) {
			d.err = errors.New("invalid pNFS stripe index")
			return
		}
	}
	if l.first >= uint32(len(l.indices)) {
		d.err = errors.New("invalid pNFS first stripe")
		return
	}
	h := len(l.handles)
	if l.util&1 != 0 && h != len(l.indices) || l.util&1 == 0 && h != 0 && h != 1 && h != len(l.servers) {
		d.err = errors.New("invalid pNFS filehandle cardinality")
	}
	if len(d.b) != 0 {
		d.err = errors.New("trailing pNFS device address")
	}
}
func (l *fileLayout) position(offset uint64, mdsHandle []byte) (server uint32, handle []byte, dsOffset uint64, remaining uint64, err error) {
	if offset < l.pattern || len(l.indices) == 0 {
		return 0, nil, 0, 0, errors.New("pNFS offset precedes layout pattern")
	}
	unit := uint64(l.util & 0xffffffc0)
	width := uint64(len(l.indices))
	relative := offset - l.pattern
	stripe := (relative/unit + uint64(l.first)) % width
	server = l.indices[stripe]
	dsOffset = offset
	remaining = unit - relative%unit
	if l.util&1 != 0 {
		dsOffset = (relative/unit/width)*unit + relative%unit
		handle = l.handles[stripe]
	} else {
		switch len(l.handles) {
		case 0:
			handle = mdsHandle
		case 1:
			handle = l.handles[0]
		default:
			handle = l.handles[server]
		}
	}
	return
}
func (v *v4Client) returnLayout(fh []byte) error {
	return v.returnLayoutAfterDelete(fh, false)
}

func (v *v4Client) returnLayoutAfterDelete(fh []byte, deleted bool) error {
	r := v.recall
	r.mu.Lock()
	state := append([]byte(nil), r.state...)
	kind, body := r.layoutKind(), r.flexReturnBody()
	if kind == 2 {
		var report encoder
		if len(r.objectError) == 0 {
			report.u32(0)
		} else {
			report.u32(1)
			report = append(report, r.objectError...)
		}
		body = report
	}
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), v.c.nfs.timeout)
	defer cancel()
	var e encoder
	e.u32(0)
	e.u32(kind)
	e.u32(3)
	e.u32(1)
	e.u64(0)
	e.u64(math.MaxUint64)
	e = append(e, state...)
	e.opaque(body)
	op := op4(51, e, func(d *decoder) {
		if d.boolean() {
			d.take(16)
		}
	})
	op.revokedLayoutReturn = deleted
	err := v.compound(ctx, fh4(fh), op)
	if deleted && errors.Is(err, Status(10025)) {
		err = nil
	}
	if err == nil && v.stateLost.Load() {
		err = errors.New("pNFS metadata state lost during layout return")
	}
	r.mu.Lock()
	r.active = false
	r.fh = nil
	r.state = nil
	r.layoutType, r.flexErrors = 0, nil
	r.objectError = nil
	r.devices = nil
	r.mu.Unlock()
	if err != nil {
		v.stateLost.Store(true)
		v.c.nfs.mu.Lock()
		v.c.nfs.closeLocked()
		v.c.nfs.mu.Unlock()
	}
	return err
}
func (v *v4Client) layoutUsable(fh []byte) error {
	return v.layoutStateUsable(fh, false)
}

func (v *v4Client) layoutStateUsable(fh []byte, allowRecall bool) error {
	if m := v.c.nfs.duplex; m != nil {
		select {
		case <-m.done:
			v.stateLost.Store(true)
		default:
		}
	}
	if last := v.lastLease.Load(); last != nil && v.leaseSeconds != 0 && time.Since(*last) >= time.Duration(v.leaseSeconds)*time.Second {
		v.stateLost.Store(true)
	}
	if v.stateLost.Load() {
		return errors.New("pNFS metadata state lost")
	}
	if err := v.checkLockedIO(fh, 1); err != nil {
		return err
	}
	r := v.recall
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active || r.recalled && !allowRecall {
		return errors.New("pNFS layout recalled; transfer stopped")
	}
	for _, notice := range r.devices {
		if notice.deleted {
			return errPNFSDeviceDeleted
		}
		if notice.invalid {
			return errPNFSDeviceChange
		}
	}
	return nil
}

// ReadPNFSToProgress streams through approved FILE/Flex servers or block images.
// It returns its layout. ReadFailover explicitly permits bounded
// authenticated READ recovery; no operation falls back to MDS READ.
// The caller must verify MDS source attributes before publishing local bytes.
func (c *Client) ReadPNFSToProgress(ctx context.Context, fh []byte, size uint64, w io.Writer, o PNFSOptions, progress func(uint64)) (int64, error) {
	return c.readPNFSToProgress(ctx, fh, size, w, o, progress, nil)
}

// ReadPNFSToProgressVerified verifies completed bytes while the layout and OPEN
// are still held. verify may sync the destination and query MDS attributes, but
// must not start another transfer. It runs only after successful complete I/O.
// Cleanup errors still fail the transfer; callers must publish only on success.
func (c *Client) ReadPNFSToProgressVerified(ctx context.Context, fh []byte, size uint64, w io.Writer, o PNFSOptions, progress func(uint64), verify func() error) (int64, error) {
	if verify == nil {
		return 0, errors.New("pNFS completion verifier is required")
	}
	return c.readPNFSToProgress(ctx, fh, size, w, o, progress, verify)
}

func (c *Client) readPNFSToProgress(ctx context.Context, fh []byte, size uint64, w io.Writer, o PNFSOptions, progress func(uint64), verify func() error) (count int64, resultErr error) {
	if o.WriteFailover {
		return 0, errors.New("write failover requires a pNFS write")
	}
	if c.v4 == nil || c.v4.recall == nil || c.config == nil || !c.config.PNFS {
		return 0, errors.New("getpnfs requires --pnfs with explicit v4.1/4.2 TCP")
	}
	if size > math.MaxInt64 || c.ReadSize == 0 {
		return 0, errors.New("invalid pNFS read size")
	}
	o, err := validatePNFSOptions(o)
	if err != nil {
		return 0, err
	}
	if o.Layout == "block" {
		return c.readBlockPNFS(ctx, fh, size, w, o, progress, verify)
	}
	if o.Layout == "object" {
		return c.readObjectPNFS(ctx, fh, size, w, o, progress, verify)
	}
	tlsConfigs, err := pnfsTLSConfigs(*c.config, o)
	if err != nil {
		return 0, err
	}
	authConfigs, err := c.pnfsKerberosConfigs(o)
	if err != nil {
		return 0, err
	}
	v := c.v4
	sid, closeIO, err := v.openIO(ctx, fh, 1)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	kind := uint32(1)
	if o.Layout == "flex" {
		kind = 4
	}
	layouts, err := v.getLayoutType(ctx, fh, sid, size, 1, kind)
	if err != nil {
		return 0, err
	}
	defer func() {
		if v.hasActiveLayout() {
			resultErr = errors.Join(resultErr, v.returnLayout(fh))
		}
	}()
	if o.RefreshDevices {
		if err := v.recall.registerLayoutDevices(layouts, false); err != nil {
			return 0, err
		}
	}
	// Validate every segment's device and endpoint before contacting any DS.
	for _, segment := range layouts {
		var err error
		if segment.flex != nil {
			if segment.iomode == 2 && segment.flex.flags&4 != 0 {
				return 0, errors.New("flex Files RW layout forbids reads")
			}
			err = v.prepareFlexReadDevices(ctx, segment.flex, o)
		} else {
			err = v.prepareLayoutDevice(ctx, segment, o)
		}
		if err != nil {
			return 0, err
		}
	}
	if o.RefreshDevices {
		v.recall.acknowledgeDeviceGenerations(layouts)
	}
	usable := func() error {
		if err := v.layoutUsable(fh); err != nil {
			return err
		}
		if o.RefreshDevices && v.recall.devicesPending() {
			return errPNFSDevicePending
		}
		return nil
	}
	dataServer, recoverRead, closePool := c.pnfsDataServers(ctx, tlsConfigs, authConfigs, usable, o.SessionTrunking)
	defer closePool()
	flexServer, recoverFlex, retireFlex, closeFlexPool := c.pnfsFlexServers(ctx, tlsConfigs, authConfigs, usable)
	defer closeFlexPool()
	recoverFlexRead := v.flexReadRecovery(recoverFlex)
	if o.MirrorFailover {
		recoverFlexRead = v.flexReadRecovery(c.flexMirrorRecovery(ctx, usable, flexServer, retireFlex))
	}
	refreshes := 0
readBatches:
	for uint64(count) < size {
		if o.RefreshDevices {
			layouts, err = v.recoverLayoutDevices(ctx, fh, sid, size, layouts, o, false, &refreshes)
			if err != nil {
				return count, err
			}
		}
		var batch []*pnfsRead
		used := map[string]bool{}
		// Only one outstanding request per endpoint/session. Stop at the
		// first repeated endpoint, preserving a contiguous bounded window.
		for next := uint64(count); next < size && len(batch) < o.Parallelism; {
			if err := ctx.Err(); err != nil {
				return count, err
			}
			if err := usable(); err != nil {
				if o.RefreshDevices && deviceRecoveryBarrier(err) {
					continue readBatches
				}
				return count, err
			}
			l, err := fileLayoutAt(layouts, next)
			if err != nil {
				return count, err
			}
			var ds *Client
			var endpoint string
			var handle []byte
			var paths []string
			var offset, left uint64
			var component *flexDS
			if l.flex != nil {
				component, left = l.flex.position(next)
				handle, offset, paths = component.handle, next, component.endpoints
				ds, endpoint, err = flexServer(component)
			} else {
				var server uint32
				server, handle, offset, left, err = l.position(next, fh)
				if err == nil {
					paths = l.endpoints[server]
					ds, endpoint, err = dataServer(paths)
				}
			}
			if err != nil {
				if component != nil && ctx.Err() == nil && usable() == nil {
					v.recordFlexError(component, next, min(left, size-next), err)
				}
				return count, err
			}
			if used[endpoint] {
				break
			}
			limit := uint32(min(left, l.length-(next-l.offset), size-next, uint64(ds.ReadSize), uint64(1<<20)))
			if component != nil {
				limit = min(limit, component.rsize)
			}
			batch = append(batch, &pnfsRead{ds: ds, handle: handle, offset: offset, limit: limit, paths: paths, endpoint: endpoint, flex: component, flexLayout: l.flex})
			used[endpoint] = true
			next += uint64(limit)
		}
		var recovery func(*pnfsRead) error
		if o.ReadFailover || o.MirrorFailover {
			recovery = recoverRead
			if o.Layout == "flex" {
				recovery = recoverFlexRead
			}
		}
		if err := readPNFSBatchRecover(ctx, batch, sid, usable, recovery); err != nil {
			if o.RefreshDevices && ctx.Err() == nil && v.recall.devicesPending() && onlyDeviceBarrier(err) {
				continue readBatches
			}
			for _, r := range batch {
				if r.flex != nil {
					v.recordFlexError(r.flex, r.offset, uint64(r.limit), r.ioErr)
				}
			}
			return count, err
		}
		// All workers have finished before output/progress callbacks run.
		// Responses may arrive out of order; publication stays in file order.
		for _, read := range batch {
			if err := ctx.Err(); err != nil {
				return count, err
			}
			if err := usable(); err != nil {
				if o.RefreshDevices && deviceRecoveryBarrier(err) {
					continue readBatches
				}
				return count, err
			}
			n, err := w.Write(read.data)
			if n < 0 || n > len(read.data) {
				return count, io.ErrShortWrite
			}
			count += int64(n)
			if progress != nil {
				progress(uint64(count))
			}
			if err != nil {
				return count, err
			}
			if n != len(read.data) {
				return count, io.ErrShortWrite
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return count, err
	}
	if err := usable(); err != nil {
		return count, err
	}
	if verify != nil {
		if err := verify(); err != nil {
			return count, err
		}
	}
	if err := ctx.Err(); err != nil {
		return count, err
	}
	return count, usable()
}

func (v *v4Client) prepareLayoutDevice(ctx context.Context, l *fileLayout, o PNFSOptions) error {
	var generation uint64
	if o.RefreshDevices {
		v.recall.mu.Lock()
		generation = v.recall.devices[string(l.device)].generation
		v.recall.mu.Unlock()
	}
	e := append(encoder(nil), l.device...)
	e.u32(1)
	e.u32(32768)
	if o.RefreshDevices {
		bitmap4(&e, 1, 2)
	} else {
		e.u32(0)
	}
	var notifications []uint32
	op := op4(47, e, func(d *decoder) {
		if d.u32() != 1 {
			d.err = errors.New("unexpected pNFS device type")
			return
		}
		body := d.opaque(32768)
		sub := &decoder{b: body}
		decodeDevice(sub, l)
		if sub.err != nil {
			d.err = sub.err
		}
		notifications = readBitmap4(d)
		if !o.RefreshDevices && len(notifications) != 0 {
			d.err = errors.New("unsolicited device notifications")
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
		return err
	}
	if o.RefreshDevices && !slices.Equal(notifications, []uint32{1, 2}) {
		return errors.New("pNFS server did not accept both requested device notifications")
	}
	endpoints := make([][]string, len(l.servers))
	for i, paths := range l.servers {
		for _, path := range paths {
			if target, ok := o.DataServers[path]; ok && !slices.Contains(endpoints[i], target) {
				endpoints[i] = append(endpoints[i], target)
			}
		}
		if len(endpoints[i]) == 0 {
			return fmt.Errorf("unapproved pNFS data server %v", paths)
		}
	}
	l.endpoints = endpoints
	if o.RefreshDevices {
		l.deviceGeneration = generation
	}
	return nil
}
