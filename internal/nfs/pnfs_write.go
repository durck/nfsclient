package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// ValidatePNFSWriteOptions permits upload callers to validate the complete
// connection/endpoint/TLS profile before creating a destination file.
func (c *Client) ValidatePNFSWriteOptions(options PNFSOptions) error {
	if options.OSDRequireSecure || options.Layout == "object" || len(options.OSDTargets) != 0 || options.OSDInitiator != "" {
		return errors.New("OSD supports finite existing-file range writes only; creation and growth are unsupported")
	}
	if options.ReadFailover || options.MirrorFailover || options.SessionTrunking {
		return errors.New("pNFS read failover cannot be used for writes")
	}
	if c.v4 == nil || c.v4.recall == nil || c.config == nil || !c.config.PNFS || c.WriteSize == 0 {
		return errors.New("pNFS writes require --pnfs with explicit v4.1/4.2 TCP and a valid write size")
	}
	if options.Layout == "block" {
		o, err := validateBlockWriteOptions(options)
		if err != nil {
			return err
		}
		files, err := openBlockStorage(context.Background(), o, c.config.Timeout, true)
		if err != nil {
			return err
		}
		files.close()
		return validateBlockJournalGate(o)
	}
	o, err := validatePNFSOptions(options)
	if err != nil {
		return err
	}
	_, err = pnfsTLSConfigs(*c.config, o)
	if err != nil {
		return err
	}
	_, err = c.pnfsKerberosConfigs(o)
	return err
}

// WritePNFSRangeFromProgress modifies a finite range (with optional growth) under a retained
// whole-file write lock. Count/progress report only durably committed bytes.
// An error can leave additional changed bytes. Explicit failover retries only
// the identical cached session request; no MDS WRITE fallback or new lock occurs.
func (c *Client) WritePNFSRangeFromProgress(ctx context.Context, fh []byte, offset, length uint64, input io.Reader, options PNFSOptions, progress func(uint64)) (count int64, resultErr error) {
	if options.Layout == "object" {
		return c.writeObjectPNFS(ctx, fh, offset, length, input, options, progress)
	}
	if options.ObjectWrite || options.OSDRequireSecure || len(options.OSDTargets) != 0 || options.OSDInitiator != "" {
		return 0, errors.New("object write options require the object layout")
	}
	if options.Layout == "block" {
		return c.writeBlockPNFS(ctx, fh, offset, length, input, options, progress)
	}
	if len(options.BlockSecurity) != 0 || len(options.OSDSecurity) != 0 || len(options.BlockVolumes) != 0 || len(options.BlockTargets) != 0 || options.BlockInitiator != "" || options.BlockWrite || options.BlockJournal != "" || options.BlockResume {
		return 0, errors.New("block images and write approval require the block layout")
	}
	if options.ReadFailover || options.MirrorFailover || options.SessionTrunking {
		return 0, errors.New("pNFS read failover cannot be used for writes")
	}
	if c.v4 == nil || c.v4.recall == nil || c.config == nil || !c.config.PNFS {
		return 0, errors.New("pNFS writes require --pnfs with explicit v4.1/4.2 TCP")
	}
	if input == nil || c.WriteSize == 0 {
		return 0, errors.New("invalid pNFS write source or size")
	}
	l, err := c.rangeLock(fh, offset, length, true)
	if err != nil {
		return 0, err
	}
	if l.info.Offset != 0 || l.info.Length != LockToEOF {
		return 0, errors.New("pNFS writes require an existing whole-file write lock")
	}
	o, err := validatePNFSOptions(options)
	if err != nil {
		return 0, err
	}
	tlsConfigs, err := pnfsTLSConfigs(*c.config, o)
	if err != nil {
		return 0, err
	}
	authConfigs, err := c.pnfsKerberosConfigs(o)
	if err != nil {
		return 0, err
	}
	before, err := c.GetAttr(ctx, fh)
	if err != nil {
		return 0, err
	}
	if before.Type != 1 || !before.HasSize || !o.Extend && offset+length > before.Size {
		return 0, errors.New("pNFS write range must fit an existing regular file")
	}
	v := c.v4
	sid := append([]byte(nil), l.sid...)
	kind := uint32(1)
	if o.Layout == "flex" {
		kind = 4
	}
	layouts, err := v.getLayoutType(ctx, fh, sid, offset+length, 2, kind)
	if err != nil {
		return 0, err
	}
	// Unknown mutation outcomes close the MDS session before returning. A
	// healthy layout is returned only once all acknowledged writes are durable.
	pending := false
	defer func() {
		if pending {
			// Flex Files must notify the MDS of incomplete mirrored updates.
			// Reporting is not durability or recovery: the original lock/session
			// is still quarantined after any uncertain mutation result.
			if o.Layout == "flex" && !v.stateLost.Load() {
				resultErr = errors.Join(resultErr, v.returnLayout(fh))
			}
			v.stateLost.Store(true)
			v.c.nfs.mu.Lock()
			v.c.nfs.closeLocked()
			v.c.nfs.mu.Unlock()
			return
		}
		if !v.stateLost.Load() && v.hasActiveLayout() {
			resultErr = errors.Join(resultErr, v.returnLayout(fh))
		}
	}()
	if o.RefreshDevices {
		if err := v.recall.registerLayoutDevices(layouts, true); err != nil {
			return 0, err
		}
	}
	for _, segment := range layouts {
		var err error
		if segment.flex != nil {
			err = v.prepareFlexWriteDevices(ctx, segment.flex, o)
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
	// A recall prevents new WRITEs but permits flushing a known acknowledged
	// prefix while the lease and original lock remain valid.
	guard := func(allowRecall bool) error {
		stateErr := v.layoutStateUsable(fh, allowRecall)
		if stateErr != nil && !deviceRecoveryBarrier(stateErr) {
			return stateErr
		}
		v.recall.mu.Lock()
		sameFile := bytes.Equal(v.recall.fh, fh)
		v.recall.mu.Unlock()
		if !sameFile {
			return errors.New("pNFS layout file changed during write")
		}
		current, err := c.rangeLock(fh, offset, length, true)
		if err != nil {
			return err
		}
		if current != l || !bytes.Equal(l.sid, sid) {
			return errors.New("pNFS write lock changed during transfer")
		}
		return stateErr
	}
	refreshes := 0
	boundary := func() ([]*fileLayout, error) {
		if err := errors.Join(ctx.Err(), guard(false)); err != nil && !deviceRecoveryBarrier(err) {
			return nil, err
		}
		if o.RefreshDevices {
			var err error
			layouts, err = v.recoverLayoutDevices(ctx, fh, sid, offset+length, layouts, o, true, &refreshes)
			if err != nil {
				return nil, err
			}
		}
		return layouts, guard(false)
	}
	usable := func() error { return guard(false) }
	dataServer, _, closePool := c.pnfsDataServers(ctx, tlsConfigs, authConfigs, usable, false)
	defer closePool()
	if o.WriteFailover {
		original := dataServer
		dataServer = func(paths []string) (*Client, string, error) {
			ds, endpoint, err := original(paths)
			if err == nil {
				err = c.enablePNFSWriteRecovery(ds, paths, endpoint, tlsConfigs, authConfigs, usable)
			}
			return ds, endpoint, err
		}
	}
	// Preserve the MDS lock stateid independently of its DS sequence encoding.
	dsSID := append([]byte(nil), sid...)
	clear(dsSID[:4])
	if o.Layout == "flex" {
		flexServer, _, _, closeFlex := c.pnfsFlexServers(ctx, tlsConfigs, authConfigs, usable)
		defer closeFlex()
		if o.WriteFailover {
			original := flexServer
			flexServer = func(component *flexDS) (*Client, string, error) {
				ds, endpoint, err := original(component)
				if err == nil {
					err = c.enablePNFSWriteRecovery(ds, component.endpoints, endpoint, tlsConfigs, authConfigs, usable)
				}
				return ds, endpoint, err
			}
		}
		count, pending, err = c.writeFlexRange(ctx, fh, offset, length, before.Size, input, layouts, o.Parallelism, flexServer, guard, progress, boundary)
		if err != nil {
			return count, err
		}
	} else if o.Parallelism > 1 {
		count, pending, err = c.writePNFSParallel(ctx, fh, dsSID, offset, length, before.Size, input, layouts, o.Parallelism, dataServer, guard, progress, boundary)
		if err != nil {
			return count, err
		}
	}
	verifiers := map[string][]byte{}
	buf := make([]byte, min(uint64(c.WriteSize), uint64(1<<20)))
	for uint64(count) < length {
		if _, err := boundary(); err != nil {
			return count, err
		}
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return count, err
		}
		logical := offset + uint64(count)
		layout, err := fileLayoutAt(layouts, logical)
		if err != nil {
			return count, err
		}
		server, handle, physical, left, err := layout.position(logical, fh)
		if err != nil {
			return count, err
		}
		ds, endpoint, err := dataServer(layout.endpoints[server])
		if err != nil {
			return count, err
		}
		limit := min(left, layout.length-(logical-layout.offset), length-uint64(count), uint64(len(buf)), uint64(ds.WriteSize))
		if limit == 0 {
			return count, errors.New("invalid pNFS data-server write size")
		}
		data := buf[:int(limit)]
		if _, err := io.ReadFull(input, data); err != nil {
			return count, err
		}
		for len(data) > 0 {
			if err := errors.Join(ctx.Err(), usable()); err != nil {
				return count, err
			}
			var request encoder
			request = append(request, dsSID...)
			request.u64(physical)
			request.u32(0)
			request.opaque(data)
			var accepted, stable uint32
			var verifier []byte
			pending = true
			if err := ds.v4.compound(ctx, fh4(handle), op4(38, request, func(d *decoder) {
				accepted, stable = d.u32(), d.u32()
				verifier = append([]byte(nil), d.take(8)...)
				if accepted == 0 || accepted > uint32(len(data)) || stable > 2 {
					d.err = errors.New("invalid pNFS WRITE acknowledgement")
				}
			})); err != nil {
				return count, err
			}
			if err := guard(true); err != nil {
				return count, err
			}
			verifierKey := endpoint
			if layout.util&2 != 0 {
				verifierKey = "metadata"
			}
			if previous := verifiers[verifierKey]; previous != nil && !bytes.Equal(previous, verifier) {
				return count, errors.New("pNFS data-server incarnation changed during write")
			}
			verifiers[verifierKey] = verifier
			if stable < 2 && (stable == 0 || layout.util&2 != 0) {
				target, commitFH, commitOffset := ds.v4, handle, physical
				if layout.util&2 != 0 {
					target, commitFH, commitOffset = v, fh, logical
				}
				var e encoder
				e.u64(commitOffset)
				e.u32(accepted)
				if err := target.compound(ctx, fh4(commitFH), op4(5, e, func(d *decoder) {
					if !bytes.Equal(d.take(8), verifier) {
						d.err = errors.New("pNFS write verifier changed; data durability is uncertain")
					}
				})); err != nil {
					return count, err
				}
			}
			if err := guard(true); err != nil {
				return count, err
			}
			if err := v.commitLayoutWrite(ctx, fh, logical, uint64(accepted), max(before.Size, logical+uint64(accepted))); err != nil {
				return count, err
			}
			pending = false
			count += int64(accepted)
			logical += uint64(accepted)
			physical += uint64(accepted)
			data = data[accepted:]
			if progress != nil {
				progress(uint64(count))
			}
			if err := errors.Join(ctx.Err(), usable()); err != nil {
				if !o.RefreshDevices || len(data) != 0 || !deviceRecoveryBarrier(err) {
					return count, err
				}
			}
		}
	}
	if o.RefreshDevices {
		if _, err := boundary(); err != nil {
			return count, err
		}
	}
	after, err := c.GetAttr(ctx, fh)
	if err != nil {
		return count, err
	}
	if after.Type != 1 || !after.HasSize || after.Size != max(before.Size, offset+length) {
		return count, errors.New("pNFS write completed but destination size changed")
	}
	return count, errors.Join(ctx.Err(), usable())
}

func (v *v4Client) commitLayoutWrite(ctx context.Context, fh []byte, offset, length, size uint64) error {
	v.recall.mu.Lock()
	state := append([]byte(nil), v.recall.state...)
	kind := v.recall.layoutKind()
	v.recall.mu.Unlock()
	var e encoder
	e.u64(offset)
	e.u64(length)
	e.u32(0)
	e = append(e, state...)
	e.u32(1)
	e.u64(offset + length - 1)
	e.u32(0)
	e.u32(kind)
	e.opaque(nil)
	return v.compound(ctx, fh4(fh), op4(49, e, func(d *decoder) {
		if d.boolean() && d.u64() != size {
			d.err = errors.New("pNFS LAYOUTCOMMIT changed the destination size")
		}
	}))
}
