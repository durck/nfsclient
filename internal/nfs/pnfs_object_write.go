package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"

	"nfsclient/internal/iscsi"
)

func validateObjectWriteOptions(o PNFSOptions) (PNFSOptions, error) {
	if o.Layout != "object" || !o.ObjectWrite {
		return o, errors.New("object range writes require explicit ObjectWrite approval")
	}
	o.ObjectWrite = false
	out, err := validateObjectOptions(o)
	out.ObjectWrite = true
	out.OSDRequireSecure = true
	return out, err
}

// objectRequiredLength computes the last physical byte touched in one dense
// stripe component without iterating through a potentially huge file range.
func objectRequiredLength(l *objectLayout, index int, first, end uint64) uint64 {
	if first >= end {
		return 0
	}
	n := uint64(len(l.components))
	lastStripe := (end - 1) / l.unit
	delta := (lastStripe%n + n - uint64(index)) % n
	if delta > lastStripe {
		return 0
	}
	stripe := lastStripe - delta
	if stripe < first/l.unit {
		return 0
	}
	tail := l.unit
	if stripe == lastStripe {
		tail = (end-1)%l.unit + 1
	}
	return stripe/n*l.unit + tail
}

func (v *v4Client) objectWriteFailure(c objectCredential, offset, length uint64, err error) error {
	var e encoder
	e = append(e, c.device...)
	e.u64(c.partition)
	e.u64(c.object)
	e.u64(offset)
	e.u64(length)
	e.u32(1)
	e.u32(1)
	v.recall.mu.Lock()
	v.recall.objectError = e
	v.recall.mu.Unlock()
	return err
}

// Each published prefix has a verified OSD WRITE, an authenticated FLUSH and a
// successful MDS LAYOUTCOMMIT. No uncertain storage operation is retried.
func (c *Client) writeObjectPNFS(ctx context.Context, fh []byte, offset, length uint64, input io.Reader, options PNFSOptions, progress func(uint64)) (count int64, resultErr error) {
	if input == nil || c.WriteSize == 0 || c.v4 == nil || c.v4.recall == nil || c.config == nil || !c.config.PNFS {
		return 0, errors.New("object writes require a source and pNFS v4.1/4.2 session")
	}
	if !c.objectCredentialPrivacy() {
		return 0, errors.New("secured object writes require krb5p or authenticated TLS to the metadata server")
	}
	o, err := validateObjectWriteOptions(options)
	if err != nil {
		return 0, err
	}
	lock, err := c.rangeLock(fh, offset, length, true)
	if err != nil {
		return 0, err
	}
	if lock.info.Offset != 0 || lock.info.Length != LockToEOF {
		return 0, errors.New("object writes require a retained whole-file write lock")
	}
	v, auth, identity := c.v4, c.Auth, c.Identity()
	auth.Groups = slices.Clone(auth.Groups)
	sid := bytes.Clone(lock.sid)
	profile := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.v4 != v || !sameNLMAuth(auth, c.Auth) || c.Identity() != identity || !c.objectCredentialPrivacy() {
			return errors.New("object write identity or client state changed")
		}
		if source, ok := input.(interface{ Check() error }); ok {
			if err := source.Check(); err != nil {
				return err
			}
		}
		current, err := c.rangeLock(fh, offset, length, true)
		if err != nil {
			return err
		}
		if current != lock || !bytes.Equal(lock.sid, sid) {
			return errors.New("object write lock changed")
		}
		return v.checkLockedIO(fh, 2)
	}
	if err := profile(); err != nil {
		return 0, err
	}
	before, err := c.GetAttr(ctx, fh)
	if err != nil {
		return 0, err
	}
	if before.Type != 1 || !before.HasSize || offset+length > before.Size {
		return 0, errors.New("object writes must fit an existing regular file without growth")
	}
	if err := profile(); err != nil {
		return 0, err
	}
	layouts, err := v.getLayoutType(ctx, fh, sid, offset+length, 2, 2)
	if err != nil {
		return 0, err
	}
	defer closeObjectLayouts(layouts)
	devices := map[string]*iscsi.ObjectDevice{}
	defer func() {
		for _, dev := range devices {
			dev.Close()
		}
	}()
	pending := false
	defer func() {
		changed := c.v4 != v || !sameNLMAuth(auth, c.Auth) || c.Identity() != identity
		if pending || changed {
			// A best-effort I/O report does not make an uncertain mutation safe.
			if pending && !changed && !v.stateLost.Load() && v.checkLockedIO(fh, 2) == nil {
				resultErr = errors.Join(resultErr, v.returnLayout(fh))
			}
			v.stateLost.Store(true)
			v.c.nfs.mu.Lock()
			v.c.nfs.closeLocked()
			v.c.nfs.mu.Unlock()
			resultErr = errors.Join(resultErr, errors.New("object mutation or credentials uncertain; original session quarantined, no replay"))
		} else if !v.stateLost.Load() {
			resultErr = errors.Join(resultErr, v.returnLayout(fh))
		}
	}()
	guard := func(allowRecall bool) error {
		if err := profile(); err != nil {
			return err
		}
		if err := v.layoutStateUsable(fh, allowRecall); err != nil {
			return err
		}
		v.recall.mu.Lock()
		same := bytes.Equal(v.recall.fh, fh)
		v.recall.mu.Unlock()
		if !same {
			return errors.New("object layout file changed")
		}
		for _, l := range layouts {
			for _, part := range l.object.components {
				if part.credential == nil || !part.credential.Secured() {
					return errors.New("object writes require secured ALLDATA component capabilities")
				}
				if err := part.credential.Check(part.partition, part.object, iscsi.ObjectWrite|iscsi.ObjectGetAttributes|iscsi.ObjectManage); err != nil {
					return err
				}
			}
		}
		for _, dev := range devices {
			if err := dev.Check(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := guard(false); err != nil {
		return 0, err
	}
	addresses := map[string]objectAddress{}
	defer func() {
		for _, a := range addresses {
			a.root.credential.Close()
		}
	}()
	targetIDs := map[iscsi.Target]string{}
	// Validate every root over the confidential MDS channel before opening any
	// storage connection. A later component cannot silently introduce NOSEC.
	for _, l := range layouts {
		for _, part := range l.object.components {
			if err := guard(false); err != nil {
				return 0, err
			}
			key := string(part.device)
			if _, ok := addresses[key]; ok {
				continue
			}
			if len(addresses) == 64 {
				return 0, errors.New("object write exceeds 64 devices")
			}
			a, err := v.objectDevice(ctx, part.device, o)
			if err != nil {
				return 0, err
			}
			if a.root.credential == nil || !a.root.credential.Secured() {
				a.root.credential.Close()
				return 0, errors.New("object writes require secured root capabilities")
			}
			if err := a.root.credential.Check(0, 0, iscsi.ObjectGetAttributes); err != nil {
				a.root.credential.Close()
				return 0, err
			}
			if old, ok := targetIDs[a.target]; ok && old != key {
				a.root.credential.Close()
				return 0, errors.New("OSD device IDs alias an approved LUN")
			}
			addresses[key], targetIDs[a.target] = a, key
		}
	}
	// Probe every component and affected physical range before the first WRITE,
	// including components outside a short logical range.
	for _, l := range layouts {
		for index, part := range l.object.components {
			if err := guard(false); err != nil {
				return 0, err
			}
			key := string(part.device)
			dev := devices[key]
			if dev == nil {
				a := addresses[key]
				policy := o.OSDSecurity["iscsi://"+a.target.Endpoint+"/"+a.target.Name+"/"+strconv.Itoa(int(a.target.LUN))]
				dev, err = iscsi.OpenObjectWithCredential(ctx, a.target, o.OSDInitiator, c.config.Timeout, a.systemID, a.name, a.root.credential, policy)
				a.root.credential.Close()
				if err != nil {
					return 0, err
				}
				devices[key] = dev
			}
			size, err := dev.LengthWithCredential(part.partition, part.object, part.credential)
			if err != nil {
				return 0, v.objectFailure(part, 0, ^uint64(0), err)
			}
			need := objectRequiredLength(l.object, index, max(offset, l.offset), min(offset+length, l.offset+l.length))
			if size < need {
				return 0, errors.New("object write range exceeds an existing component")
			}
		}
	}
	buffer := make([]byte, min(uint64(c.WriteSize), uint64(iscsi.ObjectMaxTransfer), length))
	defer clear(buffer)
	for uint64(count) < length {
		if err := guard(false); err != nil {
			return count, err
		}
		logical := offset + uint64(count)
		l, err := fileLayoutAt(layouts, logical)
		if err != nil {
			return count, err
		}
		index, physical, left := objectPosition(l.object, logical)
		part := l.object.components[index]
		dev := devices[string(part.device)]
		n := min(uint64(len(buffer)), length-uint64(count), left, l.length-(logical-l.offset))
		data := buffer[:n]
		if _, err := io.ReadFull(input, data); err != nil {
			return count, err
		}
		if err := guard(false); err != nil {
			return count, err
		}
		currentSize, err := dev.LengthWithCredential(part.partition, part.object, part.credential)
		if err != nil {
			return count, v.objectFailure(part, 0, ^uint64(0), err)
		}
		if physical > currentSize || n > currentSize-physical {
			return count, errors.New("OSD component shrank before write")
		}
		if err := guard(false); err != nil {
			return count, err
		}
		pending = true
		if err := dev.WriteWithCredential(part.partition, part.object, physical, part.credential, data); err != nil {
			return count, v.objectWriteFailure(part, physical, n, err)
		}
		if err := guard(true); err != nil {
			return count, err
		}
		if err := dev.FlushWithCredential(part.partition, part.object, part.credential); err != nil {
			return count, v.objectWriteFailure(part, physical, n, err)
		}
		if err := guard(true); err != nil {
			return count, err
		}
		if err := v.commitObjectWrite(ctx, fh, logical+n-1, before.Size); err != nil {
			return count, err
		}
		pending = false
		count += int64(n)
		if progress != nil {
			progress(uint64(count))
		}
	}
	if err := guard(false); err != nil {
		return count, err
	}
	after, err := c.GetAttr(ctx, fh)
	if err != nil {
		return count, err
	}
	if after.Type != 1 || !after.HasSize || after.Size != before.Size {
		return count, errors.New("object write completed but destination size changed")
	}
	return count, guard(false)
}

func (v *v4Client) commitObjectWrite(ctx context.Context, fh []byte, last, size uint64) error {
	v.recall.mu.Lock()
	state := bytes.Clone(v.recall.state)
	v.recall.mu.Unlock()
	var e, update encoder
	e.u64(0)
	e.u64(0)
	e.u32(0)
	e = append(e, state...)
	e.u32(1)
	e.u64(last)
	e.u32(0)
	e.u32(2)
	// RFC 5664 section 10.2 reserves offset/length as zero; section 6.2
	// reports no known space delta and no I/O error for this confirmed chunk.
	update.u32(0)
	update.u32(0)
	e.opaque(update)
	return v.compound(ctx, fh4(fh), op4(49, e, func(d *decoder) {
		if d.boolean() && d.u64() != size {
			d.err = errors.New("OSD LAYOUTCOMMIT changed destination size")
		}
	}))
}
