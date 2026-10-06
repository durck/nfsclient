package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"

	"nfs-viewer/internal/iscsi"
)

type objectCredential struct {
	device            []byte
	partition, object uint64
	cap               []byte
	credential        *iscsi.ObjectCredential
}
type objectLayout struct {
	unit       uint64
	components []objectCredential
}
type objectAddress struct {
	target         iscsi.Target
	systemID, name []byte
	root           objectCredential
}

func decodeObjectCredential(d *decoder, root bool) objectCredential {
	c := objectCredential{device: bytes.Clone(d.take(16)), partition: d.u64(), object: d.u64()}
	version, security := d.u32(), d.u32()
	key, cap := d.opaque(104), d.opaque(104)
	defer clear(key)
	if version != 1 || security != 0 || root && (c.partition != 0 || c.object != 0) || !root && (c.partition < 0x10000 || c.object < 0x10000) {
		d.err = errors.New("OSD requires version 1, SEC_NONE key encoding and valid object IDs")
	}
	if d.err == nil {
		var err error
		c.credential, err = iscsi.NewObjectCredential(c.partition, c.object, cap, key)
		if err != nil {
			d.err = err
		}
	}
	c.cap = bytes.Clone(cap)
	return c
}

func decodeObjectLayout(d *decoder) *objectLayout {
	n := d.u32()
	l := &objectLayout{unit: d.u64()}
	defer func() {
		if d.err != nil {
			for _, c := range l.components {
				c.credential.Close()
			}
		}
	}()
	width, depth, mirrors, raid, first, count := d.u32(), d.u32(), d.u32(), d.u32(), d.u32(), d.u32()
	if n == 0 || n > 64 || l.unit == 0 || l.unit > 1<<20 || width != 0 || depth != 0 || mirrors != 0 || raid != 1 || first != 0 || count != n {
		d.err = errors.New("OSD requires a complete dense RAID0 component array without groups or mirrors")
		return l
	}
	seen := map[string]bool{}
	for range n {
		c := decodeObjectCredential(d, false)
		key := string(c.device) + "/" + strconv.FormatUint(c.partition, 10) + "/" + strconv.FormatUint(c.object, 10)
		if seen[key] {
			d.err = errors.New("duplicate OSD object component")
		}
		seen[key] = true
		l.components = append(l.components, c)
	}
	if len(d.b) != 0 {
		d.err = errors.New("trailing OSD layout data")
	}
	return l
}

func validateObjectOptions(o PNFSOptions) (PNFSOptions, error) {
	if len(o.BlockReadAlternates) != 0 || len(o.BlockSecurity) != 0 || len(o.OSDTargets) < 1 || len(o.OSDTargets) > 64 || !iscsi.ValidName(o.OSDInitiator) || len(o.BlockVolumes)+len(o.BlockTargets)+len(o.DataServers)+len(o.SPNs)+len(o.TLSNames) != 0 || o.BlockInitiator != "" || o.BlockWrite || o.BlockJournal != "" || o.BlockResume || o.Extend || o.ReadFailover || o.WriteFailover || o.MirrorFailover || o.RefreshDevices || o.SessionTrunking || o.Parallelism < 0 || o.Parallelism > 1 {
		return PNFSOptions{}, errors.New("object reads need 1..64 explicit OSD targets and an initiator without write, DS or recovery options")
	}
	out := PNFSOptions{Layout: "object", Parallelism: 1, OSDInitiator: o.OSDInitiator, OSDRequireSecure: o.OSDRequireSecure}
	seen := map[iscsi.Target]bool{}
	for _, raw := range o.OSDTargets {
		t, err := iscsi.ParseTarget(raw)
		if err != nil {
			return out, err
		}
		if seen[t] {
			return out, errors.New("duplicate OSD target")
		}
		seen[t] = true
		out.OSDTargets = append(out.OSDTargets, "iscsi://"+t.Endpoint+"/"+t.Name+"/"+strconv.Itoa(int(t.LUN)))
	}
	var err error
	out.OSDSecurity, err = validateStorageSecurity(o.OSDSecurity, out.OSDTargets)
	if err != nil {
		return out, err
	}
	return out, nil
}

func decodeObjectAddress(d *decoder, id []byte, approved []string) objectAddress {
	var a objectAddress
	defer func() {
		if d.err != nil {
			a.root.credential.Close()
		}
	}()
	if d.u32() != 2 {
		d.err = errors.New("OSD requires a SCSI name target")
		return a
	}
	name := string(d.opaque(223))
	if !d.boolean() {
		d.err = errors.New("OSD requires an explicit TCP target address")
		return a
	}
	network, address := string(d.opaque(16)), string(d.opaque(1024))
	endpoint, err := universalEndpoint(network, address)
	if err != nil {
		d.err = err
		return a
	}
	lun := d.take(8)
	a.systemID = bytes.Clone(d.opaque(20))
	a.root = decodeObjectCredential(d, true)
	a.name = bytes.Clone(d.opaque(255))
	if d.err != nil {
		return a
	}
	if lun[0] != 0 || !bytes.Equal(lun[2:], make([]byte, 6)) || len(a.systemID) != 20 || bytes.Equal(a.systemID, make([]byte, 20)) || !bytes.Equal(a.root.device, id) || len(d.b) != 0 {
		d.err = errors.New("invalid OSD LUN, system ID, root device or trailing data")
		return a
	}
	a.target = iscsi.Target{Endpoint: endpoint, Name: name, LUN: lun[1]}
	for _, raw := range approved {
		t, e := iscsi.ParseTarget(raw)
		if e == nil && t == a.target {
			return a
		}
	}
	d.err = errors.New("OSD target/LUN is not explicitly approved")
	return a
}

func (v *v4Client) objectDevice(ctx context.Context, id []byte, o PNFSOptions) (objectAddress, error) {
	e := append(encoder(nil), id...)
	e.u32(2)
	e.u32(32768)
	e.u32(0)
	var a objectAddress
	op := op4(47, e, func(d *decoder) {
		if d.u32() != 2 {
			d.err = errors.New("unexpected object device layout type")
			return
		}
		sub := &decoder{b: d.opaque(32768)}
		a = decodeObjectAddress(sub, id, o.OSDTargets)
		if sub.err != nil {
			d.err = sub.err
			return
		}
		if len(readBitmap4(d)) != 0 {
			d.err = errors.New("unsolicited OSD device notifications")
		}
	})
	var status Status
	op.result = func(s Status) { status = s }
	op.failure = func(d *decoder) {
		if status == 10005 {
			d.u32()
		}
	}
	err := v.compound(ctx, op)
	if err != nil {
		a.root.credential.Close()
	}
	return a, err
}

func closeObjectLayouts(layouts []*fileLayout) {
	for _, l := range layouts {
		if l.object != nil {
			for _, component := range l.object.components {
				component.credential.Close()
			}
		}
	}
}

// Capability keys may only arrive over an authenticated confidential MDS
// channel (RFC 5664 section 13). Transport state reflects the live handshake.
func (c *Client) objectCredentialPrivacy() bool {
	if c.Security() == "krb5p" {
		return true
	}
	return c.nfs != nil && len(c.nfs.tlsVerifiedChains) != 0
}

func objectPosition(l *objectLayout, offset uint64) (int, uint64, uint64) {
	n := uint64(len(l.components))
	stripe := offset / l.unit
	return int(stripe % n), (stripe/n)*l.unit + offset%l.unit, l.unit - offset%l.unit
}

func (v *v4Client) objectFailure(c objectCredential, offset, length uint64, err error) error {
	var e encoder
	e = append(e, c.device...)
	e.u64(c.partition)
	e.u64(c.object)
	e.u64(offset)
	e.u64(length)
	e.u32(0)
	e.u32(1)
	v.recall.mu.Lock()
	v.recall.objectError = e
	v.recall.mu.Unlock()
	return err
}

func (c *Client) readObjectPNFS(ctx context.Context, fh []byte, size uint64, w io.Writer, o PNFSOptions, progress func(uint64), verify func() error) (count int64, resultErr error) {
	if w == nil {
		return 0, errors.New("object read destination is required")
	}
	if o.OSDRequireSecure && !c.objectCredentialPrivacy() {
		return 0, errors.New("secured OSD requests require krb5p or authenticated TLS to the metadata server")
	}
	v, auth, identity := c.v4, c.Auth, c.Identity()
	auth.Groups = slices.Clone(auth.Groups)
	devices := map[string]*iscsi.ObjectDevice{}
	defer func() {
		for _, dev := range devices {
			dev.Close()
		}
	}()
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.v4 != v || !sameNLMAuth(auth, c.Auth) || c.Identity() != identity {
			return errors.New("object read identity or client state changed")
		}
		for _, dev := range devices {
			if err := dev.Check(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := guard(); err != nil {
		return 0, err
	}
	sid, closeIO, err := v.openIO(ctx, fh, 1)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	if size == 0 {
		if verify != nil {
			if err := verify(); err != nil {
				return 0, err
			}
		}
		return 0, guard()
	}
	layouts, err := v.getLayoutType(ctx, fh, sid, size, 1, 2)
	if err != nil {
		return 0, err
	}
	defer closeObjectLayouts(layouts)
	defer func() { resultErr = errors.Join(resultErr, v.returnLayout(fh)) }()
	usable := func() error {
		if err := guard(); err != nil {
			return err
		}
		return v.layoutUsable(fh)
	}
	targetIDs := map[iscsi.Target]string{}
	secureDevices := map[string]bool{}
	addresses := map[string]objectAddress{}
	defer func() {
		for _, a := range addresses {
			a.root.credential.Close()
		}
	}()
	// Probe all devices before exposing the first byte, including components
	// that are not visited by a short logical file.
	for _, l := range layouts {
		for _, component := range l.object.components {
			if component.credential == nil || o.OSDRequireSecure && !component.credential.Secured() || component.credential.Secured() && !c.objectCredentialPrivacy() {
				return 0, errors.New("OSD secure capability requires protected MDS and ALLDATA credentials")
			}
			if err := component.credential.Check(component.partition, component.object, iscsi.ObjectRead|iscsi.ObjectGetAttributes); err != nil {
				return 0, err
			}
			if component.credential.Secured() {
				secureDevices[string(component.device)] = true
			}
		}
	}
	for _, l := range layouts {
		for _, component := range l.object.components {
			key := string(component.device)
			if _, ok := addresses[key]; ok {
				continue
			}
			if len(addresses) == 64 {
				return 0, errors.New("OSD transfer exceeds 64 devices")
			}
			if err := usable(); err != nil {
				return 0, err
			}
			a, err := v.objectDevice(ctx, component.device, o)
			if err != nil {
				return 0, err
			}
			if old, ok := targetIDs[a.target]; ok && old != key {
				a.root.credential.Close()
				return 0, errors.New("OSD device IDs alias an approved LUN")
			}
			if a.root.credential == nil || (o.OSDRequireSecure || secureDevices[key]) && !a.root.credential.Secured() || a.root.credential.Secured() && !c.objectCredentialPrivacy() {
				a.root.credential.Close()
				return 0, errors.New("OSD root capability security mismatch")
			}
			if err := a.root.credential.Check(0, 0, iscsi.ObjectGetAttributes); err != nil {
				a.root.credential.Close()
				return 0, err
			}
			addresses[key], targetIDs[a.target] = a, key
		}
	}
	for key, a := range addresses {
		if err := usable(); err != nil {
			return 0, err
		}
		dev, err := iscsi.OpenObjectWithCredential(ctx, a.target, o.OSDInitiator, c.config.Timeout, a.systemID, a.name, a.root.credential, o.OSDSecurity["iscsi://"+a.target.Endpoint+"/"+a.target.Name+"/"+strconv.Itoa(int(a.target.LUN))])
		a.root.credential.Close()
		if err != nil {
			return 0, err
		}
		devices[key] = dev
	}
	buffer := make([]byte, min(size, uint64(c.ReadSize), uint64(iscsi.ObjectMaxTransfer)))
	for uint64(count) < size {
		if err := usable(); err != nil {
			return count, err
		}
		l, err := fileLayoutAt(layouts, uint64(count))
		if err != nil {
			return count, err
		}
		index, off, left := objectPosition(l.object, uint64(count))
		component := l.object.components[index]
		dev := devices[string(component.device)]
		length, err := dev.LengthWithCredential(component.partition, component.object, component.credential)
		if err != nil {
			return count, v.objectFailure(component, 0, ^uint64(0), err)
		}
		data := buffer[:min(uint64(len(buffer)), size-uint64(count), left, l.length-(uint64(count)-l.offset))]
		clear(data)
		if off < length {
			n := min(uint64(len(data)), length-off)
			if err := dev.ReadWithCredential(component.partition, component.object, off, component.credential, data[:n]); err != nil {
				return count, v.objectFailure(component, off, n, err)
			}
		}
		after, err := dev.LengthWithCredential(component.partition, component.object, component.credential)
		if err != nil {
			return count, v.objectFailure(component, 0, ^uint64(0), err)
		}
		if after != length {
			return count, errors.New("OSD object length changed during read")
		}
		if err := usable(); err != nil {
			return count, err
		}
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return count, io.ErrShortWrite
		}
		count += int64(n)
		if progress != nil {
			progress(uint64(count))
		}
		if err != nil {
			return count, err
		}
		if n != len(data) {
			return count, io.ErrShortWrite
		}
	}
	if err := usable(); err != nil {
		return count, err
	}
	if verify != nil {
		if err := verify(); err != nil {
			return count, err
		}
	}
	return count, usable()
}
