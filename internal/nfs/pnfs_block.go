package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"nfs-viewer/internal/iscsi"
)

const blockSector = 512

type blockExtent struct {
	device                  []byte
	offset, length, storage uint64
	state                   uint32
}

func decodeBlockExtents(d *decoder, offset, length uint64) []blockExtent {
	n := d.u32()
	if n == 0 || n > 1024 || length == 0 || length > math.MaxUint64-offset {
		d.err = errors.New("invalid block extent count or layout range")
		return nil
	}
	end := offset
	extents := make([]blockExtent, 0, n)
	for range n {
		e := blockExtent{device: append([]byte(nil), d.take(16)...), offset: d.u64(), length: d.u64(), storage: d.u64(), state: d.u32()}
		if d.err != nil {
			return nil
		}
		if e.offset != end || e.offset%blockSector != 0 || e.length == 0 || e.length%blockSector != 0 || e.length > math.MaxUint64-e.offset || e.state != 1 && e.state != 3 || e.state == 1 && (e.storage%blockSector != 0 || e.length > math.MaxUint64-e.storage) {
			d.err = errors.New("invalid read-only block extent range, alignment or state")
			return nil
		}
		end = e.offset + e.length
		extents = append(extents, e)
	}
	if end != offset+length || len(d.b) != 0 {
		d.err = errors.New("incomplete block extent coverage or trailing data")
		return nil
	}
	return extents
}

func decodeWritableBlockExtents(d *decoder, offset, length uint64) []blockExtent {
	n := d.u32()
	if n == 0 || n > 1024 || length == 0 || length > math.MaxUint64-offset {
		d.err = errors.New("invalid writable block extent count or range")
		return nil
	}
	extents := make([]blockExtent, 0, n)
	end := offset
	var reads []blockExtent
	for range n {
		e := blockExtent{device: append([]byte(nil), d.take(16)...), offset: d.u64(), length: d.u64(), storage: d.u64(), state: d.u32()}
		if d.err != nil {
			return nil
		}
		if e.offset%blockSector != 0 || e.length == 0 || e.length%blockSector != 0 || e.length > math.MaxUint64-e.offset || e.storage%blockSector != 0 || e.length > math.MaxUint64-e.storage || e.state > 2 || e.offset < offset || e.offset+e.length > offset+length {
			d.err = errors.New("invalid writable block extent bounds, alignment or state")
			return nil
		}
		if len(extents) > 0 {
			previous := extents[len(extents)-1]
			if previous.offset > e.offset || previous.offset == e.offset && previous.state >= e.state {
				d.err = errors.New("unordered writable block extents")
				return nil
			}
		}
		if e.state == 1 {
			if len(reads) > 0 && reads[len(reads)-1].offset+reads[len(reads)-1].length > e.offset {
				d.err = errors.New("overlapping COW source extents")
				return nil
			}
			reads = append(reads, e)
		} else {
			if e.offset != end {
				d.err = errors.New("noncontiguous writable block coverage")
				return nil
			}
			end += e.length
		}
		extents = append(extents, e)
	}
	if end != offset+length || len(d.b) != 0 {
		d.err = errors.New("incomplete writable block coverage or trailing data")
		return nil
	}
	for _, r := range reads {
		covered := r.offset
		for _, e := range extents {
			if e.state == 2 && covered >= e.offset && covered < e.offset+e.length {
				covered = min(r.offset+r.length, e.offset+e.length)
			}
		}
		if covered != r.offset+r.length {
			d.err = errors.New("COW source is not covered by invalid writable extents")
			return nil
		}
	}
	return extents
}

type blockSignature struct {
	offset int64
	data   []byte
}
type blockVolume struct {
	kind              uint32
	signatures        []blockSignature
	start, size, unit uint64
	children          []uint32
	file              blockStorage
}

func decodeBlockVolumes(d *decoder) []*blockVolume {
	if len(d.b) > 32768 {
		d.err = errors.New("block device body exceeds 32 KiB")
		return nil
	}
	n := d.u32()
	if n == 0 || n > 64 {
		d.err = errors.New("block device needs 1..64 volumes")
		return nil
	}
	volumes := make([]*blockVolume, 0, n)
	for i := uint32(0); i < n && d.err == nil; i++ {
		v := &blockVolume{kind: d.u32()}
		switch v.kind {
		case 0:
			count := d.u32()
			if count == 0 || count > 16 {
				d.err = errors.New("block volume needs 1..16 signature components")
				break
			}
			for range count {
				s := blockSignature{offset: int64(d.u64()), data: append([]byte(nil), d.opaque(4096)...)}
				if len(s.data) == 0 && d.err == nil {
					d.err = errors.New("empty block volume signature")
				}
				v.signatures = append(v.signatures, s)
			}
		case 1:
			v.start, v.size = d.u64(), d.u64()
			v.children = []uint32{d.u32()}
			if v.start%blockSector != 0 || v.size == 0 || v.size%blockSector != 0 || v.size > math.MaxInt64 || v.start > math.MaxInt64-v.size {
				d.err = errors.New("invalid block slice range")
			}
		case 2, 3:
			if v.kind == 3 {
				v.unit = d.u64()
				if v.unit == 0 || v.unit%blockSector != 0 || v.unit > math.MaxInt64 {
					d.err = errors.New("invalid block stripe unit")
				}
			}
			count := d.u32()
			if count == 0 || count > 64 {
				d.err = errors.New("invalid block volume child count")
				break
			}
			for range count {
				v.children = append(v.children, d.u32())
			}
		default:
			d.err = errors.New("unsupported block volume type")
		}
		for _, child := range v.children {
			if child >= i {
				d.err = errors.New("block volume references must precede their parent")
			}
		}
		volumes = append(volumes, v)
	}
	if d.err == nil && len(d.b) != 0 {
		d.err = errors.New("trailing block device data")
	}
	return volumes
}

func validateBlockOptions(o PNFSOptions) (PNFSOptions, error) {
	if o.ObjectWrite || o.OSDRequireSecure || len(o.OSDSecurity) != 0 {
		return o, errors.New("OSD security requires object layout")
	}
	if o.BlockWrite || o.BlockJournal != "" || o.BlockResume {
		return o, errors.New("BlockWrite is only accepted for block writes")
	}
	if len(o.BlockVolumes)+len(o.BlockTargets) == 0 || len(o.BlockVolumes)+len(o.BlockTargets) > 64 || len(o.DataServers) != 0 || len(o.SPNs) != 0 || len(o.TLSNames) != 0 || o.Extend || o.WriteFailover || o.MirrorFailover || o.RefreshDevices || o.SessionTrunking || o.Parallelism != 0 && o.Parallelism != 1 {
		return PNFSOptions{}, errors.New("block reads need 1..64 approved volumes without DS, write, parallel or recovery options")
	}
	result := PNFSOptions{blockGeometry: o.blockGeometry, Layout: "block", Parallelism: 1, BlockVolumes: slices.Clone(o.BlockVolumes), BlockTargets: slices.Clone(o.BlockTargets), BlockInitiator: o.BlockInitiator}
	result.ReadFailover = o.ReadFailover
	if err := validateBlockReadAlternates(o, &result); err != nil {
		return result, err
	}
	seen := map[string]bool{}
	for i, path := range result.BlockVolumes {
		if !filepath.IsAbs(path) {
			return result, errors.New("block volume paths must be absolute")
		}
		path = filepath.Clean(path)
		if seen[path] {
			return result, errors.New("duplicate block volume path")
		}
		seen[path] = true
		result.BlockVolumes[i] = path
	}
	if len(result.BlockTargets) != 0 && !iscsi.ValidName(result.BlockInitiator) || len(result.BlockTargets) == 0 && result.BlockInitiator != "" {
		return result, errors.New("block targets require an explicit initiator IQN; images alone do not")
	}
	for i, raw := range result.BlockTargets {
		target, err := iscsi.ParseTarget(raw)
		if err != nil {
			return result, err
		}
		canonical := "iscsi://" + target.Endpoint + "/" + target.Name + "/" + strconv.Itoa(int(target.LUN))
		if seen[canonical] {
			return result, errors.New("duplicate approved block target")
		}
		seen[canonical] = true
		result.BlockTargets[i] = canonical
	}
	var err error
	result.BlockSecurity, err = validateStorageSecurity(o.BlockSecurity, result.BlockTargets)
	if err != nil {
		return result, err
	}
	return result, nil
}

// Pointer implementations are comparable, preserving physical alias checks.
type blockStorage interface {
	ReadAt([]byte, int64) (int, error)
	WriteAt([]byte, int64) (int, error)
	Sync() error
	Stat() (os.FileInfo, error)
	Close() error
}

type blockFile struct {
	file blockStorage
	path string
	info os.FileInfo
}
type blockFiles []blockFile

func openBlockFiles(paths []string) (files blockFiles, resultErr error) {
	return openBlockFilesMode(paths, false)
}

func openBlockFilesMode(paths []string, writable bool) (files blockFiles, resultErr error) {
	defer func() {
		if resultErr != nil {
			files.close()
			files = nil
		}
	}()
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return files, err
		}
		if !info.Mode().IsRegular() {
			return files, errors.New("block volume must be a regular file, not a symlink or device")
		}
		mode := os.O_RDONLY
		if writable {
			mode = os.O_RDWR
		}
		f, err := os.OpenFile(path, mode, 0)
		if err != nil {
			return files, err
		}
		opened, err := f.Stat()
		if err != nil {
			f.Close()
			return files, err
		}
		files = append(files, blockFile{f, path, opened})
		if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() == 0 || opened.Size()%blockSector != 0 {
			return files, errors.New("invalid or substituted block volume image")
		}
		for _, prior := range files[:len(files)-1] {
			if os.SameFile(prior.info, opened) {
				return files, errors.New("aliased block volume images")
			}
		}
	}
	return files, files.check()
}

// Storage approvals are opened once for this operation, never from MDS URLs.
func openBlockStorage(ctx context.Context, o PNFSOptions, timeout time.Duration, writable bool) (files blockFiles, resultErr error) {
	files, resultErr = openBlockFilesMode(o.BlockVolumes, writable)
	if resultErr != nil {
		return nil, resultErr
	}
	defer func() {
		if resultErr != nil {
			files.close()
			files = nil
		}
	}()
	seen := map[string]bool{}
	for _, raw := range o.BlockTargets {
		target, err := iscsi.ParseTarget(raw)
		if err != nil {
			return files, err
		}
		volume, err := iscsi.OpenWithSecurity(ctx, target, o.BlockInitiator, timeout, writable, o.BlockSecurity[raw])
		if err != nil {
			return files, err
		}
		info, err := volume.Stat()
		if err != nil {
			volume.Close()
			return files, err
		}
		files = append(files, blockFile{volume, raw, info})
		if seen[volume.Identity()] {
			return files, errors.New("approved iSCSI targets alias the same logical unit")
		}
		seen[volume.Identity()] = true
	}
	if o.blockGeometry != "" && o.blockGeometry != files.geometryFingerprint() {
		return files, errors.New("block storage identity or geometry changed")
	}
	return files, files.check()
}

func (files blockFiles) geometryFingerprint() string {
	var data []byte
	for _, f := range files {
		if remote, ok := f.file.(*iscsi.Volume); ok {
			data = append(data, []byte(fmt.Sprintf("%s\x00%x\x00%d\x00%d\n", f.path, remote.Identity(), f.info.Size(), remote.SectorSize()))...)
		}
	}
	if len(data) == 0 {
		return ""
	}
	return blockHash(data)
}

func (files blockFiles) close() {
	for _, f := range files {
		f.file.Close()
	}
}
func (files blockFiles) check() error {
	for _, f := range files {
		if remote, ok := f.file.(*iscsi.Volume); ok {
			if err := remote.Check(); err != nil {
				return err
			}
			continue
		}
		current, err := f.file.Stat()
		if err != nil {
			return err
		}
		named, err := os.Lstat(f.path)
		if err != nil {
			return err
		}
		if !named.Mode().IsRegular() || !os.SameFile(f.info, named) || current.Size() != f.info.Size() || !current.ModTime().Equal(f.info.ModTime()) {
			return errors.New("block volume image changed or was substituted")
		}
	}
	return nil
}

func blockSignatureMatches(f blockFile, signatures []blockSignature) (bool, error) {
	for _, s := range signatures {
		offset := s.offset
		if offset < 0 {
			offset += f.info.Size()
		}
		if offset < 0 || offset > f.info.Size() || int64(len(s.data)) > f.info.Size()-offset {
			return false, nil
		}
		data := make([]byte, len(s.data))
		if _, err := f.file.ReadAt(data, offset); err != nil {
			return false, err
		}
		if !bytes.Equal(data, s.data) {
			return false, nil
		}
	}
	return true, nil
}

func (files blockFiles) bind(volumes []*blockVolume) error {
	for _, v := range volumes {
		switch v.kind {
		case 0:
			matches := 0
			for _, f := range files {
				match, err := blockSignatureMatches(f, v.signatures)
				if err != nil {
					return err
				}
				if match {
					v.file, v.size = f.file, uint64(f.info.Size())
					matches++
				}
			}
			if matches != 1 {
				return fmt.Errorf("block volume signature matched %d approved images; exactly one is required", matches)
			}
		case 1:
			child := volumes[v.children[0]]
			if v.start > child.size || v.size > child.size-v.start {
				return errors.New("block slice exceeds its volume")
			}
		case 2, 3:
			for _, index := range v.children {
				child := volumes[index]
				if v.kind == 3 && (child.size != volumes[v.children[0]].size || child.size%v.unit != 0) {
					return errors.New("block stripe components must have equal stripe-aligned capacities")
				}
				if child.size > math.MaxInt64-v.size {
					return errors.New("block logical volume exceeds int64 capacity")
				}
				v.size += child.size
			}
		}
	}
	return files.check()
}

// Return one contiguous physical window. Descending indices bound traversal
// without allowing a hostile nested stripe to multiply the number of reads.
func blockPosition(volumes []*blockVolume, index int, offset uint64) (blockStorage, uint64, uint64, error) {
	left := uint64(math.MaxInt64)
	for {
		v := volumes[index]
		if offset >= v.size {
			return nil, 0, 0, errors.New("block offset exceeds logical volume")
		}
		left = min(left, v.size-offset)
		switch v.kind {
		case 0:
			return v.file, offset, left, nil
		case 1:
			offset += v.start
			index = int(v.children[0])
		case 2:
			for _, child := range v.children {
				if offset < volumes[child].size {
					index = int(child)
					break
				}
				offset -= volumes[child].size
			}
		case 3:
			stripe := offset / v.unit
			left = min(left, v.unit-offset%v.unit)
			index = int(v.children[stripe%uint64(len(v.children))])
			offset = stripe/uint64(len(v.children))*v.unit + offset%v.unit
		}
	}
}

func readBlockVolume(volumes []*blockVolume, index int, data []byte, offset uint64) error {
	for len(data) != 0 {
		f, position, left, err := blockPosition(volumes, index, offset)
		if err != nil {
			return err
		}
		n := min(uint64(len(data)), left)
		if _, err := f.ReadAt(data[:n], int64(position)); err != nil {
			return err
		}
		data, offset = data[n:], offset+n
	}
	return nil
}

func (v *v4Client) blockLayoutHint(ctx context.Context, fh, sid []byte) error {
	var hint, value encoder
	hint.u64(math.MaxUint64) // Regular-file I/O has no enforceable completion deadline.
	value.u32(3)
	value.opaque(hint)
	e := append(encoder(nil), sid...)
	bitmap4(&e, 63)
	e.opaque(value)
	op := op4(34, e, func(d *decoder) {
		if !slices.Equal(readBitmap4(d), []uint32{63}) && d.err == nil {
			d.err = errors.New("server did not accept the block I/O-time hint")
		}
	})
	op.failure = func(d *decoder) { readBitmap4(d) }
	return v.compound(ctx, fh4(fh), op)
}

func (v *v4Client) blockDevice(ctx context.Context, id []byte) ([]*blockVolume, error) {
	e := append(encoder(nil), id...)
	e.u32(3)
	e.u32(32768)
	e.u32(0)
	var volumes []*blockVolume
	op := op4(47, e, func(d *decoder) {
		if d.u32() != 3 {
			d.err = errors.New("unexpected block device layout type")
			return
		}
		sub := &decoder{b: d.opaque(32768)}
		volumes = decodeBlockVolumes(sub)
		if sub.err != nil {
			d.err = sub.err
			return
		}
		if len(readBitmap4(d)) != 0 {
			d.err = errors.New("unsolicited block device notifications")
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
	return volumes, err
}

func (c *Client) readBlockPNFS(ctx context.Context, fh []byte, size uint64, w io.Writer, o PNFSOptions, progress func(uint64), verify func() error) (count int64, resultErr error) {
	if w == nil {
		return 0, errors.New("block read destination is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	files, err := openBlockStorage(ctx, o, c.config.Timeout, false)
	if err != nil {
		return 0, err
	}
	defer files.close()
	v := c.v4
	auth, identity := c.Auth, c.Identity()
	auth.Groups = slices.Clone(auth.Groups)
	profileOK := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.v4 != v || !sameNLMAuth(auth, c.Auth) || c.Identity() != identity {
			return errors.New("block read identity or client state changed")
		}
		return files.check()
	}
	if err := profileOK(); err != nil {
		return 0, err
	}
	sid, closeIO, err := v.openIO(ctx, fh, 1)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	if err := v.blockLayoutHint(ctx, fh, sid); err != nil {
		return 0, err
	}
	if size == 0 {
		if verify != nil {
			if err := verify(); err != nil {
				return 0, err
			}
		}
		return 0, profileOK()
	}
	layouts, err := v.getLayoutType(ctx, fh, sid, size, 1, 3)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, v.returnLayout(fh)) }()
	usable := func() error {
		if err := profileOK(); err != nil {
			return err
		}
		return v.layoutUsable(fh)
	}
	devices := map[string][]*blockVolume{}
	// Validate all extents and capacities before publishing any data bytes.
	for _, l := range layouts {
		if l.iomode != 1 {
			return 0, errors.New("block read requires read-only layout extents")
		}
		for _, e := range l.block {
			if e.state == 3 {
				continue
			}
			key := string(e.device)
			volumes := devices[key]
			if volumes == nil {
				if len(devices) == 64 {
					return 0, errors.New("block transfer exceeds 64 device topologies")
				}
				if err := usable(); err != nil {
					return 0, err
				}
				volumes, err = v.blockDevice(ctx, e.device)
				if err != nil {
					return 0, err
				}
				if err := files.bind(volumes); err != nil {
					return 0, err
				}
				devices[key] = volumes
			}
			capacity := volumes[len(volumes)-1].size
			if e.storage > capacity || e.length > capacity-e.storage {
				return 0, errors.New("block extent exceeds its approved logical volume")
			}
		}
	}
	if o.ReadFailover {
		guard := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if c.v4 != v || !sameNLMAuth(auth, c.Auth) || c.Identity() != identity {
				return errors.New("block read identity or client state changed")
			}
			return v.layoutUsable(fh)
		}
		if err := files.enableReadRecovery(o, devices, guard); err != nil {
			return 0, err
		}
	}
	buffer := make([]byte, min(uint64(1<<20), uint64(c.ReadSize), size))
	for uint64(count) < size {
		if err := usable(); err != nil {
			return count, err
		}
		l, err := fileLayoutAt(layouts, uint64(count))
		if err != nil {
			return count, err
		}
		var extent *blockExtent
		for i := range l.block {
			e := &l.block[i]
			if uint64(count) >= e.offset && uint64(count)-e.offset < e.length {
				extent = e
				break
			}
		}
		if extent == nil {
			return count, errors.New("block read outside extent coverage")
		}
		relative := uint64(count) - extent.offset
		data := buffer[:min(uint64(len(buffer)), size-uint64(count), extent.length-relative, l.length-(uint64(count)-l.offset))]
		if extent.state == 3 {
			clear(data)
		} else {
			volumes := devices[string(extent.device)]
			// One physical read per iteration keeps cancellation/recall checks
			// between stripe fragments as well as between logical extents.
			_, _, left, err := blockPosition(volumes, len(volumes)-1, extent.storage+relative)
			if err != nil {
				return count, err
			}
			data = data[:min(uint64(len(data)), left)]
			if err := readBlockVolume(volumes, len(volumes)-1, data, extent.storage+relative); err != nil {
				return count, err
			}
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
