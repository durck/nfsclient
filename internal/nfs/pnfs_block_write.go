package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"nfs-viewer/internal/iscsi"
)

func validateBlockWriteOptions(o PNFSOptions) (PNFSOptions, error) {
	if o.ReadFailover || len(o.BlockReadAlternates) != 0 {
		return o, errors.New("iSCSI read recovery cannot be enabled for block writes")
	}
	if o.Layout != "block" || !o.BlockWrite {
		return o, errors.New("block range writes require explicit BlockWrite approval")
	}
	o.BlockWrite = false
	journal, resume := o.BlockJournal, o.BlockResume
	o.BlockJournal, o.BlockResume = "", false
	extend := o.Extend
	o.Extend = false
	result, err := validateBlockOptions(o)
	result.BlockWrite = true
	result.Extend = extend
	result.BlockJournal, result.BlockResume = journal, resume
	if err == nil && (resume && journal == "" || journal != "" && !filepath.IsAbs(journal)) {
		err = errors.New("block recovery requires an absolute journal path")
	}
	return result, err
}

type blockPhysicalRange struct {
	file           blockStorage
	offset, length uint64
	write          bool
}

// Validate the complete effective grant, including untouched extents, before
// changing storage. Duplicate physical writable ranges, COW aliases and writes
// into signature bytes would otherwise corrupt unrelated data or volume identity.
func checkBlockWriteMapping(layouts []*fileLayout, devices map[string][]*blockVolume, blockSize uint64) error {
	var ranges []blockPhysicalRange
	appendRange := func(r blockPhysicalRange) error {
		if len(ranges) == 16384 {
			return errors.New("block write mapping exceeds 16384 physical windows")
		}
		ranges = append(ranges, r)
		return nil
	}
	for _, l := range layouts {
		if l.offset%blockSize != 0 || l.length%blockSize != 0 {
			return errors.New("writable grant boundary is not server-block aligned")
		}
		for _, e := range l.block {
			start, end := max(l.offset, e.offset), min(l.offset+l.length, e.offset+e.length)
			if start >= end {
				continue
			}
			if e.state != 1 && (start%blockSize != 0 || end%blockSize != 0 || e.storage%blockSize != 0) {
				return errors.New("writable extent is not server-block aligned")
			}
			volumes := devices[string(e.device)]
			for off := start; off < end; {
				f, physical, left, err := blockPosition(volumes, len(volumes)-1, e.storage+off-e.offset)
				if err != nil {
					return err
				}
				length := min(left, end-off)
				if remote, ok := f.(*iscsi.Volume); ok && e.state != 1 && (physical%uint64(remote.SectorSize()) != 0 || length%uint64(remote.SectorSize()) != 0 || blockSize%uint64(remote.SectorSize()) != 0) {
					return errors.New("iSCSI writable mapping must contain complete sectors")
				}
				if err := appendRange(blockPhysicalRange{f, physical, length, e.state != 1}); err != nil {
					return err
				}
				off += length
			}
		}
	}
	for _, volumes := range devices {
		for _, v := range volumes {
			if v.kind != 0 {
				continue
			}
			for _, s := range v.signatures {
				offset := s.offset
				if offset < 0 {
					offset += int64(v.size)
				}
				if err := appendRange(blockPhysicalRange{v.file, uint64(offset), uint64(len(s.data)), false}); err != nil {
					return err
				}
			}
		}
	}
	byFile := map[blockStorage][]blockPhysicalRange{}
	for _, r := range ranges {
		byFile[r.file] = append(byFile[r.file], r)
	}
	for _, rs := range byFile {
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].offset != rs[j].offset {
				return rs[i].offset < rs[j].offset
			}
			return !rs[i].write && rs[j].write
		})
		var readEnd, writeEnd uint64
		for _, r := range rs {
			if r.write && r.offset < max(readEnd, writeEnd) || !r.write && r.offset < writeEnd {
				return errors.New("block writable mappings alias another extent or volume signature")
			}
			if r.write {
				writeEnd = max(writeEnd, r.offset+r.length)
			} else {
				readEnd = max(readEnd, r.offset+r.length)
			}
		}
	}
	return nil
}

// A local write is the only operation allowed to advance this image baseline.
// Concurrent image writers remain outside this explicit single-writer profile.
func (files blockFiles) acceptWrite(file blockStorage) error {
	for i := range files {
		f := &files[i]
		if f.file != file {
			continue
		}
		if remote, ok := file.(*iscsi.Volume); ok {
			if err := remote.Check(); err != nil {
				return err
			}
			return files.check()
		}
		current, err := file.Stat()
		if err != nil {
			return err
		}
		named, err := os.Lstat(f.path)
		if err != nil {
			return err
		}
		if !named.Mode().IsRegular() || !os.SameFile(f.info, named) || !os.SameFile(f.info, current) || current.Size() != f.info.Size() {
			return errors.New("written block image changed identity or size")
		}
		f.info = current
		return files.check()
	}
	return errors.New("write targeted an unapproved block image")
}

func (v *v4Client) commitBlockWrite(ctx context.Context, fh []byte, offset, blockSize, last uint64, extent blockExtent, size uint64) error {
	v.recall.mu.Lock()
	state := slices.Clone(v.recall.state)
	v.recall.mu.Unlock()
	var update, e encoder
	if extent.state == 2 {
		update.u32(1)
		update = append(update, extent.device...)
		update.u64(offset)
		update.u64(blockSize)
		update.u64(0)
		update.u32(0)
	} else {
		update.u32(0)
	}
	e.u64(offset)
	e.u64(blockSize)
	e.u32(0)
	e = append(e, state...)
	e.u32(1)
	e.u64(last)
	e.u32(0)
	e.u32(3)
	e.opaque(update)
	return v.compound(ctx, fh4(fh), op4(49, e, func(d *decoder) {
		if d.boolean() && d.u64() != size {
			d.err = errors.New("block LAYOUTCOMMIT changed destination size")
		}
	}))
}

func (c *Client) writeBlockPNFS(ctx context.Context, fh []byte, offset, length uint64, input io.Reader, options PNFSOptions, progress func(uint64)) (count int64, resultErr error) {
	o, err := validateBlockWriteOptions(options)
	if err != nil {
		return 0, err
	}
	if input == nil || c.WriteSize == 0 || c.v4 == nil || c.v4.recall == nil || c.config == nil || !c.config.PNFS || length == 0 || length > math.MaxInt64 || offset > math.MaxInt64-length {
		return 0, errors.New("invalid block write source, range or pNFS connection")
	}
	lock, err := c.rangeLock(fh, offset, length, true)
	if err != nil {
		return 0, err
	}
	if lock.info.Offset != 0 || lock.info.Length != LockToEOF {
		return 0, errors.New("block writes require an existing whole-file write lock")
	}
	files, err := openBlockStorage(ctx, o, c.config.Timeout, true)
	if err != nil {
		return 0, err
	}
	defer files.close()
	o.blockGeometry = files.geometryFingerprint()
	if source, ok := input.(interface{ Stat() (os.FileInfo, error) }); ok {
		info, err := source.Stat()
		if err != nil {
			return 0, err
		}
		for _, file := range files {
			if os.SameFile(info, file.info) {
				return 0, errors.New("block write source aliases a volume image")
			}
		}
	}
	v, sid, auth, identity := c.v4, slices.Clone(lock.sid), c.Auth, c.Identity()
	lockedOffset, lockedLength := offset, length
	auth.Groups = slices.Clone(auth.Groups)
	profile := func() error {
		if c.v4 != v || !sameNLMAuth(auth, c.Auth) || c.Identity() != identity {
			return errors.New("block write identity or client changed")
		}
		if err := v.checkLockedIO(fh, 2); err != nil {
			return err
		}
		current, err := c.rangeLock(fh, lockedOffset, lockedLength, true)
		if err != nil {
			return err
		}
		if current != lock || !bytes.Equal(lock.sid, sid) {
			return errors.New("block write lock changed")
		}
		return files.check()
	}
	if err := errors.Join(ctx.Err(), profile()); err != nil {
		return 0, err
	}
	before, err := c.GetAttr(ctx, fh)
	if err != nil {
		return 0, err
	}
	if before.Type != 1 || !before.HasSize || !o.Extend && offset+length > before.Size {
		return 0, errors.New("block write must fit an existing regular file unless Extend is explicit")
	}
	var blockSize uint64
	if err := v.attrs(ctx, fh, []uint32{65}, func(_ uint32, d *decoder) { blockSize = uint64(d.u32()) }); err != nil {
		return 0, err
	}
	if blockSize == 0 || blockSize%blockSector != 0 || blockSize > 1<<20 {
		return 0, errors.New("block writes require an advertised 512-aligned block size of at most 1 MiB")
	}
	var journal *blockJournal
	if o.BlockJournal != "" {
		var buffered *blockBufferedInput
		journal, buffered, err = c.beginBlockRecovery(o, fh, offset, length, input, before, blockSize, func() error { return errors.Join(ctx.Err(), profile()) })
		if err != nil {
			return 0, err
		}
		defer func() { resultErr = errors.Join(resultErr, journal.file.Close(), buffered.Close()) }()
		input = buffered
		if o.BlockResume {
			recoveryGuard := func() error { return errors.Join(ctx.Err(), profile(), buffered.Check()) }
			if err = c.reconcileBlock(ctx, fh, o, journal, recoveryGuard); err != nil {
				return 0, err
			}
			if err = journal.append(blockJournalEvent{Kind: "resumed", Epoch: c.blockEpoch()}); err != nil {
				return 0, err
			}
			count = int64(journal.state.Progress)
			if progress != nil && count != 0 {
				progress(uint64(count))
				if err = recoveryGuard(); err != nil {
					return count, err
				}
			}
			before, err = c.GetAttr(ctx, fh)
			if err != nil {
				return count, err
			}
			if before.Type != 1 || !before.HasSize || before.Size != journal.state.CurrentSize {
				return count, errors.New("recovery EOF changed after verification")
			}
			if _, err = buffered.reader.Seek(count, io.SeekStart); err != nil {
				return count, err
			}
			offset += uint64(count)
			length -= uint64(count)
			if length == 0 {
				if journal.state.Phase != "completed" {
					if err = journal.append(blockJournalEvent{Kind: "completed"}); err != nil {
						return count, err
					}
				}
				return count, recoveryGuard()
			}
		}
		if min(offset, before.Size)/blockSize*blockSize != journal.state.NextBlock {
			return count, errors.New("block recovery cursor is inconsistent")
		}
	}
	end := offset + length
	rounded := end
	if remainder := end % blockSize; remainder != 0 {
		rounded += blockSize - remainder
	}
	if rounded > math.MaxInt64 {
		return 0, errors.New("aligned block write exceeds int64")
	}
	if err := v.blockLayoutHint(ctx, fh, sid); err != nil {
		return 0, err
	}
	layouts, err := v.getLayoutType(ctx, fh, sid, rounded, 2, 3)
	if err != nil {
		return 0, err
	}
	pending := false
	defer func() {
		changedIdentity := c.v4 != v || !sameNLMAuth(auth, c.Auth) || c.Identity() != identity
		if pending || changedIdentity {
			v.stateLost.Store(true)
			v.c.nfs.mu.Lock()
			v.c.nfs.closeLocked()
			v.c.nfs.mu.Unlock()
			if pending {
				resultErr = errors.Join(resultErr, errors.New("block mutation outcome is uncertain; original session quarantined, no replay"))
			}
			if changedIdentity {
				resultErr = errors.Join(resultErr, errors.New("block credentials changed; original session quarantined without cleanup under another identity"))
			}
		} else if !v.stateLost.Load() {
			resultErr = errors.Join(resultErr, v.returnLayout(fh))
		}
	}()
	guard := func(allowRecall bool) error {
		if source, ok := input.(interface{ Check() error }); ok {
			if err := source.Check(); err != nil {
				return err
			}
		}
		if err := errors.Join(ctx.Err(), profile()); err != nil {
			return err
		}
		if err := v.layoutStateUsable(fh, allowRecall); err != nil {
			return err
		}
		v.recall.mu.Lock()
		same := bytes.Equal(v.recall.fh, fh)
		v.recall.mu.Unlock()
		if !same {
			return errors.New("block layout file changed")
		}
		return nil
	}
	devices := map[string][]*blockVolume{}
	for _, l := range layouts {
		for _, e := range l.block {
			key := string(e.device)
			volumes := devices[key]
			if volumes == nil {
				if len(devices) == 64 {
					return 0, errors.New("block write exceeds 64 device topologies")
				}
				if err := guard(false); err != nil {
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
				return 0, errors.New("writable block extent exceeds approved volume")
			}
		}
	}
	if err := checkBlockWriteMapping(layouts, devices, blockSize); err != nil {
		return 0, err
	}
	buffer := make([]byte, blockSize)
	// Initialize the gap from the old EOF as well as the input range. Every
	// acknowledged gap block may grow the file even while input progress is zero.
	first := min(offset, before.Size)
	committedSize := before.Size
	for logical := first - first%blockSize; logical < rounded; logical += blockSize {
		if err := guard(false); err != nil {
			return count, err
		}
		layout, err := fileLayoutAt(layouts, logical)
		if err != nil {
			return count, err
		}
		var target *blockExtent
		for i := range layout.block {
			e := &layout.block[i]
			if e.state != 1 && logical >= e.offset && logical+blockSize <= min(e.offset+e.length, layout.offset+layout.length) {
				target = e
				break
			}
		}
		if target == nil {
			return count, errors.New("whole server block is outside writable grant")
		}
		clear(buffer)
		readExtent := func(e blockExtent) error {
			start, stop := max(logical, e.offset), min(logical+blockSize, e.offset+e.length, before.Size)
			volumes := devices[string(e.device)]
			for pos := start; pos < stop; {
				if err := guard(false); err != nil {
					return err
				}
				f, physical, left, err := blockPosition(volumes, len(volumes)-1, e.storage+pos-e.offset)
				if err != nil {
					return err
				}
				n := min(left, stop-pos)
				if _, err := f.ReadAt(buffer[pos-logical:pos-logical+n], int64(physical)); err != nil {
					return err
				}
				if err := guard(false); err != nil {
					return err
				}
				pos += n
			}
			return nil
		}
		if target.state == 0 {
			if err := readExtent(*target); err != nil {
				return count, err
			}
		} else {
			for _, e := range layout.block {
				if e.state == 1 {
					if err := readExtent(e); err != nil {
						return count, err
					}
				}
			}
		}
		preimage := sha256.Sum256(buffer)
		start, stop := max(logical, offset), min(logical+blockSize, end)
		accepted := uint64(0)
		if start < stop {
			if _, err := io.ReadFull(input, buffer[start-logical:stop-logical]); err != nil {
				return count, err
			}
			accepted = stop - start
		}
		if err := guard(false); err != nil {
			return count, err
		}
		if journal != nil {
			if err := journal.prepare(logical, preimage[:], buffer, accepted, max(committedSize, stop)); err != nil {
				return count, err
			}
		}
		volumes := devices[string(target.device)]
		changed := map[blockStorage]bool{}
		for pos := logical; pos < logical+blockSize; {
			if err := guard(false); err != nil {
				return count, err
			}
			f, physical, left, err := blockPosition(volumes, len(volumes)-1, target.storage+pos-target.offset)
			if err != nil {
				return count, err
			}
			limit := uint64(c.WriteSize)
			if remote, ok := f.(*iscsi.Volume); ok {
				sector := uint64(remote.SectorSize())
				limit = max(sector, limit-limit%sector)
			}
			n := min(left, logical+blockSize-pos, limit)
			if journal != nil && journal.state.Phase == "prepared" {
				if err := journal.append(blockJournalEvent{Kind: "write-issued"}); err != nil {
					return count, err
				}
			}
			pending = true
			written, err := f.WriteAt(buffer[pos-logical:pos-logical+n], int64(physical))
			if err != nil {
				return count, err
			}
			if uint64(written) != n {
				return count, io.ErrShortWrite
			}
			if err := files.acceptWrite(f); err != nil {
				return count, err
			}
			changed[f] = true
			pos += n
		}
		for f := range changed {
			if err := guard(true); err != nil {
				return count, err
			}
			if err := f.Sync(); err != nil {
				return count, err
			}
		}
		if err := guard(true); err != nil {
			return count, err
		}
		if journal != nil {
			if err := journal.append(blockJournalEvent{Kind: "storage-synced"}); err != nil {
				return count, err
			}
			if err := journal.append(blockJournalEvent{Kind: "commit-issued"}); err != nil {
				return count, err
			}
		}
		nextSize := max(committedSize, stop)
		if err := v.commitBlockWrite(ctx, fh, logical, blockSize, stop-1, *target, nextSize); err != nil {
			return count, err
		}
		pending = false
		if journal != nil {
			if err := journal.append(blockJournalEvent{Kind: "confirmed"}); err != nil {
				return count, err
			}
		}
		committedSize = nextSize
		count += int64(accepted)
		if progress != nil && accepted != 0 {
			progress(uint64(count))
		}
		if err := guard(false); err != nil {
			return count, err
		}
	}
	after, err := c.GetAttr(ctx, fh)
	if err != nil {
		return count, err
	}
	if after.Type != 1 || !after.HasSize || after.Size != max(before.Size, end) {
		return count, errors.New("block write completed but destination size changed")
	}
	if err := guard(false); err != nil {
		return count, err
	}
	if journal != nil {
		if err := journal.append(blockJournalEvent{Kind: "completed"}); err != nil {
			return count, err
		}
	}
	return count, nil
}
