package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"nfsclient/internal/iscsi"
	"os"
)

func checkBlockJournalAliases(o PNFSOptions, input io.Reader) error {
	info, err := os.Lstat(o.BlockJournal)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("block journal must be a regular file")
	}
	for _, path := range o.BlockVolumes {
		volume, e := os.Stat(path)
		if e != nil {
			return e
		}
		if os.SameFile(info, volume) {
			return errors.New("block journal aliases a volume image")
		}
	}
	if source, ok := input.(interface{ Stat() (os.FileInfo, error) }); ok {
		src, e := source.Stat()
		if e != nil {
			return e
		}
		if os.SameFile(info, src) {
			return errors.New("block journal aliases upload source")
		}
	}
	return nil
}
func validateBlockJournalGate(o PNFSOptions) error {
	if o.BlockJournal == "" {
		return nil
	}
	if err := checkBlockJournalAliases(o, nil); err != nil {
		return err
	}
	j, err := loadBlockJournal(o.BlockJournal, !o.BlockResume, true)
	if err != nil {
		return err
	}
	defer j.file.Close()
	if o.BlockResume {
		if j.state.Phase == "" || j.state.Phase == "acknowledged-unknown" {
			return errors.New("no resumable block operation")
		}
		return nil
	}
	if j.state.Phase != "" && j.state.Phase != "completed" && j.state.Phase != "acknowledged-unknown" {
		return ErrBlockPending
	}
	return nil
}

func (c *Client) blockRecoveryProfile(o PNFSOptions) string {
	b, _ := json.Marshal(struct {
		Security        map[string]iscsi.Security
		MDS             string
		Images, Targets []string
		Initiator       string
		Geometry        string
	}{o.BlockSecurity, c.offloadProfile(), o.BlockVolumes, o.BlockTargets, o.BlockInitiator, o.blockGeometry})
	return blockHash(b)
}
func (c *Client) blockEpoch() string {
	b, _ := json.Marshal(struct {
		Nonce, Session []byte
		Client         uint64
	}{c.v4.clientNonce, c.v4.session, c.v4.clientID})
	return blockHash(b)
}

type blockBufferedInput struct {
	reader   *os.File
	original io.Reader
	guards   []func() error
}

func (r *blockBufferedInput) Close() error { return r.reader.Close() }
func (r *blockBufferedInput) Check() error {
	for _, guard := range r.guards {
		if err := guard(); err != nil {
			return err
		}
	}
	if g, ok := r.original.(interface{ Check() error }); ok {
		return g.Check()
	}
	return nil
}
func (r *blockBufferedInput) Read(p []byte) (int, error) {
	if err := r.Check(); err != nil {
		return 0, err
	}
	n, e := r.reader.Read(p)
	if err := r.Check(); err != nil {
		return n, errors.Join(e, err)
	}
	return n, e
}

func (c *Client) beginBlockRecovery(o PNFSOptions, fh []byte, offset, length uint64, input io.Reader, before Attr, blockSize uint64, guards ...func() error) (*blockJournal, *blockBufferedInput, error) {
	if before.Size > math.MaxInt64-(1<<20) || offset > math.MaxInt64-(1<<20) || length > math.MaxInt64-(1<<20)-offset {
		return nil, nil, errors.New("block recovery destination/range exceeds aligned int64 bounds")
	}
	if len(c.v4.clientNonce) != 16 {
		return nil, nil, errors.New("block recovery needs an identified NFS client incarnation")
	}
	if err := checkBlockJournalAliases(o, input); err != nil {
		return nil, nil, err
	}
	j, err := loadBlockJournal(o.BlockJournal, !o.BlockResume, true)
	if err != nil {
		return nil, nil, err
	}
	var buffered *blockBufferedInput
	fail := func(err error) (*blockJournal, *blockBufferedInput, error) {
		j.file.Close()
		if buffered != nil {
			buffered.Close()
		}
		return nil, nil, err
	}
	if j.state.Version != 2 {
		return fail(errors.New("legacy version-1 block journal cannot resume or start streaming recovery; resolve or acknowledge the old intent, then use a fresh journal path"))
	}
	if !o.BlockResume && j.state.Phase != "" && j.state.Phase != "completed" && j.state.Phase != "acknowledged-unknown" {
		return fail(ErrBlockPending)
	}
	spool, err := newBlockSpool()
	if err != nil {
		return fail(err)
	}
	buffered = &blockBufferedInput{reader: spool, original: input, guards: guards}
	digest := sha256.New()
	chunk := make([]byte, 64<<10)
	for remaining := length; remaining > 0; {
		if err = buffered.Check(); err != nil {
			return fail(err)
		}
		part := chunk[:min(uint64(len(chunk)), remaining)]
		if _, err = io.ReadFull(input, part); err != nil {
			return fail(err)
		}
		if err = buffered.Check(); err != nil {
			return fail(err)
		}
		if _, err = spool.Write(part); err != nil {
			return fail(err)
		}
		if err = buffered.Check(); err != nil {
			return fail(err)
		}
		digest.Write(part)
		remaining -= uint64(len(part))
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	sourceHash := hex.EncodeToString(digest.Sum(nil))
	if err = buffered.Check(); err != nil {
		return fail(err)
	}
	if o.BlockResume {
		i := j.state.Intent
		if j.state.Phase == "" || j.state.Phase == "acknowledged-unknown" || i.Profile != c.blockRecoveryProfile(o) || !bytes.Equal(i.Handle, fh) || i.Offset != offset || i.Length != length || i.Extend != o.Extend || i.SourceHash != sourceHash || i.BlockSize != blockSize {
			return fail(errors.New("block recovery intent, source, geometry or profile changed"))
		}
		if i.Epoch == c.blockEpoch() {
			return fail(errors.New("block recovery requires a fresh NFS client and a newly acquired whole-file lock"))
		}
	} else {
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return fail(err)
		}
		if err = buffered.Check(); err != nil {
			return fail(err)
		}
		err = j.append(blockJournalEvent{Kind: "begin", ID: hex.EncodeToString(id[:]), Profile: c.blockRecoveryProfile(o), Epoch: c.blockEpoch(), Handle: bytes.Clone(fh), Offset: offset, Length: length, SourceHash: sourceHash, OriginalSize: before.Size, BlockSize: blockSize, Extend: o.Extend})
		if err != nil {
			return fail(err)
		}
	}
	return j, buffered, nil
}

func stableBlockAttrs(a, b Attr) bool {
	if a.Type != 1 || b.Type != 1 || !a.HasSize || !b.HasSize || a.Size != b.Size {
		return false
	}
	if a.HasChange {
		return b.HasChange && a.Change == b.Change
	}
	return a.HasCTime && b.HasCTime && a.CTime.Equal(b.CTime) && a.HasMTime && b.HasMTime && a.MTime.Equal(b.MTime)
}

// Reconciliation uses only newly granted READ extents, never saved INVALID
// storage locations. A confirmed Sync bounds old storage I/O; an uncertain
// storage command cannot be resolved merely by observing a matching read.
func (c *Client) reconcileBlock(ctx context.Context, fh []byte, o PNFSOptions, j *blockJournal, guard func() error) error {
	s := j.state
	if s.Phase == "write-issued" {
		return ErrBlockPending
	}
	if err := guard(); err != nil {
		return err
	}
	before, err := c.GetAttr(ctx, fh)
	if err != nil {
		return err
	}
	if !before.HasSize || before.Size > math.MaxInt64 || !before.HasChange && !(before.HasCTime && before.HasMTime) {
		return errors.New("block recovery requires observable destination attributes within int64")
	}
	visible := newBlockRecoveryVerifier(s)
	readOptions := o
	readOptions.BlockWrite = false
	readOptions.Extend = false
	readOptions.BlockJournal = ""
	readOptions.BlockResume = false
	_, err = c.ReadPNFSToProgressVerified(ctx, fh, before.Size, visible, readOptions, func(uint64) {}, func() error {
		after, e := c.GetAttr(ctx, fh)
		if e != nil {
			return e
		}
		if !stableBlockAttrs(before, after) {
			return errors.New("block recovery destination changed during verification")
		}
		return guard()
	})
	if err != nil {
		return err
	}
	if err = guard(); err != nil {
		return err
	}
	if err = visible.finish(before.Size); err != nil {
		return err
	}
	if s.Prepared == nil {
		if before.Size != s.CurrentSize {
			return errors.New("block recovery EOF changed")
		}
		return nil
	}
	p := s.Prepared
	current := visible.pending
	if s.Phase != "prepared" && before.Size == p.NextSize && bytes.Equal(current, p.Data) {
		return j.append(blockJournalEvent{Kind: "confirmed"})
	}
	if before.Size == s.CurrentSize && blockHash(current) == hex.EncodeToString(p.BeforeHash) {
		return j.append(blockJournalEvent{Kind: "restart-prepared"})
	}
	return errors.New("pending block is neither its saved preimage nor postimage; recovery refused")
}
