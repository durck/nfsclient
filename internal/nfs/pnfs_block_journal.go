package nfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

const blockJournalMagic = "NFS-BLOCK-WAL-1\n"
const maxBlockRecoveryFile = 16 << 20
const maxBlockJournal = 64 << 20
const maxBlockFrame = 2 << 20

var ErrBlockPending = errors.New("block storage outcome is unverified; keep journal quarantined, no replay")

type blockJournalEvent struct {
	Sequence                                uint64
	Kind, ID, Profile, Epoch                string `json:",omitempty"`
	Handle                                  []byte `json:",omitempty"`
	Offset, Length, OriginalSize, BlockSize uint64 `json:",omitempty"`
	SourceHash                              string `json:",omitempty"`
	Extend                                  bool   `json:",omitempty"`
	BeforeHash, Data                        []byte `json:",omitempty"`
	Accepted, NextSize                      uint64 `json:",omitempty"`
}
type blockConfirmed struct {
	Offset uint64
	Hash   string
}
type blockJournalState struct {
	Version                          int    `json:",omitempty"`
	ConfirmedCount                   uint64 `json:",omitempty"`
	ConfirmedDigest                  string `json:",omitempty"`
	Intent                           blockJournalEvent
	Phase                            string
	Progress, CurrentSize, NextBlock uint64
	Prepared                         *blockJournalEvent
	Confirmed                        []blockConfirmed
}
type blockJournal struct {
	bank            int
	checkpointFault func(string) error
	file            *os.File
	size            int64
	sequence        uint64
	state           blockJournalState
}

func blockHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validBlockHash(h string) bool {
	b, e := hex.DecodeString(h)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == h
}

func applyBlockEvent(s blockJournalState, e blockJournalEvent) (blockJournalState, error) {
	bad := func() (blockJournalState, error) { return s, errors.New("invalid block journal transition or bounds") }
	if e.Kind == "begin" {
		limit := uint64(maxBlockRecoveryFile)
		if s.Version == 2 {
			limit = math.MaxInt64 - (1 << 20)
		}
		id, err := hex.DecodeString(e.ID)
		if s.Phase != "" && s.Phase != "completed" && s.Phase != "acknowledged-unknown" || err != nil || len(id) != 16 || hex.EncodeToString(id) != e.ID || e.ID == s.Intent.ID || e.Profile == "" || len(e.Profile) > 128 || e.Epoch == "" || len(e.Epoch) > 128 || len(e.Handle) == 0 || len(e.Handle) > 128 || !validBlockHash(e.SourceHash) || e.Length == 0 || e.Offset > limit || e.Length > limit-e.Offset || e.OriginalSize > limit || !e.Extend && e.Offset+e.Length > e.OriginalSize || e.BlockSize == 0 || e.BlockSize%512 != 0 || e.BlockSize > 1<<20 || len(e.BeforeHash) != 0 || len(e.Data) != 0 || e.Accepted != 0 || e.NextSize != 0 {
			return bad()
		}
		return blockJournalState{Version: s.Version, Intent: e, Phase: "ready", CurrentSize: e.OriginalSize, NextBlock: min(e.Offset, e.OriginalSize) / e.BlockSize * e.BlockSize}, nil
	}
	if s.Phase == "" {
		return bad()
	}
	if e.Kind == "resumed" {
		if s.Phase != "ready" && s.Phase != "completed" || e.Epoch == "" || e.Epoch == s.Intent.Epoch || len(e.Epoch) > 128 {
			return bad()
		}
		epoch := e.Epoch
		e.Epoch = ""
		if e.ID != "" || e.Profile != "" || len(e.Handle) != 0 || e.Offset != 0 || e.Length != 0 || e.OriginalSize != 0 || e.BlockSize != 0 || e.SourceHash != "" || e.Extend || len(e.BeforeHash) != 0 || len(e.Data) != 0 || e.Accepted != 0 || e.NextSize != 0 {
			return bad()
		}
		s.Intent.Epoch = epoch
		return s, nil
	}
	if e.ID != "" || e.Profile != "" || e.Epoch != "" || len(e.Handle) != 0 || e.Length != 0 || e.OriginalSize != 0 || e.BlockSize != 0 || e.SourceHash != "" || e.Extend {
		return bad()
	}
	if e.Kind == "prepared" {
		end := s.Intent.Offset + s.Intent.Length
		stop := min(e.Offset+s.Intent.BlockSize, end)
		start := max(e.Offset, s.Intent.Offset)
		if s.Phase != "ready" || e.Offset != s.NextBlock || e.Offset >= end || len(e.BeforeHash) != 32 || uint64(len(e.Data)) != s.Intent.BlockSize || e.Accepted != stop-min(start, stop) || e.NextSize != max(s.CurrentSize, stop) {
			return bad()
		}
		p := e
		p.Data = bytes.Clone(e.Data)
		p.BeforeHash = bytes.Clone(e.BeforeHash)
		s.Prepared = &p
		s.Phase = "prepared"
		return s, nil
	}
	if e.Offset != 0 || e.Accepted != 0 || e.NextSize != 0 || len(e.BeforeHash) != 0 || len(e.Data) != 0 {
		return bad()
	}
	switch e.Kind {
	case "write-issued":
		if s.Phase != "prepared" {
			return bad()
		}
		s.Phase = e.Kind
	case "storage-synced":
		if s.Phase != "write-issued" {
			return bad()
		}
		s.Phase = e.Kind
	case "commit-issued":
		if s.Phase != "storage-synced" {
			return bad()
		}
		s.Phase = e.Kind
	case "confirmed":
		if s.Phase != "commit-issued" && s.Phase != "storage-synced" {
			return bad()
		}
		if s.Version == 2 {
			s.ConfirmedDigest = chainBlockHash(s.ConfirmedDigest, s.Prepared.Offset, s.Prepared.Data)
			s.ConfirmedCount++
		} else {
			s.Confirmed = append(s.Confirmed, blockConfirmed{s.Prepared.Offset, blockHash(s.Prepared.Data)})
		}
		s.Progress += s.Prepared.Accepted
		s.CurrentSize = s.Prepared.NextSize
		s.NextBlock = s.Prepared.Offset + s.Intent.BlockSize
		s.Prepared = nil
		s.Phase = "ready"
	case "restart-prepared":
		if s.Phase != "prepared" && s.Phase != "storage-synced" && s.Phase != "commit-issued" {
			return bad()
		}
		s.Prepared = nil
		s.Phase = "ready"
	case "completed":
		if s.Phase != "ready" || s.Progress != s.Intent.Length || s.CurrentSize != max(s.Intent.OriginalSize, s.Intent.Offset+s.Intent.Length) || s.NextBlock < s.Intent.Offset+s.Intent.Length {
			return bad()
		}
		s.Phase = e.Kind
	case "acknowledged-unknown":
		if s.Phase == "completed" || s.Phase == "acknowledged-unknown" {
			return bad()
		}
		s.Phase = e.Kind
	default:
		return bad()
	}
	return s, nil
}

func loadBlockJournal(path string, create bool, streaming ...bool) (_ *blockJournal, resultErr error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("block journal path must be absolute")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("block journal parent must be an existing real directory")
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	created := create && err == nil
	if create && errors.Is(err, os.ErrExist) {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() {
			return nil, errors.New("block journal must be a regular file")
		}
		f, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			f.Close()
		}
	}()
	if err = lockNSMFile(f); err != nil {
		return nil, fmt.Errorf("block journal belongs to another process: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() > maxBlockJournal {
		return nil, errors.New("substituted or oversized block journal")
	}
	j := &blockJournal{file: f, size: info.Size()}
	if created && len(streaming) > 0 && streaming[0] {
		if err := j.initializeBlockCheckpoints(); err != nil {
			return nil, err
		}
		return j, nil
	}
	if created {
		n, e := f.WriteString(blockJournalMagic)
		if e != nil {
			return nil, e
		}
		if n != len(blockJournalMagic) {
			return nil, io.ErrShortWrite
		}
		if e = f.Sync(); e != nil {
			return nil, e
		}
		j.size = int64(n)
		return j, nil
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBlockJournal+1))
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(b, []byte(blockCheckpointMagic)) {
		if err := j.loadBlockCheckpoints(b); err != nil {
			return nil, err
		}
		return j, nil
	}
	if !bytes.HasPrefix(b, []byte(blockJournalMagic)) {
		return nil, errors.New("invalid/empty block journal; keep quarantined")
	}
	b = b[len(blockJournalMagic):]
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("truncated block journal header")
		}
		n := int(binary.BigEndian.Uint32(b))
		b = b[4:]
		if n < 1 || n > maxBlockFrame || len(b) < n+32 {
			return nil, errors.New("truncated/oversized block journal frame")
		}
		h := sha256.Sum256(b[:n])
		if !bytes.Equal(h[:], b[n:n+32]) {
			return nil, errors.New("block journal checksum mismatch")
		}
		d := json.NewDecoder(bytes.NewReader(b[:n]))
		d.DisallowUnknownFields()
		var e blockJournalEvent
		if err = d.Decode(&e); err != nil {
			return nil, err
		}
		if d.Decode(new(any)) != io.EOF || e.Sequence != j.sequence+1 {
			return nil, errors.New("block journal sequence or trailing JSON mismatch")
		}
		s, err := applyBlockEvent(j.state, e)
		if err != nil {
			return nil, err
		}
		j.state = s
		j.sequence = e.Sequence
		b = b[n+32:]
	}
	return j, nil
}

func (j *blockJournal) append(e blockJournalEvent) error {
	if j.sequence == ^uint64(0) {
		return errors.New("block journal sequence exhausted; no mutation may issue")
	}
	e.Sequence = j.sequence + 1
	next, err := applyBlockEvent(j.state, e)
	if err != nil {
		return err
	}
	if j.state.Version == 2 {
		return j.appendBlockCheckpoint(e, next)
	}
	info, err := j.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(j.file.Name())
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() != j.size {
		return errors.New("block journal changed externally")
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > maxBlockFrame || j.size+int64(4+len(b)+32) > maxBlockJournal {
		return errors.New("block journal full; no further mutation may issue")
	}
	h := sha256.Sum256(b)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	frame = append(frame, b...)
	frame = append(frame, h[:]...)
	if _, err = j.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	n, err := j.file.Write(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	if err = j.file.Sync(); err != nil {
		return err
	}
	j.state = next
	j.sequence = e.Sequence
	j.size += int64(len(frame))
	return nil
}
func (j *blockJournal) prepare(offset uint64, pre, data []byte, accepted, size uint64) error {
	return j.append(blockJournalEvent{Kind: "prepared", Offset: offset, BeforeHash: pre, Data: data, Accepted: accepted, NextSize: size})
}

// BlockJournalInfo omits cached block contents. No saved layout or stateid is
// accepted as authorization for a recovery operation.
type BlockJournalInfo struct {
	ID, Phase, Profile                               string
	Offset, Length, Progress, CurrentSize, NextBlock uint64
	PendingOffset                                    *uint64 `json:",omitempty"`
	ConfirmedBlocks                                  uint64
}

func InspectBlockJournal(path string) (BlockJournalInfo, error) {
	j, err := loadBlockJournal(path, false)
	if err != nil {
		return BlockJournalInfo{}, err
	}
	defer j.file.Close()
	s := j.state
	i := BlockJournalInfo{s.Intent.ID, s.Phase, s.Intent.Profile, s.Intent.Offset, s.Intent.Length, s.Progress, s.CurrentSize, s.NextBlock, nil, uint64(len(s.Confirmed))}
	if s.Version == 2 {
		i.ConfirmedBlocks = s.ConfirmedCount
	}
	if s.Prepared != nil {
		off := s.Prepared.Offset
		i.PendingOffset = &off
	}
	return i, nil
}
func AcknowledgeBlockJournal(path, id string) error {
	j, err := loadBlockJournal(path, false)
	if err != nil {
		return err
	}
	defer j.file.Close()
	if j.state.Intent.ID != id || id == "" {
		return errors.New("ack must identify the pending block operation")
	}
	return j.append(blockJournalEvent{Kind: "acknowledged-unknown"})
}
