package nfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
)

// Version 2 checkpoints retain the preceding state and its next transition.
// Only the inactive bank is overwritten. A zero footer means an interrupted
// write; any malformed committed footer/body is quarantined, never ignored.
const blockCheckpointMagic = "NFS-BLOCK-CP-2\n"
const blockCheckpointPayload = 2 << 20
const blockCheckpointFooter = 48
const blockCheckpointBank = 4 + blockCheckpointPayload + blockCheckpointFooter
const blockCheckpointSize = len(blockCheckpointMagic) + 2*blockCheckpointBank

type blockCheckpoint struct {
	PreviousSequence uint64
	Previous         blockJournalState
	Event            blockJournalEvent
}

func chainBlockHash(previous string, offset uint64, data []byte) string {
	h := sha256.New()
	// Domain separation and a fixed initial digest make boundaries unambiguous.
	h.Write([]byte("NFS-BLOCK-CONFIRMED-2"))
	prior, _ := hex.DecodeString(previous)
	if len(prior) == 0 {
		prior = make([]byte, sha256.Size)
	}
	h.Write(prior)
	h.Write(binary.BigEndian.AppendUint64(nil, offset))
	sum := sha256.Sum256(data)
	h.Write(sum[:])
	return hex.EncodeToString(h.Sum(nil))
}

func validateBlockSnapshot(s blockJournalState) error {
	bad := errors.New("invalid block checkpoint state")
	if s.Version != 2 || len(s.Confirmed) != 0 {
		return bad
	}
	if s.Phase == "" {
		if !reflect.DeepEqual(s, blockJournalState{Version: 2}) {
			return bad
		}
		return nil
	}
	base, err := applyBlockEvent(blockJournalState{Version: 2}, s.Intent)
	if err != nil || s.Intent.Kind != "begin" || s.Intent.Sequence == 0 {
		return bad
	}
	start := base.NextBlock
	end := s.Intent.Offset + s.Intent.Length
	rounded := (end + s.Intent.BlockSize - 1) / s.Intent.BlockSize * s.Intent.BlockSize
	if s.NextBlock < start || s.NextBlock > rounded || (s.NextBlock-start)%s.Intent.BlockSize != 0 || s.ConfirmedCount != (s.NextBlock-start)/s.Intent.BlockSize {
		return bad
	}
	if s.ConfirmedCount == 0 && s.ConfirmedDigest != "" || s.ConfirmedCount > 0 && !validBlockHash(s.ConfirmedDigest) {
		return bad
	}
	stop := min(s.NextBlock, end)
	progress := uint64(0)
	if stop > s.Intent.Offset {
		progress = stop - s.Intent.Offset
	}
	size := s.Intent.OriginalSize
	if s.ConfirmedCount > 0 {
		size = max(size, stop)
	}
	if s.Progress != progress || s.CurrentSize != size {
		return bad
	}
	switch s.Phase {
	case "ready", "completed":
		if s.Prepared != nil {
			return bad
		}
		if s.Phase == "completed" {
			check := s
			check.Phase = "ready"
			if _, err := applyBlockEvent(check, blockJournalEvent{Kind: "completed"}); err != nil {
				return bad
			}
		}
	case "prepared", "write-issued", "storage-synced", "commit-issued":
		if s.Prepared == nil {
			return bad
		}
		check := s
		check.Phase = "ready"
		check.Prepared = nil
		if _, err := applyBlockEvent(check, *s.Prepared); err != nil || s.Prepared.Kind != "prepared" || s.Prepared.Sequence <= s.Intent.Sequence {
			return bad
		}
	case "acknowledged-unknown":
		if s.Prepared != nil {
			check := s
			check.Phase = "ready"
			check.Prepared = nil
			if _, err := applyBlockEvent(check, *s.Prepared); err != nil {
				return bad
			}
		}
	default:
		return bad
	}
	return nil
}

func (j *blockJournal) initializeBlockCheckpoints() error {
	if err := j.file.Truncate(int64(blockCheckpointSize)); err != nil {
		return err
	}
	if _, err := j.file.WriteAt([]byte(blockCheckpointMagic), 0); err != nil {
		return err
	}
	if err := j.file.Sync(); err != nil {
		return err
	}
	j.bank = -1
	j.size = int64(blockCheckpointSize)
	j.state = blockJournalState{Version: 2}
	return nil
}

func decodeBlockCheckpoint(bank []byte) (blockCheckpoint, blockJournalState, bool, error) {
	var cp blockCheckpoint
	var s blockJournalState
	footer := bank[len(bank)-blockCheckpointFooter:]
	if bytes.Equal(footer, make([]byte, blockCheckpointFooter)) {
		return cp, s, false, nil
	}
	if string(footer[:8]) != "NFSBCEND" {
		return cp, s, false, errors.New("invalid block checkpoint commit marker")
	}
	n := int(binary.BigEndian.Uint32(bank))
	if n < 1 || n > blockCheckpointPayload {
		return cp, s, false, errors.New("invalid block checkpoint bounds")
	}
	body := bank[4 : 4+n]
	digest := sha256.Sum256(body)
	if !bytes.Equal(digest[:], footer[16:]) {
		return cp, s, false, errors.New("committed block checkpoint checksum mismatch")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&cp); err != nil {
		return cp, s, false, err
	}
	if d.Decode(new(any)) != io.EOF || cp.Event.Sequence == 0 || cp.Event.Sequence != binary.BigEndian.Uint64(footer[8:16]) {
		return cp, s, false, errors.New("block checkpoint generation or JSON mismatch")
	}
	if err := validateBlockSnapshot(cp.Previous); err != nil {
		return cp, s, false, err
	}
	if cp.Event.Sequence != cp.PreviousSequence+1 || cp.Previous.Intent.Sequence > cp.PreviousSequence || cp.Previous.Phase == "" && cp.PreviousSequence != 0 || cp.Previous.Prepared != nil && cp.Previous.Prepared.Sequence > cp.PreviousSequence {
		return cp, s, false, errors.New("block checkpoint predecessor generation mismatch")
	}
	var err error
	s, err = applyBlockEvent(cp.Previous, cp.Event)
	if err == nil {
		err = validateBlockSnapshot(s)
	}
	return cp, s, err == nil, err
}

func (j *blockJournal) loadBlockCheckpoints(data []byte) error {
	if len(data) != blockCheckpointSize {
		return errors.New("truncated or extended block checkpoint")
	}
	var cps [2]blockCheckpoint
	var states [2]blockJournalState
	var valid [2]bool
	for i := range 2 {
		start := len(blockCheckpointMagic) + i*blockCheckpointBank
		var err error
		cps[i], states[i], valid[i], err = decodeBlockCheckpoint(data[start : start+blockCheckpointBank])
		if err != nil {
			return err
		}
	}
	if !valid[0] && !valid[1] {
		// Only the pristine, zero-filled initial file is an empty journal.
		for _, b := range data[len(blockCheckpointMagic):] {
			if b != 0 {
				return errors.New("block checkpoint has no committed evidence")
			}
		}
		j.bank = -1
		j.state = blockJournalState{Version: 2}
		return nil
	}
	active := 0
	if !valid[0] || valid[1] && cps[1].Event.Sequence > cps[0].Event.Sequence {
		active = 1
	}
	if valid[0] && valid[1] && (cps[active].Event.Sequence != cps[1-active].Event.Sequence+1 || !reflect.DeepEqual(cps[active].Previous, states[1-active])) {
		return errors.New("block checkpoint lineage mismatch")
	}
	j.state = states[active]
	j.sequence = cps[active].Event.Sequence
	j.bank = active
	return nil
}

func (j *blockJournal) blockCheckpointStep(stage string) error {
	if j.checkpointFault != nil {
		return j.checkpointFault(stage)
	}
	return nil
}

func (j *blockJournal) appendBlockCheckpoint(e blockJournalEvent, next blockJournalState) error {
	if err := validateBlockSnapshot(next); err != nil {
		return err
	}
	info, err := j.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(j.file.Name())
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() != int64(blockCheckpointSize) {
		return errors.New("block checkpoint changed externally")
	}
	body, err := json.Marshal(blockCheckpoint{PreviousSequence: j.sequence, Previous: j.state, Event: e})
	if err != nil {
		return err
	}
	if len(body) > blockCheckpointPayload {
		return errors.New("block checkpoint exceeds fixed capacity; mutation refused")
	}
	if err = j.blockCheckpointStep("before-write"); err != nil {
		return err
	}
	bank := 1 - j.bank
	if j.bank < 0 {
		bank = 0
	}
	start := int64(len(blockCheckpointMagic) + bank*blockCheckpointBank)
	footerOffset := start + 4 + blockCheckpointPayload
	if _, err = j.file.WriteAt(make([]byte, blockCheckpointFooter), footerOffset); err != nil {
		return err
	}
	if err = j.file.Sync(); err != nil {
		return err
	}
	if err = j.blockCheckpointStep("invalidated"); err != nil {
		return err
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	split := len(frame) / 2
	if _, err = j.file.WriteAt(frame[:split], start); err != nil {
		return err
	}
	if err = j.blockCheckpointStep("partial-body"); err != nil {
		return err
	}
	if _, err = j.file.WriteAt(frame[split:], start+int64(split)); err != nil {
		return err
	}
	if err = j.file.Sync(); err != nil {
		return err
	}
	if err = j.blockCheckpointStep("body-synced"); err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	footer := append([]byte("NFSBCEND"), binary.BigEndian.AppendUint64(nil, e.Sequence)...)
	footer = append(footer, digest[:]...)
	if _, err = j.file.WriteAt(footer, footerOffset); err != nil {
		return err
	}
	if err = j.file.Sync(); err != nil {
		return err
	}
	if err = j.blockCheckpointStep("committed"); err != nil {
		return err
	}
	j.state = next
	j.sequence = e.Sequence
	j.bank = bank
	return nil
}
