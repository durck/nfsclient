package nfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
)

// Fixed banks retain both sides of the latest validated transition. The locked
// inode is never renamed/truncated after initialization. A commit footer is
// invalidated and synced before reusing the inactive bank; only an exact zero
// footer is an interrupted write, while malformed committed data is quarantined.
const offloadCheckpointMagic = "NFS-OFFLOAD-CP1\n\x00"
const offloadCheckpointPayload = 2*65536 + 128
const offloadCheckpointFooter = 48
const offloadCheckpointBank = 4 + offloadCheckpointPayload + offloadCheckpointFooter
const offloadCheckpointSize = len(offloadCheckpointMagic) + 2*offloadCheckpointBank

type offloadCheckpoint struct{ Previous, Record OffloadRecord }

func (j *offloadJournal) initializeCheckpoints() error {
	if err := j.file.Truncate(int64(offloadCheckpointSize)); err != nil {
		return err
	}
	if _, err := j.file.WriteAt([]byte(offloadCheckpointMagic), 0); err != nil {
		return err
	}
	if err := j.file.Sync(); err != nil {
		return err
	}
	j.checkpoint, j.bank, j.size = true, -1, int64(offloadCheckpointSize)
	return nil
}

// Validate an independently stored predecessor without inventing an earlier
// network result. Its full structural constraints still apply; the following
// Record must pass the ordinary transition validator against it.
func validateOffloadSnapshot(r OffloadRecord) error {
	if r.Sequence == 0 {
		return errors.New("checkpoint has no predecessor generation")
	}
	if r.Sequence == 1 {
		return validateOffloadRecord(r, OffloadRecord{})
	}
	previous := r
	previous.Sequence--
	previous.Pending = true
	return validateOffloadRecord(r, previous)
}

func decodeOffloadCheckpoint(bank []byte) (offloadCheckpoint, bool, error) {
	var out offloadCheckpoint
	footer := bank[len(bank)-offloadCheckpointFooter:]
	if bytes.Equal(footer, make([]byte, offloadCheckpointFooter)) {
		return out, false, nil
	}
	if string(footer[:8]) != "NFSCPEND" {
		return out, false, errors.New("invalid offload checkpoint commit marker")
	}
	n := int(binary.BigEndian.Uint32(bank))
	if n == 0 || n > offloadCheckpointPayload {
		return out, false, errors.New("invalid offload checkpoint bounds")
	}
	body := bank[4 : 4+n]
	digest := sha256.Sum256(body)
	if !bytes.Equal(digest[:], footer[16:]) {
		return out, false, errors.New("committed offload checkpoint checksum mismatch")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return out, false, err
	}
	if d.Decode(new(any)) != io.EOF {
		return out, false, errors.New("trailing checkpoint JSON")
	}
	if out.Record.Sequence != binary.BigEndian.Uint64(footer[8:16]) {
		return out, false, errors.New("checkpoint generation mismatch")
	}
	if out.Previous.Sequence != 0 {
		if err := validateOffloadSnapshot(out.Previous); err != nil {
			return out, false, err
		}
	}
	if err := validateOffloadRecord(out.Record, out.Previous); err != nil {
		return out, false, err
	}
	return out, true, nil
}

func (j *offloadJournal) loadCheckpoints(data []byte) error {
	if len(data) != offloadCheckpointSize {
		return errors.New("truncated or extended offload checkpoint file")
	}
	var snapshots [2]offloadCheckpoint
	var valid [2]bool
	for i := range 2 {
		start := len(offloadCheckpointMagic) + i*offloadCheckpointBank
		var err error
		snapshots[i], valid[i], err = decodeOffloadCheckpoint(data[start : start+offloadCheckpointBank])
		if err != nil {
			return err
		}
	}
	if !valid[0] && !valid[1] {
		return errors.New("offload checkpoint has no committed evidence")
	}
	active := 0
	if !valid[0] || valid[1] && snapshots[1].Record.Sequence > snapshots[0].Record.Sequence {
		active = 1
	}
	if valid[0] && valid[1] {
		if snapshots[0].Record.Sequence == snapshots[1].Record.Sequence || !reflect.DeepEqual(snapshots[active].Previous, snapshots[1-active].Record) {
			return errors.New("offload checkpoint lineage mismatch")
		}
	}
	j.record, j.bank, j.checkpoint = snapshots[active].Record, active, true
	return nil
}

func (j *offloadJournal) checkpointStep(stage string) error {
	if j.checkpointFault != nil {
		return j.checkpointFault(stage)
	}
	return nil
}

func (j *offloadJournal) appendCheckpoint(r OffloadRecord) error {
	info, err := j.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(j.file.Name())
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() != int64(offloadCheckpointSize) {
		return errors.New("offload checkpoint changed externally")
	}
	recordBody, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(recordBody) > 65536 {
		return errors.New("offload checkpoint record exceeds its bound; request refused")
	}
	body, err := json.Marshal(offloadCheckpoint{Previous: j.record, Record: r})
	if err != nil {
		return err
	}
	if len(body) > offloadCheckpointPayload {
		return errors.New("offload checkpoint transition exceeds its bound; request refused")
	}
	if err := j.checkpointStep("before-write"); err != nil {
		return err
	}
	bank := 1 - j.bank
	if j.bank < 0 {
		bank = 0
	}
	start := int64(len(offloadCheckpointMagic) + bank*offloadCheckpointBank)
	footerOffset := start + 4 + offloadCheckpointPayload
	if _, err := j.file.WriteAt(make([]byte, offloadCheckpointFooter), footerOffset); err != nil {
		return err
	}
	if err := j.file.Sync(); err != nil {
		return err
	}
	if err := j.checkpointStep("invalidated"); err != nil {
		return err
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	split := len(frame) / 2
	if _, err := j.file.WriteAt(frame[:split], start); err != nil {
		return err
	}
	if err := j.checkpointStep("partial-body"); err != nil {
		return err
	}
	if _, err := j.file.WriteAt(frame[split:], start+int64(split)); err != nil {
		return err
	}
	if err := j.checkpointStep("before-body-sync"); err != nil {
		return err
	}
	if err := j.file.Sync(); err != nil {
		return err
	}
	if err := j.checkpointStep("body-synced"); err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	footer := append([]byte("NFSCPEND"), binary.BigEndian.AppendUint64(nil, r.Sequence)...)
	footer = append(footer, digest[:]...)
	if _, err := j.file.WriteAt(footer, footerOffset); err != nil {
		return err
	}
	if err := j.checkpointStep("before-commit-sync"); err != nil {
		return err
	}
	if err := j.file.Sync(); err != nil {
		return err
	}
	if err := j.checkpointStep("committed"); err != nil {
		return err
	}
	j.record, j.bank = r, bank
	return nil
}
