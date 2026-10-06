package nfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

const maxNSMJournal = 8 << 20

type nsmSavedLock struct {
	Version   uint32
	Info      LockInfo
	FH, Owner []byte
	SVID      uint32
	Auth      Auth
	Confirmed bool
}

type nsmRecord struct {
	Version            int
	Address, Peer      string
	State              uint32
	Dirty              bool
	LastSVID           uint32
	NotifyEpoch        uint32         `json:",omitempty"`
	NotifyAcknowledged bool           `json:",omitempty"`
	Locks              []nsmSavedLock `json:",omitempty"`
}

type nsmState struct {
	file   *os.File
	record nsmRecord
	size   int64
}

// The journal is append-only and synced before sending LOCK. Partial records,
// missing established state and unclean sessions are never silently repaired.
// Confirmed owners support explicit cleanup; unknown acquisition outcomes remain
// quarantined because an earlier LOCK may still be executing remotely.
func openNSMState(dir, address, peer string) (_ *nsmState, err error) {
	return openNSMStateMode(dir, address, peer, false)
}

func openNSMStateMode(dir, address, peer string, recoverLocks bool) (_ *nsmState, err error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("NSM state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("NSM state directory must be a real directory")
	}
	name := filepath.Join(dir, "nsm-state")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		info, err = os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("NSM state must be a regular file")
		}
		f, err = os.OpenFile(name, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	if err = lockNSMFile(f); err != nil {
		return nil, fmt.Errorf("NSM state is owned by another process: %w", err)
	}
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(name)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(opened, named) {
		return nil, errors.New("NSM state file changed while opening")
	}
	if opened.Size() > maxNSMJournal {
		return nil, errors.New("NSM state journal exceeds its size limit")
	}
	s := &nsmState{file: f, size: opened.Size()}
	if created {
		s.record = nsmRecord{Version: 2, Address: address, Peer: peer, State: 1}
	} else {
		data, readErr := io.ReadAll(io.LimitReader(f, maxNSMJournal+1))
		if readErr != nil {
			return nil, readErr
		}
		if len(data) == 0 {
			return nil, errors.New("empty existing NSM state; recovery required")
		}
		var previous nsmRecord
		for len(data) > 0 {
			if len(data) < 4 {
				return nil, errors.New("truncated NSM state header")
			}
			n := int(binary.BigEndian.Uint32(data))
			data = data[4:]
			if n < 1 || n > 65536 || len(data) < n+sha256.Size {
				return nil, errors.New("invalid NSM state record length")
			}
			hash := sha256.Sum256(data[:n])
			if !bytes.Equal(hash[:], data[n:n+sha256.Size]) {
				return nil, errors.New("NSM state checksum mismatch")
			}
			d := json.NewDecoder(bytes.NewReader(data[:n]))
			d.DisallowUnknownFields()
			s.record = nsmRecord{}
			if err := d.Decode(&s.record); err != nil {
				return nil, err
			}
			if d.Decode(new(any)) != io.EOF {
				return nil, errors.New("trailing NSM JSON data")
			}
			data = data[n+sha256.Size:]
			r := s.record
			if (r.Version != 1 && r.Version != 2) || r.Address != address || r.Peer != peer || r.State == 0 || r.State > math.MaxInt32 || r.State%2 != 1 {
				return nil, errors.New("NSM state profile or epoch mismatch")
			}
			if err := validateSavedNLMLocks(r); err != nil {
				return nil, err
			}
			if r.LastSVID < previous.LastSVID {
				return nil, errors.New("NSM process identity counter regressed")
			}
			if previous.State != 0 && (r.State != previous.State && (r.State != previous.State+2 || previous.Dirty || r.Dirty)) {
				return nil, errors.New("invalid NSM state transition")
			}
			if previous.NotifyEpoch != 0 && r.NotifyEpoch != previous.NotifyEpoch {
				return nil, errors.New("NSM notification epoch changed or cleared without a server cleanup barrier; journal remains quarantined")
			}
			if previous.NotifyAcknowledged && !r.NotifyAcknowledged {
				return nil, errors.New("NSM notification receipt evidence regressed")
			}
			previous = r
		}
		if s.record.NotifyEpoch != 0 && !recoverLocks {
			return nil, errors.New("unfinished NSM crash notification remains quarantined")
		}
		if s.record.Dirty {
			if !recoverLocks {
				return nil, errors.New("previous NLM session ended with held or uncertain locks; journal quarantined; use nlmrecover for recorded confirmed locks, never delete state")
			}
			if s.record.Version != 2 || len(s.record.Locks) == 0 {
				return nil, errors.New("legacy or incomplete journal cannot recover lock identities; keep quarantined")
			}
			for _, l := range s.record.Locks {
				if !l.Confirmed {
					return nil, errors.New("unconfirmed LOCK may still execute on the server; journal remains quarantined")
				}
			}
			return s, nil // Keep the epoch and identities until every UNLOCK is confirmed.
		}
		if s.record.NotifyEpoch != 0 {
			return s, nil // Resume the exact epoch; never replace a pending notification.
		}
		if s.record.State > math.MaxInt32-2 {
			return nil, errors.New("NSM epoch exhausted; recovery required")
		}
		s.record.State += 2
	}
	s.record.Version = 2
	if err := s.append(); err != nil {
		return nil, err
	}
	return s, nil
}

func validateSavedNLMLocks(r nsmRecord) error {
	if r.NotifyAcknowledged && (r.NotifyEpoch == 0 || r.State != r.NotifyEpoch || r.Dirty) {
		return errors.New("invalid NSM notification receipt evidence")
	}
	if r.NotifyEpoch != 0 && (r.Version != 2 || r.NotifyEpoch > math.MaxInt32 || r.NotifyEpoch%2 != 1 || (r.NotifyEpoch != r.State && (r.State > math.MaxInt32-2 || r.NotifyEpoch != r.State+2)) || r.Dirty && r.NotifyEpoch == r.State) {
		return errors.New("invalid pending NSM notification epoch")
	}
	if r.LastSVID > math.MaxInt32 {
		return errors.New("NSM process identity counter exhausted")
	}
	if len(r.Locks) > 64 || len(r.Locks) > 0 && (!r.Dirty || r.Version != 2) {
		return errors.New("invalid NSM saved lock list")
	}
	ids, owners, pids := map[uint64]bool{}, map[string]bool{}, map[uint32]bool{}
	for _, l := range r.Locks {
		if (l.Version != 1 && l.Version != 4) || l.Info.ID == 0 || l.Info.Uncertain || ids[l.Info.ID] || len(l.FH) == 0 || len(l.FH) > 64 || l.Version == 1 && len(l.FH) != 32 || len(l.Owner) != 16 || owners[string(l.Owner)] || l.SVID == 0 || l.SVID > r.LastSVID || pids[l.SVID] || len(l.Auth.Groups) > 16 {
			return errors.New("invalid NSM saved lock identity")
		}
		if err := validateNLMRange(l.Version, l.Info.Offset, l.Info.Length); err != nil {
			return err
		}
		ids[l.Info.ID], owners[string(l.Owner)], pids[l.SVID] = true, true, true
	}
	return nil
}

func (s *nsmState) append() error {
	info, err := s.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(s.file.Name())
	if err != nil || !os.SameFile(info, named) || !named.Mode().IsRegular() || info.Size() != s.size {
		return errors.New("NSM state changed externally")
	}
	body, err := json.Marshal(s.record)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(body)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	frame = append(frame, hash[:]...)
	if s.size+int64(len(frame)) > maxNSMJournal {
		return errors.New("NSM state journal is full; new lock refused")
	}
	if _, err := s.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := s.file.Write(frame); err != nil {
		return err
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	s.size += int64(len(frame))
	return nil
}

func (s *nsmState) dirty(value bool) error {
	if s.record.Dirty == value {
		return nil
	}
	s.record.Dirty = value
	return s.append()
}

func (s *nsmState) close() { s.file.Close() }
