package nfs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrOffloadPending = errors.New("previous offload outcome is unverified; inspect the journal and verify server quiescence and destination before acknowledging it; no replay")

const maxOffloadJournal = 4 << 20

type offloadIntent struct {
	Operation                    string
	Source, Destination          []byte
	SourceOffset, Offset, Length uint64
	SourceProfile                string
	Target, SourceTarget         string
}

// OffloadRecord is local evidence, not a resumable server stateid or a success
// claim. Acknowledging an unknown outcome records an operator's decision only.
type OffloadRecord struct {
	Version                      int
	Sequence                     uint64
	ID, Profile, Operation       string
	Source, Destination          []byte `json:",omitempty"`
	SourceOffset, Offset, Length uint64
	SourceProfile                string `json:",omitempty"`
	Target, SourceTarget         string `json:",omitempty"`
	Phase                        string
	Pending                      bool
	Outcome, Error               string                     `json:",omitempty"`
	CallbackID                   []byte                     `json:",omitempty"`
	Reconcile                    *OffloadReconcileEvidence  `json:",omitempty"`
	Recovery                     *OffloadSessionEvidence    `json:",omitempty"`
	Expectation                  *OffloadExpectation        `json:",omitempty"`
	SourceGrant                  *OffloadSourceGrant        `json:",omitempty"`
	Resources                    *OffloadResources          `json:",omitempty"`
	Endpoints                    map[string]OffloadEndpoint `json:",omitempty"`
}

type offloadJournal struct {
	file            *os.File
	size            int64
	record          OffloadRecord
	attemptDigest   [32]byte
	attemptStarted  time.Time
	checkpoint      bool
	bank            int
	checkpointFault func(string) error // Test-only crash boundary injection.
	parent          *offloadJournal
	endpoint        string
	guard           *sync.Mutex
}

func loadOffloadJournal(path string, create bool, checkpoints ...bool) (_ *offloadJournal, err error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("offload journal path must be absolute")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("offload journal parent must be an existing real directory")
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	created := create && err == nil
	if create && errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, errors.New("offload journal must be a regular file")
		}
		f, err = os.OpenFile(path, os.O_RDWR, 0)
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
		return nil, fmt.Errorf("offload journal is owned by another process: %w", err)
	}
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(opened, named) {
		return nil, errors.New("offload journal changed while opening")
	}
	if opened.Size() > maxOffloadJournal {
		return nil, errors.New("offload journal exceeds its size limit")
	}
	j := &offloadJournal{file: f, size: opened.Size()}
	if created {
		if len(checkpoints) > 0 && checkpoints[0] {
			if err := j.initializeCheckpoints(); err != nil {
				return nil, err
			}
		}
		return j, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxOffloadJournal+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("empty existing offload journal; keep quarantined")
	}
	if bytes.HasPrefix(data, []byte(offloadCheckpointMagic)) {
		if err := j.loadCheckpoints(data); err != nil {
			return nil, err
		}
		return j, nil
	}
	var previous OffloadRecord
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("truncated offload journal header")
		}
		n := int(binary.BigEndian.Uint32(data))
		data = data[4:]
		if n < 1 || n > 65536 || len(data) < n+sha256.Size {
			return nil, errors.New("invalid offload journal record length")
		}
		digest := sha256.Sum256(data[:n])
		if !bytes.Equal(digest[:], data[n:n+sha256.Size]) {
			return nil, errors.New("offload journal checksum mismatch")
		}
		d := json.NewDecoder(bytes.NewReader(data[:n]))
		d.DisallowUnknownFields()
		var r OffloadRecord
		if err := d.Decode(&r); err != nil {
			return nil, err
		}
		if d.Decode(new(any)) != io.EOF {
			return nil, errors.New("trailing offload JSON data")
		}
		if err := validateOffloadRecord(r, previous); err != nil {
			return nil, err
		}
		previous = r
		data = data[n+sha256.Size:]
	}
	j.record = previous
	return j, nil
}

func validateOffloadRecord(r, previous OffloadRecord) error {
	if err := validateOffloadEndpoints(r, previous); err != nil {
		return err
	}
	if err := validateOffloadResources(r, previous); err != nil {
		return err
	}
	if err := validateOffloadSourceGrant(r, previous); err != nil {
		return err
	}
	if err := validateOffloadExpectation(r, previous); err != nil {
		return err
	}
	if err := validateOffloadSession(r, previous); err != nil {
		return err
	}
	if err := validateOffloadReconcile(r, previous); err != nil {
		return err
	}
	if len(r.Target) > 4096 || len(r.SourceTarget) > 4096 {
		return errors.New("offload journal target exceeds its bound")
	}
	id, err := hex.DecodeString(r.ID)
	if err != nil || len(id) != 16 || r.ID != hex.EncodeToString(id) || r.Version != 1 || r.Sequence == 0 || r.Sequence != previous.Sequence+1 || len(r.Profile) == 0 || len(r.Profile) > 128 || len(r.SourceProfile) > 128 || len(r.Destination) == 0 || len(r.Destination) > 128 || len(r.Source) > 128 || len(r.Error) > 2048 || len(r.CallbackID) != 0 && len(r.CallbackID) != 16 {
		return errors.New("invalid offload journal identity or bounds")
	}
	if err := ValidateSpaceRange(r.Offset, r.Length); err != nil {
		return err
	}
	if r.SourceOffset > ^uint64(0)-r.Length {
		return errors.New("invalid saved offload source range")
	}
	switch r.Operation {
	case "copyasync", "copyrange", "clonerange", "copyfrom", "writesame":
	default:
		return errors.New("invalid saved offload operation")
	}
	if r.Phase != "prepared" && r.Phase != "issued" {
		return errors.New("invalid offload phase")
	}
	if r.Pending {
		if r.Outcome != "" && r.Outcome != "unverified" || r.Outcome == "unverified" && r.Phase != "issued" {
			return errors.New("invalid pending offload outcome")
		}
	} else {
		switch r.Outcome {
		case "completed":
			if r.Phase != "issued" || r.Error != "" || r.Resources != nil && !offloadResourcesReleased(r) {
				return errors.New("invalid completed offload")
			}
		case "completed-data-state-unverified":
			if r.Phase != "issued" || r.Error != "" || r.Recovery == nil || !r.Recovery.Committed || r.Recovery.Request != nil || r.Recovery.StateCleanup != "unverified" {
				return errors.New("data receipt lacks checked completion and explicit state disposition")
			}
		case "not-issued":
			if r.Phase != "prepared" && (r.Resources == nil || r.Recovery == nil || r.Recovery.DataIssued || r.Recovery.Request != nil || r.Recovery.Result != nil) || r.Resources != nil && !offloadResourcesReleased(r) {
				return errors.New("invalid unissued offload")
			}
		case "acknowledged-unknown":
		case "reconciled-verified":
			if r.Phase != "issued" || r.Reconcile == nil || !r.Reconcile.Receipt {
				return errors.New("reconciled outcome lacks confirmed completion receipt")
			}
		default:
			return errors.New("invalid terminal offload outcome")
		}
	}
	if previous.Sequence == 0 || !previous.Pending {
		if !r.Pending || r.Phase != "prepared" || r.Outcome != "" || r.Error != "" || len(r.CallbackID) != 0 || previous.ID == r.ID {
			return errors.New("invalid new offload transition")
		}
		if previous.Sequence != 0 && previous.Profile != r.Profile {
			return errors.New("offload journal profile changed")
		}
	} else {
		if r.ID != previous.ID || r.Profile != previous.Profile || r.Operation != previous.Operation || !bytes.Equal(r.Source, previous.Source) || !bytes.Equal(r.Destination, previous.Destination) || r.SourceOffset != previous.SourceOffset || r.Offset != previous.Offset || r.Length != previous.Length || r.SourceProfile != previous.SourceProfile || previous.Phase == "issued" && r.Phase != "issued" || len(previous.CallbackID) != 0 && !bytes.Equal(previous.CallbackID, r.CallbackID) {
			return errors.New("offload journal intent changed")
		}
		if r.Target != previous.Target || r.SourceTarget != previous.SourceTarget {
			return errors.New("offload journal target changed")
		}
	}
	return nil
}

func (j *offloadJournal) append(r OffloadRecord) error {
	if j.parent != nil {
		next := j.parent.record
		next.Endpoints = cloneOffloadEndpoints(next.Endpoints)
		e := next.Endpoints[j.endpoint]
		e.Recovery, e.Resources = r.Recovery, r.Resources
		next.Endpoints[j.endpoint] = e
		if r.SourceGrant != nil {
			next.SourceGrant = r.SourceGrant
		}
		if err := j.parent.append(next); err != nil {
			return err
		}
		j.record = endpointRecord(j.parent.record, j.endpoint)
		return nil
	}
	r.Version = 1
	r.Sequence = j.record.Sequence + 1
	if err := validateOffloadRecord(r, j.record); err != nil {
		return err
	}
	if j.checkpoint {
		return j.appendCheckpoint(r)
	}
	info, err := j.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(j.file.Name())
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() != j.size {
		return errors.New("offload journal changed externally")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(body) > 65536 || j.size+int64(4+len(body)+sha256.Size) > maxOffloadJournal {
		return errors.New("offload journal is full; request refused")
	}
	digest := sha256.Sum256(body)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	frame = append(frame, digest[:]...)
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
	j.record = r
	j.size += int64(len(frame))
	return nil
}

func openOffloadJournal(path, profile string, intent offloadIntent, checkpoints ...bool) (_ *offloadJournal, err error) {
	j, err := loadOffloadJournal(path, true, checkpoints...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			j.file.Close()
		}
	}()
	if len(checkpoints) > 0 && checkpoints[0] && !j.checkpoint {
		return nil, errors.New("session recovery requires a new checkpoint journal; resolve existing legacy evidence and select a fresh path")
	}
	if j.record.Sequence != 0 && j.record.Profile != profile {
		return nil, errors.New("offload journal profile mismatch; keep original evidence")
	}
	if j.record.Pending {
		if j.record.Phase != "prepared" || j.record.Resources != nil && !offloadResourcesReleased(j.record) {
			return nil, ErrOffloadPending
		}
		r := j.record
		r.Pending = false
		r.Outcome = "not-issued"
		if err = j.append(r); err != nil {
			return nil, err
		}
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, err
	}
	r := OffloadRecord{ID: hex.EncodeToString(id[:]), Profile: profile, Operation: intent.Operation, Source: bytes.Clone(intent.Source), Destination: bytes.Clone(intent.Destination), SourceOffset: intent.SourceOffset, Offset: intent.Offset, Length: intent.Length, SourceProfile: intent.SourceProfile, Phase: "prepared", Pending: true}
	r.Target, r.SourceTarget = intent.Target, intent.SourceTarget
	if err = j.append(r); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *offloadJournal) issue() error {
	if j.record.Phase == "issued" {
		return nil
	}
	r := j.record
	r.Phase = "issued"
	return j.append(r)
}

func (j *offloadJournal) callbackID(id []byte) error {
	r := j.record
	r.CallbackID = bytes.Clone(id)
	return j.append(r)
}

func (j *offloadJournal) finish(cause error) error {
	r := j.record
	if r.Phase == "prepared" && (r.Resources == nil || offloadResourcesReleased(r)) {
		r.Pending = false
		r.Outcome = "not-issued"
	} else if cause == nil && (r.Resources == nil || offloadResourcesReleased(r)) {
		r.Pending = false
		r.Outcome = "completed"
	} else if r.Phase == "issued" {
		r.Outcome = "unverified"
	}
	if cause != nil {
		r.Error = strings.ToValidUTF8(cause.Error(), "?")
		if len(r.Error) > 2048 {
			r.Error = strings.ToValidUTF8(r.Error[:2045], "?") + "..."
		}
	}
	return errors.Join(j.append(r), j.file.Close())
}

func InspectOffloadJournal(path string) (OffloadRecord, error) {
	j, err := loadOffloadJournal(path, false)
	if err != nil {
		return OffloadRecord{}, err
	}
	err = j.file.Close()
	return j.record, err
}

// AcknowledgeOffloadJournal does not contact a server, replay a request, reuse
// a stateid or certify data. The caller must first establish quiescence and
// independently verify/repair the destination. The unknown outcome is retained.
func AcknowledgeOffloadJournal(path, id string) error {
	j, err := loadOffloadJournal(path, false)
	if err != nil {
		return err
	}
	defer j.file.Close()
	if !j.record.Pending || j.record.ID != id {
		return errors.New("acknowledgement must identify the current pending offload")
	}
	r := j.record
	r.Pending = false
	r.Outcome = "acknowledged-unknown"
	return j.append(r)
}

func (c *Client) offloadProfile() string {
	var cfg Config
	if c.config != nil {
		cfg = *c.config
	}
	peer := ""
	if c.nfs != nil && c.nfs.conn != nil {
		peer = c.nfs.conn.RemoteAddr().String()
	}
	body, _ := json.Marshal(struct {
		Host, Peer, Version, Security, Principal, SPN string
		RPCVersion                                    uint32
		Auth                                          Auth
		TLS                                           bool
		TLSName                                       string
		Insecure                                      bool
	}{cfg.Host, peer, c.Version(), c.Security(), c.principal, cfg.Kerberos.SPN, cfg.Kerberos.RPCVersion, c.Auth, cfg.TLS.Enabled, cfg.TLS.ServerName, cfg.TLS.InsecureSkipVerify})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func (c *Client) offloadTarget() string {
	host, peer := "", ""
	if c.config != nil {
		host = c.config.Host
	}
	if c.nfs != nil && c.nfs.conn != nil {
		peer = c.nfs.conn.RemoteAddr().String()
	}
	return fmt.Sprintf("%s peer=%s version=%s security=%s principal=%s uid=%d gid=%d", host, peer, c.Version(), c.Security(), c.principal, c.Auth.UID, c.Auth.GID)
}
