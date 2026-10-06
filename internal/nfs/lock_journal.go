package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"nfs-viewer/internal/krbconfig"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrLockJournalPending = errors.New("saved lock state is unresolved; exact cached evidence is required before restoring state")

// A policy refusal happens before journal persistence or RPC issue. It does
// not invalidate confirmed locks; storage and pending-state errors still do.
type lockJournalPolicyError string

func (e lockJournalPolicyError) Error() string { return string(e) }

const maxLockJournal = 16 << 20

// An exact pending request carries at most 1 MiB of XDR, plus redundant
// operation arguments and base64 JSON. Keep a separate bounded frame cap.
const maxLockRecord = 4 << 20

// LockNamespace contains path/handle identity only, never credentials or data.
type LockNamespace struct {
	Export, CWD             string
	Root                    []byte
	FSID, FSIDMinor, FileID uint64
	Paths                   map[uint64]string
}

type savedLock struct {
	Info                                               LockInfo
	Handle, OpenState, OpenOwner, LockState, LockOwner []byte
	OpenSequence                                       uint32
}

type lockRecord struct {
	Version                                                int
	Serial                                                 uint64
	Profile, Identity, Principal, Peer                     string
	Pending, Retired                                       bool
	Armed                                                  bool             `json:",omitempty"`
	Intent                                                 *savedLockIntent `json:",omitempty"`
	Nonce, Session, Root                                   []byte
	ClientID, ServerMinor                                  uint64
	Owner, Scope                                           []byte
	Slot, ReadSize, WriteSize, MaxReply, MaxRequest, Lease uint32
	Channel                                                sessionChannelLimits
	Confirmed                                              time.Time
	Auth                                                   Auth
	Namespace                                              LockNamespace
	Locks                                                  []savedLock
	PendingRequest                                         *SavedCompound      `json:",omitempty"`
	RecoveredRequest                                       *LockRequestReceipt `json:",omitempty"`
}

// A recovered request receipt describes one old request, not a completed file
// transfer. No interrupted application command is automatically resumed.
type LockRequestReceipt struct{ Operation, Status, Count uint32 }

type lockJournal struct {
	file        *os.File
	size        int64
	record      lockRecord
	recovering  bool // Durable lifecycle recovery owns this journal exclusively.
	transaction bool // Under the owning v4Client.mu.
}

type LockJournalSummary struct {
	Serial           uint64
	Pending, Retired bool
	Armed            bool
	Phase            string `json:",omitempty"`
	Locks            int
	Confirmed        time.Time
	RecoveredRequest *LockRequestReceipt
}

func InspectLockJournal(path string) (LockJournalSummary, error) {
	j, err := loadLockJournal(path, false)
	if err != nil {
		return LockJournalSummary{}, err
	}
	defer j.file.Close()
	r := j.record
	phase := ""
	if r.Intent != nil {
		phase = r.Intent.Phase
	}
	return LockJournalSummary{Serial: r.Serial, Pending: r.Pending, Retired: r.Retired, Armed: r.Armed, Phase: phase, Locks: len(r.Locks), Confirmed: r.Confirmed, RecoveredRequest: r.RecoveredRequest}, nil
}

func lockProfile(cfg Config) (string, error) {
	if cfg.Version != "4.1" && cfg.Version != "4.2" || cfg.Transport != "" && cfg.Transport != "tcp" || cfg.PNFS || cfg.Offload || cfg.TLS.InsecureSkipVerify || cfg.Security != "sys" && cfg.Security != "krb5i" && cfg.Security != "krb5p" || cfg.Security == "sys" && !cfg.TLS.Enabled {
		return "", errors.New("durable locks require explicit protected ordinary NFSv4.1/4.2 TCP")
	}
	if cfg.NFSPort == 0 {
		cfg.NFSPort = 2049
	}
	if cfg.TLS.Enabled && cfg.TLS.ServerName == "" {
		return "", errors.New("durable TLS locks require an explicit certificate name")
	}
	if cfg.Kerberos.RPCVersion == 0 {
		cfg.Kerberos.RPCVersion = 1
	}
	var trust []string
	if cfg.Security != "sys" && cfg.Kerberos.ConfigFile != "" {
		snapshot := cfg.Kerberos.configSnapshot
		if snapshot == nil {
			var err error
			snapshot, err = krbconfig.Load(cfg.Kerberos.ConfigFile)
			if err != nil {
				return "", err
			}
		}
		if err := snapshot.Verify(); err != nil {
			return "", err
		}
		trust = append(trust, "krb5:"+snapshot.Fingerprint())
	}
	for _, name := range []string{cfg.TLS.CAFile, cfg.TLS.CertFile} {
		if name == "" {
			trust = append(trust, "")
			continue
		}
		f, err := os.Open(name)
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
		f.Close()
		if err != nil || len(data) > 4<<20 {
			return "", errors.New("invalid recovery trust file")
		}
		h := sha256.Sum256(data)
		trust = append(trust, hex.EncodeToString(h[:]))
	}
	body, err := json.Marshal(struct {
		Host, Version, Security, Principal, SPN, TLSName string
		Port                                             int
		Auth                                             Auth
		TLS                                              bool
		RPC                                              uint32
		Trust                                            []string
	}{cfg.Host, cfg.Version, cfg.Security, cfg.Kerberos.Principal, cfg.Kerberos.SPN, cfg.TLS.ServerName, cfg.NFSPort, cfg.Auth, cfg.TLS.Enabled, cfg.Kerberos.RPCVersion, trust})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:]), nil
}

func validateLockRecord(r lockRecord, serial uint64) error {
	if r.Version != 1 || r.Serial != serial+1 || len(r.Profile) != 64 || len(r.Identity) > 2048 || len(r.Principal) > 1024 || len(r.Peer) > 1024 || len(r.Nonce) != 16 || len(r.Session) != 16 || len(r.Root) == 0 || len(r.Root) > 128 || r.ClientID == 0 || len(r.Owner) == 0 || len(r.Owner) > 1024 || len(r.Scope) == 0 || len(r.Scope) > 1024 || r.Slot == 0 || r.Slot == ^uint32(0) || r.Lease == 0 || r.Confirmed.IsZero() || r.ReadSize == 0 || r.ReadSize > 1<<20 || r.WriteSize == 0 || r.WriteSize > 1<<20 || len(r.Auth.Groups) > 16 || len(r.Locks) > 64 || len(r.Namespace.Paths) > 64 || len(r.Namespace.Root) == 0 || len(r.Namespace.Root) > 128 || r.Pending && r.Retired {
		return errors.New("invalid durable lock record bounds")
	}
	if err := r.Intent.validate(r); err != nil {
		return err
	}
	if r.PendingRequest != nil {
		s := r.PendingRequest
		if !r.Pending || s.Validate() != nil || !bytes.Equal(s.Session, r.Session) || s.Sequence != r.Slot || s.Auth.UID != r.Auth.UID || s.Auth.GID != r.Auth.GID || !slices.Equal(s.Auth.Groups, r.Auth.Groups) || (r.Intent == nil && !savedLockDataRequest(*s) || r.Intent != nil && !savedIntentMatches(r, *s)) {
			return errors.New("invalid durable pending compound")
		}
	}
	if !validLockPath(r.Namespace.Export) || !validLockPath(r.Namespace.CWD) {
		return errors.New("invalid saved lock namespace")
	}
	ids := map[uint64]bool{}
	for _, l := range r.Locks {
		if l.Info.ID == 0 || ids[l.Info.ID] || l.Info.Uncertain || len(l.Handle) == 0 || len(l.Handle) > 128 || len(l.OpenState) != 16 || len(l.LockState) != 16 || len(l.OpenOwner) != 16 || len(l.LockOwner) != 16 || l.OpenSequence == 0 || !validLockPath(r.Namespace.Paths[l.Info.ID]) {
			return errors.New("invalid saved lock inventory")
		}
		if err := ValidateLockRange(l.Info.Offset, l.Info.Length); err != nil {
			return err
		}
		ids[l.Info.ID] = true
	}
	if !r.Retired && !r.Armed && r.Intent == nil && len(r.Locks) == 0 {
		return errors.New("active durable lock inventory is empty")
	}
	return nil
}

func validLockPath(p string) bool {
	if !strings.HasPrefix(p, "/") || !utf8.ValidString(p) || len(p) > 16384 || strings.ContainsAny(p, "\\\x00\r\n") || len(strings.Split(p, "/")) > 65 {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." || len(part) > 255 {
			return false
		}
	}
	return true
}

func loadLockJournal(path string, create bool) (_ *lockJournal, err error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("lock journal path must be absolute")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("lock journal needs an existing real private directory")
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	if err = lockNSMFile(f); err != nil {
		return nil, fmt.Errorf("lock journal has another process owner: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() > maxLockJournal {
		return nil, errors.New("invalid or changed lock journal")
	}
	j := &lockJournal{file: f, size: info.Size()}
	if create {
		return j, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLockJournal+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("empty existing lock journal; keep quarantined")
	}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("truncated lock journal header")
		}
		n := int(binary.BigEndian.Uint32(data))
		data = data[4:]
		if n < 1 || n > maxLockRecord || len(data) < n+32 {
			return nil, errors.New("invalid lock journal frame")
		}
		h := sha256.Sum256(data[:n])
		if !bytes.Equal(h[:], data[n:n+32]) {
			return nil, errors.New("lock journal checksum mismatch")
		}
		if !utf8.Valid(data[:n]) {
			return nil, errors.New("invalid UTF-8 in lock journal")
		}
		d := json.NewDecoder(bytes.NewReader(data[:n]))
		d.DisallowUnknownFields()
		var r lockRecord
		if err := d.Decode(&r); err != nil {
			return nil, err
		}
		if d.Decode(new(any)) != io.EOF {
			return nil, errors.New("trailing lock journal JSON")
		}
		if err := validateLockRecord(r, j.record.Serial); err != nil {
			return nil, err
		}
		if j.record.Serial != 0 && (r.Profile != j.record.Profile || !bytes.Equal(r.Nonce, j.record.Nonce) || !bytes.Equal(r.Session, j.record.Session) || r.ClientID != j.record.ClientID || r.Identity != j.record.Identity || r.Principal != j.record.Principal || r.Peer != j.record.Peer || !bytes.Equal(r.Owner, j.record.Owner) || !bytes.Equal(r.Scope, j.record.Scope) || r.ServerMinor != j.record.ServerMinor || r.Slot < j.record.Slot || j.record.Retired) {
			return nil, errors.New("durable lock incarnation or ordering changed")
		}
		if j.record.Serial != 0 {
			previous := j.record
			if r.Auth.UID != previous.Auth.UID || r.Auth.GID != previous.Auth.GID || !slices.Equal(r.Auth.Groups, previous.Auth.Groups) || !bytes.Equal(r.Root, previous.Root) || r.Namespace.Export != previous.Namespace.Export || !bytes.Equal(r.Namespace.Root, previous.Namespace.Root) || r.Namespace.FSID != previous.Namespace.FSID || r.Namespace.FSIDMinor != previous.Namespace.FSIDMinor || r.Namespace.FileID != previous.Namespace.FileID || r.Confirmed.Before(previous.Confirmed) {
				return nil, errors.New("saved identity or namespace changed")
			}
			for _, l := range r.Locks {
				found := false
				for _, p := range previous.Locks {
					if p.Info.ID == l.Info.ID {
						found = p.Info == l.Info && p.OpenSequence == l.OpenSequence && bytes.Equal(p.Handle, l.Handle) && bytes.Equal(p.OpenState, l.OpenState) && bytes.Equal(p.OpenOwner, l.OpenOwner) && bytes.Equal(p.LockState, l.LockState) && bytes.Equal(p.LockOwner, l.LockOwner) && r.Namespace.Paths[l.Info.ID] == previous.Namespace.Paths[l.Info.ID]
					}
				}
				if !found && !completedSavedAcquisition(previous, r, l) {
					return nil, errors.New("saved lock inventory changed without acquisition evidence")
				}
			}
		}
		j.record = r
		data = data[n+32:]
	}
	return j, nil
}

func (j *lockJournal) append(r lockRecord) error {
	r.Version = 1
	r.Serial = j.record.Serial + 1
	if err := validateLockRecord(r, j.record.Serial); err != nil {
		return err
	}
	info, err := j.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(j.file.Name())
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() != j.size {
		return errors.New("lock journal changed externally")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(body) > maxLockRecord || j.size+int64(4+len(body)+32) > maxLockJournal {
		return errors.New("lock journal full; request refused")
	}
	h := sha256.Sum256(body)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
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
	j.size += int64(n)
	j.record = r
	return nil
}

func (v *v4Client) savedLocks() []savedLock {
	var items []savedLock
	for _, i := range v.c.Locks() {
		l := v.locks[i.ID]
		items = append(items, savedLock{Info: l.info, Handle: bytes.Clone(l.file.fh), OpenState: bytes.Clone(l.file.sid), OpenOwner: bytes.Clone(l.file.owner), LockState: bytes.Clone(l.sid), LockOwner: bytes.Clone(l.owner), OpenSequence: l.file.seq})
	}
	return items
}

// SaveLocks enables durable recording of confirmed state and planned lock phases.
// Saving an empty selected namespace arms it before the first acquisition.
func (c *Client) SaveLocks(path string, namespace LockNamespace) error {
	v := c.v4
	if v == nil || c.config == nil {
		return errors.New("durable locks require a configured NFSv4 client")
	}
	savedCfg := *c.config
	savedCfg.Auth = c.Auth
	profile, err := lockProfile(savedCfg)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.statefulFailover != nil && v.statefulFailover.Armed {
		return errors.New("automatic endpoint failover is armed; reconnect before saving an endpoint-bound journal")
	}
	if v.serverIdentity == nil || v.stateLost.Load() || v.leaseMoved.Load() || len(v.locks) > 64 {
		return errors.New("save requires confirmed lock state and a known session")
	}
	last := v.lastLease.Load()
	if last == nil || v.leaseSeconds == 0 || time.Since(*last) >= time.Duration(v.leaseSeconds)*time.Second {
		return errors.New("saved locks require a live confirmed lease")
	}
	r := lockRecord{Profile: profile, Identity: c.Identity(), Principal: c.principal, Peer: c.nfs.conn.RemoteAddr().String(), Nonce: bytes.Clone(v.clientNonce), Session: bytes.Clone(v.session), Root: bytes.Clone(v.root), ClientID: v.clientID, ServerMinor: v.serverMinor, Owner: []byte(v.serverIdentity.owner), Scope: []byte(v.serverIdentity.scope), Slot: v.sequence, ReadSize: c.ReadSize, WriteSize: c.WriteSize, MaxReply: v.maxReplyPayload, MaxRequest: v.maxRequestPayload, Channel: v.channel, Lease: v.leaseSeconds, Confirmed: *last, Auth: c.Auth, Namespace: namespace, Locks: v.savedLocks()}
	r.Armed = len(v.locks) == 0 || v.journal != nil && v.journal.record.Armed
	r.Auth.Groups = slices.Clone(c.Auth.Groups)
	r.Namespace.Root = bytes.Clone(namespace.Root)
	r.Namespace.Paths = make(map[uint64]string, len(namespace.Paths))
	for id, p := range namespace.Paths {
		r.Namespace.Paths[id] = p
	}
	for _, info := range c.Locks() {
		l := v.locks[info.ID]
		if info.Uncertain || l.file.auth.UID != c.Auth.UID || l.file.auth.GID != c.Auth.GID || !slices.Equal(l.file.auth.Groups, c.Auth.Groups) {
			return ErrLockUncertain
		}
	}
	if v.journal != nil {
		if filepath.Clean(path) != filepath.Clean(v.journal.file.Name()) || v.journal.record.Pending || v.journal.record.Retired {
			return ErrLockJournalPending
		}
		if r.Confirmed.Before(v.journal.record.Confirmed) {
			r.Confirmed = v.journal.record.Confirmed
		}
		return v.journal.append(r)
	}
	j, err := loadLockJournal(path, true)
	if err != nil {
		return err
	}
	if err = j.append(r); err != nil {
		j.file.Close()
		return err
	}
	v.journal = j
	return nil
}

func (j *lockJournal) before(v *v4Client, auth Auth, ops []v4Op) error {
	if j.record.Retired {
		return nil
	}
	if j.record.Intent != nil && !intentMatches(j.record, ops) {
		return lockJournalPolicyError("durable lock phase in progress")
	}
	if j.record.Pending && !j.transaction || v.stateLost.Load() || v.leaseMoved.Load() {
		return ErrLockJournalPending
	}
	if auth.UID != j.record.Auth.UID || auth.GID != j.record.Auth.GID || !slices.Equal(auth.Groups, j.record.Auth.Groups) {
		return lockJournalPolicyError("saved lock credentials changed")
	}
	for _, op := range ops {
		switch op.code {
		case 3, 9, 10, 15, 16, 22, 24, 25, 26, 27, 33, 38:
		case 4, 12, 14, 18, 45:
			if !j.transaction {
				return lockJournalPolicyError("saved lock cleanup requires a durable unlock transaction")
			}
		default:
			return lockJournalPolicyError("saved lock profile refuses new state or untracked mutation")
		}
	}
	r := j.record
	r.Pending = true
	r.PendingRequest = nil
	return j.append(r)
}

func (j *lockJournal) after(v *v4Client, started time.Time, cause error) error {
	if j.record.Retired {
		return nil
	}
	if j.record.Intent != nil {
		return nil
	}
	if channelNotSent(cause) {
		r := j.record
		r.Pending = j.transaction
		r.PendingRequest = nil
		return j.append(r)
	}
	var status Status
	if cause != nil && !errors.As(cause, &status) || v.stateLost.Load() || v.leaseMoved.Load() {
		return nil
	}
	if v.sequence == j.record.Slot {
		return nil
	} // No confirmed SEQUENCE, no new lease evidence.
	r := j.record
	r.Slot = v.sequence
	r.Confirmed = started
	r.Pending = j.transaction
	r.PendingRequest = nil
	return j.append(r)
}

func (v *v4Client) beginSavedUnlock() (func(error) error, error) {
	if v.journal == nil {
		return func(e error) error { return e }, nil
	}
	v.mu.Lock()
	j := v.journal
	if j.record.Pending || j.record.Retired || j.transaction {
		v.mu.Unlock()
		return nil, ErrLockJournalPending
	}
	r := j.record
	r.Pending = true
	if err := j.append(r); err != nil {
		v.mu.Unlock()
		return nil, err
	}
	j.transaction = true
	v.mu.Unlock()
	return func(cause error) error {
		v.mu.Lock()
		defer v.mu.Unlock()
		j.transaction = false
		if cause != nil || v.stateLost.Load() || v.leaseMoved.Load() {
			return cause
		}
		r := j.record
		r.Locks = v.savedLocks()
		r.Pending = false
		r.Retired = len(r.Locks) == 0
		if err := j.append(r); err != nil {
			v.stateLost.Store(true)
			return err
		}
		return nil
	}, nil
}

// RecoverLocks continues one saved protocol incarnation, not a restarted owner.
// Recorded pending compounds are resolved in their original live session;
// absent evidence, expired leases and revoked state remain quarantined.
func RecoverLocks(ctx context.Context, cfg Config, path string, validate func(*Client, LockNamespace) error) (*Client, error) {
	if err := validateSecurity(&cfg); err != nil {
		return nil, err
	}
	profile, err := lockProfile(cfg)
	if err != nil {
		return nil, err
	}
	j, err := loadLockJournal(path, false)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			j.file.Close()
		}
	}()
	r := j.record
	if r.Profile != profile || r.Auth.UID != cfg.Auth.UID || r.Auth.GID != cfg.Auth.GID || !slices.Equal(r.Auth.Groups, cfg.Auth.Groups) || r.Pending && r.PendingRequest == nil && r.Intent == nil || r.Retired || validate == nil {
		return nil, ErrLockJournalPending
	}
	if r.Channel.Request == 0 {
		return nil, errors.New("saved session lacks negotiated channel limits; reconnect instead of replaying the saved slot")
	}
	if time.Since(r.Confirmed) >= time.Duration(r.Lease)*time.Second || r.Confirmed.After(time.Now().Add(time.Second)) {
		return nil, errors.New("saved lease elapsed or local time moved backwards")
	}
	ctx, cancel := context.WithDeadline(ctx, r.Confirmed.Add(time.Duration(r.Lease)*time.Second))
	defer cancel()
	if r.Intent != nil {
		if err := j.recoverIntent(ctx, cfg); err != nil {
			return nil, err
		}
		r = j.record
		if r.Retired {
			return nil, ErrLockJournalReleased
		}
	}
	if r.PendingRequest != nil {
		if err := j.recoverPending(ctx, cfg); err != nil {
			return nil, err
		}
		r = j.record
	}
	r.Pending = true
	if err = j.append(r); err != nil {
		return nil, err
	}
	minor := uint32(1)
	if cfg.Version == "4.2" {
		minor = 2
	}
	old := &Client{config: &cfg, version: cfg.Version, security: cfg.Security, principal: r.Principal, Auth: r.Auth, ReadSize: r.ReadSize, WriteSize: r.WriteSize}
	v := &v4Client{c: old, minor: minor, clientID: r.ClientID, clientNonce: bytes.Clone(r.Nonce), session: bytes.Clone(r.Session), sequence: r.Slot, root: bytes.Clone(r.Root), serverMinor: r.ServerMinor, maxReplyPayload: r.MaxReply, maxRequestPayload: r.MaxRequest, channel: r.Channel, leaseSeconds: r.Lease, locks: map[uint64]*v4Lock{}, parents: map[string]v4Name{}, recoverEmpty: r.Armed}
	v.serverIdentity = &createSessionKey{nonce: string(r.Nonce), owner: string(r.Owner), scope: string(r.Scope), clientID: r.ClientID, minor: minor}
	v.lastLease.Store(&r.Confirmed)
	old.v4 = v
	for _, l := range r.Locks {
		v.locks[l.Info.ID] = &v4Lock{info: l.Info, file: &v4Open{fh: bytes.Clone(l.Handle), sid: bytes.Clone(l.OpenState), owner: bytes.Clone(l.OpenOwner), seq: l.OpenSequence, auth: r.Auth}, sid: bytes.Clone(l.LockState), owner: bytes.Clone(l.LockOwner)}
	}
	port := cfg.NFSPort
	if port == 0 {
		port = 2049
	}
	target := ReadReplica{Address: net.JoinHostPort(cfg.Host, strconv.Itoa(port)), SPN: cfg.Kerberos.SPN, TLSName: cfg.TLS.ServerName}
	fresh, err := old.MigrateLocks(ctx, target, func(c *Client) error {
		if c.nfs.conn.RemoteAddr().String() != r.Peer || *c.v4.serverIdentity != *v.serverIdentity || c.v4.serverMinor != r.ServerMinor || c.Identity() != r.Identity {
			return errors.New("saved server incarnation, peer or identity changed")
		}
		return validate(c, r.Namespace)
	})
	if err != nil {
		return nil, err
	}
	// Persist the fully validated sequence before making recovered state usable.
	fresh.v4.mu.Lock()
	r = j.record
	r.Pending = false
	r.Slot = fresh.v4.sequence
	r.Confirmed = time.Now()
	r.Lease = fresh.v4.leaseSeconds
	err = j.append(r)
	if err == nil {
		fresh.v4.journal = j
	}
	fresh.v4.mu.Unlock()
	if err != nil {
		fresh.v4.migrationBorrowed = true
		fresh.v4.stateLost.Store(true)
		fresh.Close()
		return nil, err
	}
	ready = true
	return fresh, nil
}
