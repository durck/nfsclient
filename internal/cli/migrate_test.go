package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

type migrationLockWire struct {
	open, lock, owner []byte
	write             bool
	offset, length    uint64
}
type migrationEvidence struct {
	mu    sync.Mutex
	nonce []byte
	owner string
	next  uint32
	locks []migrationLockWire
}
type migrationWirePeer struct {
	base                                                          blockCLIPeer
	metadata                                                      referralWirePeer
	origin                                                        bool
	recovery                                                      bool
	mode                                                          string
	evidence                                                      *migrationEvidence
	moved                                                         atomic.Bool
	opens, locks, binds, tests, unlocks, destroyed, reads, writes atomic.Int32
}

func migrationSID(kind, id byte) []byte {
	b := bytes.Repeat([]byte{kind}, 16)
	binary.BigEndian.PutUint32(b, 1)
	b[15] = id
	return b
}
func (p *migrationWirePeer) operation(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
	x := p.evidence
	x.mu.Lock()
	defer x.mu.Unlock()
	var e []byte
	sessionID := bytes.Repeat([]byte{9}, 16)
	switch code {
	case 42:
		nonce := bytes.Clone(d.take(8))
		owner := string(d.opaque())
		d.take(12)
		if p.origin {
			x.nonce, x.owner = nonce, owner
		} else if !bytes.Equal(nonce, x.nonce) || owner != x.owner {
			return nil, 0, errors.New("migration changed owner/verifier"), true
		}
		id, flags := uint64(123), uint32(0x10000)
		scope, server := "migration-scope", "source-owner"
		if !p.origin {
			flags |= 0x80000000
			server = "destination-owner"
			if p.recovery {
				server = "source-owner"
			}
		}
		if !p.origin && p.mode == "unconfirmed" {
			flags &^= 0x80000000
		}
		if !p.origin && p.mode == "client-id" {
			id++
		}
		if !p.origin && p.mode == "scope" {
			scope = "different-scope"
		}
		e = blockCLIQuad(e, id)
		e = missingV4Words(e, 1, flags, 0)
		e = blockCLIQuad(e, 1)
		e = missingV4Opaque(e, []byte(server))
		e = missingV4Opaque(e, []byte(scope))
		e = missingV4Words(e, 0)
	case 43:
		if !p.origin {
			return nil, 0, errors.New("migration created a replacement session"), true
		}
		d.take(8)
		seq := d.word()
		d.word()
		fore, back := d.take(28), d.take(28)
		//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
		if d.word() != 0 || d.word() != 0 {
			return nil, 0, errors.New("unexpected migration callback"), true
		}
		e = append(e, sessionID...)
		e = missingV4Words(e, seq, 0)
		e = append(e, fore...)
		e = append(e, back...)
		x.next = 1
	case 53:
		if !bytes.Equal(d.take(16), sessionID) {
			return nil, 0, errors.New("migration session ID changed"), true
		}
		seq := d.word()
		if seq != x.next {
			return nil, 0, fmt.Errorf("migration used sequence %d, expected %d", seq, x.next), true
		}
		x.next++
		d.take(12)
		peek := &missingV4Decoder{b: d.b}
		finalLease := false
		if !p.origin && p.mode == "revoked-final" && peek.word() == 22 {
			peek.opaque()
			finalLease = peek.word() == 9 && reflect.DeepEqual(peek.bitmap(), []uint32{10})
		}
		e = append(e, sessionID...)
		if !p.origin && p.mode == "sequence" {
			seq++
		}
		flags := uint32(0)
		if p.origin && p.mode == "valid-lease-moved" && p.moved.Load() {
			flags = 0x80 // RFC 8881 SEQ4_STATUS_LEASE_MOVED.
		}
		if !p.origin && (p.mode == "revoked" || finalLease) {
			flags = 0x10
		}
		e = missingV4Words(e, seq, 0, 0, 0, flags)
	case 41:
		p.binds.Add(1)
		if !bytes.Equal(d.take(16), sessionID) || d.word() != 1 || d.word() != 0 {
			return nil, 0, errors.New("unsafe migration binding"), true
		}
		if p.mode == "no-session" {
			return nil, 10052, nil, true
		}
		e = append(e, sessionID...)
		e = missingV4Words(e, 1, 0)
	case 55:
		p.tests.Add(1)
		count := d.word()
		if count != uint32(2*len(x.locks)) {
			return nil, 0, errors.New("migration did not test both stateids per lock"), true
		}
		for _, l := range x.locks {
			if !bytes.Equal(d.take(16), l.open) || !bytes.Equal(d.take(16), l.lock) {
				return nil, 0, errors.New("migration tested different stateids"), true
			}
		}
		if p.mode == "test-count" {
			count--
		}
		e = missingV4Words(e, count)
		for i := uint32(0); i < count; i++ {
			s := uint32(0)
			if p.mode == "lost-open" && i == 0 || p.mode == "lost-lock" && i == 1 {
				s = 10025
			}
			e = missingV4Words(e, s)
		}
	case 24:
		*current = "/"
	case 22:
		*current = string(d.opaque())
	case 15:
		name := string(d.opaque())
		if *current == "/" && (p.origin && name == "data" || !p.origin && (name == "relocated" || p.recovery && name == "data")) {
			*current = "/data"
		} else if *current == "/data" && name == "file" {
			*current = "/data/file"
			if !p.origin && p.mode == "path" {
				*current = "/different/file"
			}
		} else {
			return nil, 2, nil, true
		}
	case 10:
		e = missingV4Opaque(e, []byte(*current))
	case 9:
		bits := d.bitmap()
		if reflect.DeepEqual(bits, []uint32{24}) {
			var a []byte
			a = missingV4Words(a, 1)
			a = missingV4Opaque(a, []byte("data"))
			a = missingV4Words(a, 1, 1)
			a = missingV4Opaque(a, []byte("approved.test"))
			a = missingV4Words(a, 1)
			a = missingV4Opaque(a, []byte("relocated"))
			e = blockCLIBitmap(e, bits)
			e = missingV4Opaque(e, a)
		} else if p.origin && p.moved.Load() && *current == "/data" {
			return nil, 10019, nil, true
		} else {
			// Reuse independent attribute construction, with its request restored.
			wire := blockCLIBitmap(nil, bits)
			copyDecoder := &missingV4Decoder{b: wire}
			value, s, err, _ := p.metadata.operation(code, copyDecoder, current)
			return value, s, err, true
		}
	case 18:
		if !p.origin {
			return nil, 0, errors.New("migration reissued OPEN"), true
		}
		p.opens.Add(1)
		d.word()
		share := d.word()
		if (share != 1 && share != 3) || d.word() != 0 {
			return nil, 0, errors.New("changed share mode"), true
		}
		d.take(8)
		owner := bytes.Clone(d.opaque())
		//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
		if d.word() != 0 || d.word() != 0 || string(d.opaque()) != "file" {
			return nil, 0, errors.New("migration created/reclaimed an OPEN"), true
		}
		id := byte(len(x.locks) + 1)
		l := migrationLockWire{open: migrationSID(7, id), lock: migrationSID(8, id), owner: owner, write: share == 3}
		x.locks = append(x.locks, l)
		*current = "/data/file"
		e = append(e, l.open...)
		e = missingV4Words(e, 1, 0, 1, 0, 1, 0, 0, 0)
	case 12:
		if !p.origin {
			return nil, 0, errors.New("migration reissued LOCK"), true
		}
		p.locks.Add(1)
		kind := d.word()
		if d.word() != 0 {
			return nil, 0, errors.New("unexpected reclaim"), true
		}
		l := &x.locks[len(x.locks)-1]
		l.offset = uint64(d.word())<<32 | uint64(d.word())
		l.length = uint64(d.word())<<32 | uint64(d.word())
		if (kind == 2) != l.write || d.word() != 1 || d.word() != 1 || !bytes.Equal(d.take(16), l.open) || d.word() != 0 {
			return nil, 0, errors.New("initial lock state/sequence changed"), true
		}
		d.take(8)
		d.opaque()
		e = append(e, l.lock...)
		if p.mode != "not-moved" {
			p.moved.Store(true)
		}
	case 38:
		if p.origin && !p.recovery {
			return nil, 0, errors.New("WRITE replayed on source"), true
		}
		sid := d.take(16)
		valid := false
		for _, l := range x.locks {
			valid = valid || l.write && bytes.Equal(sid, l.lock)
		}
		offset := uint64(d.word())<<32 | uint64(d.word())
		stable := d.word()
		data := d.opaque()
		if !valid || stable != 2 || offset > uint64(len(p.metadata.data)) || uint64(len(data)) > uint64(len(p.metadata.data))-offset {
			return nil, 0, errors.New("invalid migrated WRITE"), true
		}
		copy(p.metadata.data[int(offset):], data)
		p.writes.Add(1)
		e = missingV4Words(e, uint32(len(data)), 2)
		e = append(e, bytes.Repeat([]byte{4}, 8)...)
	case 25:
		if p.origin && !p.recovery {
			return nil, 0, errors.New("data command replayed on original"), true
		}
		sid := d.take(16)
		valid := false
		for _, l := range x.locks {
			valid = valid || bytes.Equal(sid, l.lock)
		}
		if !valid {
			return nil, 0, errors.New("read did not use migrated LOCK"), true
		}
		offset := uint64(d.word())<<32 | uint64(d.word())
		size := int(d.word())
		if offset > uint64(len(p.metadata.data)) {
			return nil, 0, errors.New("invalid migrated offset"), true
		}
		end := min(int(offset)+size, len(p.metadata.data))
		eof := uint32(0)
		if end == len(p.metadata.data) {
			eof = 1
		}
		e = missingV4Words(e, eof)
		e = missingV4Opaque(e, p.metadata.data[int(offset):end])
		p.reads.Add(1)
	case 14:
		if p.origin && p.mode != "not-moved" {
			return nil, 0, errors.New("old state unlocked after transition"), true
		}
		d.word()
		if d.word() != 1 {
			return nil, 0, errors.New("LOCKU sequence was reset"), true
		}
		sid := d.take(16)
		off := uint64(d.word())<<32 | uint64(d.word())
		length := uint64(d.word())<<32 | uint64(d.word())
		valid := false
		for _, l := range x.locks {
			valid = valid || bytes.Equal(sid, l.lock) && off == l.offset && length == l.length
		}
		if !valid {
			return nil, 0, errors.New("migrated lock range changed"), true
		}
		p.unlocks.Add(1)
		e = bytes.Clone(sid)
		binary.BigEndian.PutUint32(e, 2)
	case 45:
		d.take(16)
	case 4:
		if p.origin && p.moved.Load() {
			return nil, 0, errors.New("old OPEN closed after migration"), true
		}
		if d.word() != 2 {
			return nil, 0, errors.New("OPEN sequence was reset"), true
		}
		sid := d.take(16)
		valid := false
		for _, l := range x.locks {
			valid = valid || bytes.Equal(sid, l.open)
		}
		if !valid {
			return nil, 0, errors.New("migrated OPEN changed"), true
		}
		e = bytes.Clone(sid)
	case 44, 57:
		p.destroyed.Add(1)
		if !strings.HasPrefix(p.mode, "valid-") && !p.origin {
			return nil, 0, errors.New("failed migration destroyed transferred state"), true
		}
		if code == 44 {
			d.take(16)
		} else {
			d.take(8)
		}
	default:
		return nil, 0, nil, false
	}
	return e, 0, nil, true
}

func TestStateMigrationProtected(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"valid-read", "valid-write", "valid-range", "valid-multi", "valid-lease-moved", "unconfirmed", "client-id", "scope", "no-session", "sequence", "revoked", "revoked-final", "test-count", "lost-open", "lost-lock", "path", "not-moved"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				policy, server := referralTLSPolicy(t)
				x := &migrationEvidence{}
				payload := bytes.Repeat([]byte("transferred-lock\x00\xff"), 200)
				origin := &migrationWirePeer{origin: true, mode: mode, evidence: x, metadata: referralWirePeer{data: payload}}
				target := &migrationWirePeer{mode: mode, evidence: x, metadata: referralWirePeer{data: payload}}
				var listeners []net.Listener
				var joined []chan error
				start := func(p *migrationWirePeer) string {
					l, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					listeners = append(listeners, l)
					done := make(chan error, 1)
					joined = append(joined, done)
					p.base.minor = minor
					p.base.operationHook = p.operation
					go func() { done <- p.base.serve(&referralTLSListener{Listener: l, config: server}) }()
					return l.Addr().String()
				}
				originAddress, targetAddress := start(origin), start(target)
				var client *nfs.Client
				var once sync.Once
				stop := func() {
					once.Do(func() {
						if client != nil {
							client.Close()
						}
						for _, l := range listeners {
							l.Close()
						}
						for _, done := range joined {
							if err := <-done; err != nil {
								t.Errorf("migration wire: %v", err)
							}
						}
					})
				}
				t.Cleanup(stop)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, port, _ := net.SplitHostPort(originAddress)
				number, _ := strconv.Atoi(port)
				if os.Getenv("NFS_VIEWER_TEST_BINARY") != "" {
					kind, ranges := "read", ""
					if mode == "valid-write" {
						kind = "write"
					}
					if mode == "valid-range" || mode == "valid-multi" {
						ranges = " 0 100"
					}
					args := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(number), "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--tls", "--tls-ca", policy.CAFile, "--tls-server-name", policy.ServerName, "--command", "lock file " + kind + ranges}
					count := int32(1)
					if mode == "valid-multi" {
						args = append(args, "--command", "lock file read 200 100")
						count++
					}
					args = append(args, "--command", "migrate approved.test="+targetAddress+",,referral.test")
					local := filepath.Join(t.TempDir(), "output")
					if mode != "valid-range" && mode != "valid-multi" {
						args = append(args, "--command", "get file "+strconv.Quote(local))
					}
					args = append(args, "--command", "unlock 1")
					if count == 2 {
						args = append(args, "--command", "unlock 2")
					}
					out, e := runKerberosCLI(t, args)
					t.Logf("MIGRATION_RELEASE_CLI mode=%s error=%v output=%s", mode, e, out)
					valid := strings.HasPrefix(mode, "valid-")
					if (e == nil) != valid {
						t.Fatal("wrong release migration outcome", e)
					}
					if valid {
						if mode != "valid-range" && mode != "valid-multi" {
							got, err := os.ReadFile(local)
							if err != nil || !bytes.Equal(got, payload) {
								t.Fatal("release migrated bytes differ", err)
							}
						}
						if target.unlocks.Load() != count {
							t.Fatal("release locks not released")
						}
					} else if target.destroyed.Load() != 0 {
						t.Fatal("release failure destroyed transferred session")
					}
					stop()
					if origin.opens.Load() != count || origin.locks.Load() != count || target.opens.Load() != 0 || target.locks.Load() != 0 {
						t.Fatal("release OPEN/LOCK replayed")
					}
					return
				}
				var err error
				client, err = nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", NFSPort: number, Version: fmt.Sprintf("4.%d", minor), Timeout: time.Second, TLS: policy})
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(client, "127.0.0.1", false, false, io.Discard)
				if err = s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				write := mode == "valid-write"
				length := uint64(nfs.LockToEOF)
				if mode == "valid-range" || mode == "valid-multi" {
					length = 100
				}
				id, err := s.LockRange(ctx, "file", write, 0, length)
				if err != nil {
					t.Fatal(err)
				}
				ids := []uint64{id}
				if mode == "valid-multi" {
					second, e := s.LockRange(ctx, "file", false, 200, 100)
					if e != nil {
						t.Fatal(e)
					}
					ids = append(ids, second)
				}
				before := s.Client.Locks()
				old := s.Client
				err = s.Migrate(ctx, session.ReferralTarget{Server: "approved.test", Target: nfs.ReadReplica{Address: targetAddress, TLSName: "referral.test"}})
				valid := strings.HasPrefix(mode, "valid-")
				if (err == nil) != valid {
					t.Fatal("wrong migration outcome", err)
				}
				if valid {
					client = s.Client
					if client == old || s.Export != "/relocated" || !reflect.DeepEqual(before, client.Locks()) || s.LockPaths[id] != "/file" {
						t.Fatal("migration inventory/namespace changed")
					}
					if mode != "valid-range" && mode != "valid-multi" {
						if write {
							updated := bytes.Repeat([]byte("new-explicit-write"), 5)
							fh, err := client.LockedFileHandle(id)
							if err != nil {
								t.Fatal(err)
							}
							n, err := client.WriteFrom(ctx, fh, bytes.NewReader(updated))
							if err != nil || n != int64(len(updated)) || target.writes.Load() == 0 {
								t.Fatal("migrated locked write", err)
							}
						}
						var out bytes.Buffer
						n, err := s.Cat(ctx, "file", &out)
						if err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
							t.Fatal("migrated locked read", err)
						}
					}
					for _, id := range ids {
						if err = client.Unlock(ctx, id); err != nil {
							t.Fatal("migrated unlock", err)
						}
					}
					if len(client.Locks()) != 0 || target.unlocks.Load() != int32(len(ids)) {
						t.Fatal("lock not released once")
					}
				} else {
					if s.Client != old || s.Export != "/data" || len(old.Locks()) != 1 {
						t.Fatal("failed migration lost quarantine")
					}
					if mode != "not-moved" && !old.Locks()[0].Uncertain {
						t.Fatal("failed migrated state treated as live")
					}
					if target.destroyed.Load() != 0 {
						t.Fatal("failed validation destroyed session")
					}
				}
				stop()
				if origin.opens.Load() != int32(len(ids)) || origin.locks.Load() != int32(len(ids)) || target.opens.Load() != 0 || target.locks.Load() != 0 {
					t.Fatal("OPEN/LOCK was replayed")
				}
			})
		}
	}
}

func TestStateMigrationSyntax(t *testing.T) {
	for _, line := range []string{"migrate", "migrate host:2049,,", "migrate x=host:2049", "migrate x=host:2049,, extra"} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), line); err == nil {
			t.Fatal("invalid migration syntax accepted", line)
		}
	}
}
