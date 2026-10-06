package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// Destroying a DS session does not destroy its confirmed client ID. FreeBSD
// returns an ignored zero sequence on subsequent EXCHANGE_ID replies.
func TestV4CreateSessionSequenceSurvivesSessionDestruction(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			next := uint32(22)
			confirmed := false
			var requests []uint32
			v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 42:
					d.take(8)
					d.str()
					d.take(12)
					e.u64(123)
					flags, sequence := uint32(0x40000), next
					if confirmed {
						flags |= 0x80000000
						sequence = 0
					}
					e.u32(sequence)
					e.u32(flags)
					e.u32(0)
					e.u64(1)
					e.opaque([]byte("server"))
					e.opaque([]byte("scope"))
					e.u32(0)
				case 43:
					d.u64()
					sequence := d.u32()
					requests = append(requests, sequence)
					d.take(68)
					if sequence != next {
						return nil, Status(10063), nil
					}
					next++
					confirmed = true
					e = createSequenceReply(sequence)
				case 44:
					d.take(16)
				default:
					return nil, 0, fmt.Errorf("unexpected DS operation %d", code)
				}
				return e, 0, nil
			})
			v.exchangeRole = 0x40000
			for i := 0; i < 3; i++ {
				if err := v.initialize(context.Background()); err != nil {
					t.Fatalf("session %d: %v; sent %v", i, err, requests)
				}
				v.close(context.Background())
			}
			if fmt.Sprint(requests) != "[22 23 24]" {
				t.Fatal(requests)
			}
		})
	}
}

type createSequenceServer struct {
	mu                 sync.Mutex
	next               uint32
	confirmed          bool
	clientID           uint64
	owner, scope       string
	minorID            uint64
	requests           []uint32
	failure            string
	checkHandle        func([]byte) error
	trunk              bool
	trunkFailure       string
	bindings, destroys int
	slot               uint32
	session            []byte
}

func (s *createSequenceServer) peer(t *testing.T, minor uint32, parent *v4Client, role uint32, read ...operationReply4) *v4Client {
	t.Helper()
	v := peer4WithHandle(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var e encoder
		switch code {
		case 42:
			if !bytes.Equal(d.take(8), bytes.Repeat([]byte{6}, 8)) || d.str() != fmt.Sprintf("nfs-viewer-%x", bytes.Repeat([]byte{6}, 16)) {
				return nil, 0, errors.New("client incarnation changed")
			}
			d.take(12)
			e.u64(s.clientID)
			if s.confirmed {
				e.u32(0) // Ignored even if the next real sequence is nonzero.
				e.u32(role | 0x80000000)
			} else {
				e.u32(s.next)
				e.u32(role)
			}
			e.u32(0)
			e.u64(s.minorID)
			e.opaque([]byte(s.owner))
			e.opaque([]byte(s.scope))
			e.u32(0)
		case 43:
			if d.u64() != s.clientID {
				return nil, 0, errors.New("wrong client ID")
			}
			sequence := d.u32()
			s.requests = append(s.requests, sequence)
			d.take(68)
			if sequence != s.next {
				return nil, Status(10063), nil
			}
			s.next++
			s.confirmed = true
			switch s.failure {
			case "status":
				return nil, Status(10018), nil
			case "truncated":
				return nil, 0, nil
			case "mismatch":
				return createSequenceReply(sequence + 1), 0, nil
			}
			e = createSequenceReply(sequence)
			if s.trunk {
				s.session, s.slot = append([]byte(nil), e[:16]...), 1
			}
		case 41:
			if !s.trunk || !bytes.Equal(d.take(16), s.session) || d.u32() != 1 || d.boolean() {
				return nil, 0, errors.New("invalid trunk bind request")
			}
			s.bindings++
			if s.trunkFailure == "status" {
				return nil, Status(10052), nil
			}
			if s.trunkFailure == "truncated" {
				return nil, 0, nil
			}
			e = append(e, s.session...)
			if s.trunkFailure == "session" {
				e[0] ^= 1
			}
			direction := uint32(1)
			if s.trunkFailure == "direction" {
				direction = 3
			}
			e.u32(direction)
			rdma := uint32(0)
			if s.trunkFailure == "rdma" {
				rdma = 1
			}
			e.u32(rdma)
		case 44:
			d.take(16)
			s.destroys++
		case 53:
			id, slot := d.take(16), d.u32()
			if s.trunk {
				if !bytes.Equal(id, s.session) || slot != s.slot {
					return nil, 0, fmt.Errorf("shared slot mismatch: got %d want %d", slot, s.slot)
				}
				s.slot++
			}
			e = append(e, id...)
			e.u32(slot)
			d.take(12)
			for range 4 {
				e.u32(0)
			}
		case 58:
			d.boolean()
		case 24:
		case 10:
			e.opaque([]byte("root"))
		case 25, 38, 5:
			if len(read) == 0 {
				return nil, 0, errors.New("unexpected data-server I/O")
			}
			return read[0](code, d)
		default:
			return nil, 0, fmt.Errorf("unexpected operation %d (must not destroy shared client ID)", code)
		}
		return e, 0, nil
	}, s.checkHandle)
	v.clientNonce = bytes.Repeat([]byte{6}, 16)
	v.exchangeRole = role
	if parent != nil {
		v.creates = parent.sessionSequences()
	}
	return v
}

func TestV4CreateSessionIdentityAndTemporaryClients(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, distinction := range []string{"same-server", "different-minor-id", "different-owner", "different-scope", "different-client-id", "wrap"} {
			t.Run(fmt.Sprintf("%d/%s", minor, distinction), func(t *testing.T) {
				ctx := context.Background()
				mds := &createSequenceServer{next: 22, clientID: 123, owner: "mds", scope: "scope"}
				if distinction == "wrap" {
					mds.next = ^uint32(0)
				}
				parent := mds.peer(t, minor, nil, 0x20000)
				if err := parent.initialize(ctx); err != nil {
					t.Fatal(err)
				}
				ds := mds
				switch distinction {
				case "different-minor-id":
					mds.minorID++
				case "different-owner":
					ds = &createSequenceServer{next: 75, clientID: 123, owner: "ds", scope: "scope"}
				case "different-scope":
					ds = &createSequenceServer{next: 75, clientID: 123, owner: "mds", scope: "other"}
				case "different-client-id":
					ds = &createSequenceServer{next: 75, clientID: 456, owner: "mds", scope: "scope"}
				}
				for range 3 {
					client := ds.peer(t, minor, parent, 0x40000)
					if err := client.initialize(ctx); err != nil {
						t.Fatal(err)
					}
					client.close(ctx)
					// The original MDS session must remain usable after DS cleanup.
					if err := parent.compound(ctx); err != nil {
						t.Fatal(err)
					}
				}
				want := "[22 23 24 25]"
				if ds != mds {
					want = "[75 76 77]"
				}
				if distinction == "wrap" {
					want = "[4294967295 0 1 2]"
				}
				if fmt.Sprint(ds.requests) != want {
					t.Fatal(ds.requests)
				}
			})
		}
	}
}

func TestV4CreateSessionUnknownSequenceRefusesReplay(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, failure := range []string{"unknown-confirmed", "status", "truncated", "mismatch"} {
			t.Run(fmt.Sprintf("%d/%s", minor, failure), func(t *testing.T) {
				s := &createSequenceServer{next: 22, clientID: 123, owner: "server", scope: "scope", failure: failure}
				s.confirmed = failure == "unknown-confirmed"
				v := s.peer(t, minor, nil, 0x40000)
				if err := v.initialize(context.Background()); err == nil {
					t.Fatal("bad reply accepted")
				}
				s.failure = ""
				v2 := s.peer(t, minor, v, 0x40000)
				if err := v2.initialize(context.Background()); err == nil || !strings.Contains(err.Error(), "sequence is unknown") {
					t.Fatal(err)
				}
				want := 1
				if failure == "unknown-confirmed" {
					want = 0
				}
				if len(s.requests) != want {
					t.Fatalf("unsafe replay: %v", s.requests)
				}
				// A new unconfirmed server incarnation establishes its own slot.
				s.clientID, s.next, s.confirmed = s.clientID+1, 91, false
				v3 := s.peer(t, minor, v, 0x40000)
				if err := v3.initialize(context.Background()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestV4CreateSessionConcurrentEndpoints(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			s := &createSequenceServer{next: 22, clientID: 123, owner: "server", scope: "scope"}
			parent := s.peer(t, minor, nil, 0x20000)
			if err := parent.initialize(context.Background()); err != nil {
				t.Fatal(err)
			}
			var clients []*v4Client
			for range 16 {
				clients = append(clients, s.peer(t, minor, parent, 0x40000))
			}
			var wg sync.WaitGroup
			for _, v := range clients {
				wg.Go(func() {
					if err := v.initialize(context.Background()); err != nil {
						t.Error(err)
						return
					}
					v.close(context.Background())
				})
			}
			wg.Wait()
			if len(s.requests) != 17 {
				t.Fatal(s.requests)
			}
			for i, n := range s.requests {
				if n != uint32(22+i) {
					t.Fatal(s.requests)
				}
			}
			if err := parent.compound(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV4CreateSessionCancelledWait(t *testing.T) {
	s := (&v4Client{}).sessionSequences()
	if err := s.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.lock(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-s.gate
}

func createSequenceReply(sequence uint32) encoder {
	e := encoder(bytes.Repeat([]byte{9}, 16))
	e.u32(sequence)
	e.u32(0)
	for range 2 {
		for _, n := range []uint32{0, 1 << 20, 1 << 20, 65536, 16, 1, 0} {
			e.u32(n)
		}
	}
	return e
}
