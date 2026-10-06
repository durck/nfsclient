package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestAutomaticStatefulSameSessionFailover(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"applied", "not-applied", "read", "denied", "uncached", "scope", "unconfirmed", "no-session"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				policy, tlsServer := referralTLSPolicy(t)
				x := &migrationEvidence{}
				payload := bytes.Repeat([]byte("original locked data"), 8)
				origin := &migrationWirePeer{origin: true, recovery: true, mode: "not-moved", evidence: x, metadata: referralWirePeer{data: bytes.Clone(payload)}}
				target := &migrationWirePeer{recovery: true, mode: mode, evidence: x, metadata: referralWirePeer{data: bytes.Clone(payload)}}
				if mode == "applied" || mode == "not-applied" || mode == "read" || mode == "denied" {
					target.mode = "valid-read"
				}
				var mu sync.Mutex
				var originalSeq, originalArgs, cachedReply []byte
				var cachedStatus uint32
				replayed := false
				operation := uint32(38)
				if mode == "read" {
					operation = 25
				}
				origin.base.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
					if code == 53 {
						peek := &missingV4Decoder{b: d.b}
						peek.take(32)
						if peek.word() == 22 {
							peek.opaque()
							if peek.word() == operation {
								mu.Lock()
								originalSeq = bytes.Clone(d.b)
								mu.Unlock()
								if mode == "not-applied" {
									return nil, 0, io.EOF, true
								}
							}
						}
					}
					if code == operation {
						mu.Lock()
						defer mu.Unlock()
						originalArgs = bytes.Clone(d.b)
						if mode == "denied" {
							cachedStatus = 13
						} else {
							var err error
							cachedReply, cachedStatus, err, _ = origin.operation(code, d, current)
							if err != nil {
								return nil, 0, err, true
							}
							copy(target.metadata.data, origin.metadata.data)
						}
						return nil, 0, io.EOF, true
					}
					return origin.operation(code, d, current)
				}
				target.base.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
					if code == 53 && !replayed {
						mu.Lock()
						equal := bytes.Equal(d.b, originalSeq)
						mu.Unlock()
						if !equal {
							return nil, 0, errors.New("automatic failover changed original sequence or operations"), true
						}
						if mode == "not-applied" {
							return target.operation(code, d, current)
						}
						id := bytes.Clone(d.take(16))
						seq := d.word()
						slot, highest, cache := d.word(), d.word(), d.word()
						if mode == "uncached" {
							return nil, 10068, nil, true
						}
						x.mu.Lock()
						want := x.next - 1
						x.mu.Unlock()
						if seq != want || slot != 0 || highest != 0 || cache != 1 {
							return nil, 0, errors.New("automatic failover did not replay cached slot"), true
						}
						return missingV4Words(id, seq, 0, 0, 0, 0), 0, nil, true
					}
					if code == operation && !replayed {
						replayed = true
						if mode == "not-applied" {
							return target.operation(code, d, current)
						}
						mu.Lock()
						defer mu.Unlock()
						if !bytes.Equal(d.b, originalArgs) {
							return nil, 0, errors.New("automatic replay changed mutation bytes"), true
						}
						d.take(uint32(len(d.b)))
						return bytes.Clone(cachedReply), cachedStatus, nil, true
					}
					return target.operation(code, d, current)
				}
				var listeners []net.Listener
				var done []chan error
				start := func(p *migrationWirePeer) string {
					l, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					listeners = append(listeners, l)
					p.base.minor = minor
					ch := make(chan error, 1)
					done = append(done, ch)
					go func() { ch <- p.base.serve(&referralTLSListener{Listener: l, config: tlsServer}) }()
					return l.Addr().String()
				}
				address, alternate := start(origin), start(target)
				var c *nfs.Client
				t.Cleanup(func() {
					if c != nil {
						c.Close()
					}
					for _, l := range listeners {
						l.Close()
					}
					for _, ch := range done {
						if err := <-ch; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
							t.Error(err)
						}
					}
				})
				_, port, _ := net.SplitHostPort(address)
				number, _ := strconv.Atoi(port)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var err error
				c, err = nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", NFSPort: number, Version: fmt.Sprintf("4.%d", minor), Timeout: time.Second, TLS: policy})
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(c, "127.0.0.1", false, false, io.Discard)
				if err = s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				id, err := s.LockRange(ctx, "file", true, 0, nfs.LockToEOF)
				if err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				sh := &Shell{Session: s, Out: &output, Err: &output}
				if _, err = sh.Execute(ctx, "migrate --arm-failover approved.test="+alternate+",,referral.test"); err != nil {
					t.Fatal(err)
				}
				if !c.StatefulFailoverStatus().Armed {
					t.Fatal("approval was not armed")
				}
				if err = s.SaveLocks(filepath.Join(t.TempDir(), "refused")); err == nil {
					t.Fatal("endpoint-bound journal combined with automatic failover")
				}
				fh, err := c.LockedFileHandle(id)
				if err != nil {
					t.Fatal(err)
				}
				patch := []byte("APPLIED")
				if mode == "read" {
					var b bytes.Buffer
					_, err = c.ReadTo(ctx, fh, &b)
					if err == nil && !bytes.Equal(b.Bytes(), payload) {
						t.Fatal("cached read differs")
					}
				} else {
					_, err = c.WriteRangeFromProgress(ctx, fh, 0, uint64(len(patch)), bytes.NewReader(patch), nil)
				}
				good := mode == "applied" || mode == "not-applied" || mode == "read" || mode == "denied"
				if (err == nil) != (good && mode != "denied") {
					t.Fatalf("unexpected failover result: %v", err)
				}
				status := c.StatefulFailoverStatus()
				if status.Armed || !status.Consumed {
					t.Fatal("approval was not consumed exactly once")
				}
				if c.Locks()[0].Uncertain == good {
					t.Fatal("cached outcome did not control state usability")
				}
				if origin.opens.Load() != 1 || origin.locks.Load() != 1 || target.opens.Load() != 0 || target.locks.Load() != 0 {
					t.Fatal("automatic failover created replacement OPEN/LOCK")
				}
				if good {
					if mode == "applied" || mode == "not-applied" {
						if origin.writes.Load()+target.writes.Load() != 1 || !bytes.Equal(target.metadata.data[:len(patch)], patch) {
							t.Fatal("mutation was duplicated or lost")
						}
					}
					if err = c.Unlock(ctx, id); err != nil || target.unlocks.Load() != 1 {
						t.Fatalf("retained unlock failed: %v", err)
					}
					if err = c.EnableStatefulFailover(nfs.ReadReplica{Address: address, TLSName: "referral.test"}); err != nil {
						t.Fatal("healthy session could not explicitly rearm:", err)
					}
				} else if err = c.EnableStatefulFailover(nfs.ReadReplica{Address: address, TLSName: "referral.test"}); err == nil {
					t.Fatal("uncertain session rearmed")
				}
			})
		}
	}
}
