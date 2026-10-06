package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

// Session namespace validation happens after the public client reclaim has
// finished. A successful final GETATTR can still revoke the recovered locks.
func TestSessionReclaimRejectsFinalStateLoss(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, flag := range []uint32{0, 0x8, 0x80, 0x100} {
			t.Run(fmt.Sprintf("4.%d/flag-%x", minor, flag), func(t *testing.T) {
				x := &migrationEvidence{}
				origin := &migrationWirePeer{origin: true, mode: "not-moved", evidence: x}
				target := &migrationWirePeer{origin: true, mode: "not-moved", evidence: x}
				origin.base.minor, target.base.minor = minor, minor
				origin.base.operationHook = origin.operation
				var injected atomic.Bool
				target.base.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
					switch code {
					case 42:
						e, status, err, handled := target.operation(code, d, current)
						binary.BigEndian.PutUint64(e, 456)
						return e, status, err, handled
					case 18:
						if d.word() != 0 || d.word() != 1 || d.word() != 0 || !bytes.Equal(d.take(8), blockCLIQuad(nil, 456)) || !bytes.Equal(d.opaque(), x.locks[0].owner) || d.word() != 0 || d.word() != 1 || d.word() != 0 {
							return nil, 0, errors.New("expected previous OPEN reclaim"), true
						}
						return missingV4Words(bytes.Clone(x.locks[0].open), 1, 0, 1, 0, 1, 0, 0, 0), 0, nil, true
					case 12:
						//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
						if d.word() != 1 || d.word() != 1 || !bytes.Equal(d.take(8), blockCLIQuad(nil, 0)) || !bytes.Equal(d.take(8), blockCLIQuad(nil, nfs.LockToEOF)) || d.word() != 1 || d.word() != 1 || !bytes.Equal(d.take(16), x.locks[0].open) || d.word() != 0 || !bytes.Equal(d.take(8), blockCLIQuad(nil, 456)) {
							return nil, 0, errors.New("expected previous LOCK reclaim"), true
						}
						d.opaque()
						return bytes.Clone(x.locks[0].lock), 0, nil, true
					case 53:
						peek := &missingV4Decoder{b: d.b}
						peek.take(32)
						final := peek.word() == 22 && string(peek.opaque()) == "/data/file" && peek.word() == 9
						e, status, err, handled := target.operation(code, d, current)
						if final {
							injected.Store(true)
							binary.BigEndian.PutUint32(e[len(e)-4:], flag)
						}
						return e, status, err, handled
					}
					return target.operation(code, d, current)
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					if err := origin.base.serve(listener); err != nil {
						done <- err
						return
					}
					done <- target.base.serve(listener)
				}()
				var client *nfs.Client
				t.Cleanup(func() {
					if client != nil {
						client.Close()
					}
					listener.Close()
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, err = nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", NFSPort: listener.Addr().(*net.TCPAddr).Port, Version: fmt.Sprintf("4.%d", minor), Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(client, "127.0.0.1", false, false, io.Discard)
				if err := s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				id, err := s.LockRange(ctx, "file", false, 0, nfs.LockToEOF)
				if err != nil {
					t.Fatal(err)
				}
				old := s.Client
				err = s.Reclaim(ctx)
				client = s.Client
				if !injected.Load() {
					t.Fatal("did not reach final namespace validation")
				}
				if flag == 0 {
					if err != nil || s.Client == old || len(s.Client.Locks()) != 1 || s.Client.Locks()[0].Uncertain || s.LockPaths[id] != "/file" {
						t.Fatal("healthy session reclaim failed", err)
					}
				} else {
					if !errors.Is(err, nfs.ErrLockUncertain) || s.Client != old {
						t.Fatal("quarantined recovered client published", err)
					}
					if len(old.Locks()) != 1 || !old.Locks()[0].Uncertain || s.LockPaths[id] != "/file" {
						t.Fatal("old uncertain inventory was lost")
					}
				}
			})
		}
	}
}
