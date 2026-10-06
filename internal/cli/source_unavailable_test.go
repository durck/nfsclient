package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func TestSourceUnavailableRetainedSession(t *testing.T) {
	for _, mode := range []string{"valid-write", "unconfirmed", "scope", "owner", "lost-lock", "path"} {
		t.Run(mode, func(t *testing.T) {
			policy, tlsServer := referralTLSPolicy(t)
			evidence := &migrationEvidence{}
			payload := []byte("retained state across explicitly approved replica")
			origin := &migrationWirePeer{origin: true, mode: "not-moved", evidence: evidence, metadata: referralWirePeer{data: payload}}
			target := &migrationWirePeer{recovery: true, mode: mode, evidence: evidence, metadata: referralWirePeer{data: payload}}
			if mode == "owner" {
				target.recovery = false
			}
			var unavailable atomic.Bool
			var sourceRPCs atomic.Int32
			var listeners []net.Listener
			var done []chan error
			start := func(p *migrationWirePeer) string {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listeners = append(listeners, listener)
				p.base.minor = 1
				p.base.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
					if p.origin && unavailable.Load() {
						sourceRPCs.Add(1)
						return nil, 0, errors.New("source is unavailable"), true
					}
					return p.operation(code, d, current)
				}
				ch := make(chan error, 1)
				done = append(done, ch)
				go func() { ch <- p.base.serve(&referralTLSListener{Listener: listener, config: tlsServer}) }()
				return listener.Addr().String()
			}
			originAddress, targetAddress := start(origin), start(target)
			var c *nfs.Client
			t.Cleanup(func() {
				if c != nil {
					c.Close()
				}
				for _, l := range listeners {
					l.Close()
				}
				for _, ch := range done {
					if err := <-ch; err != nil {
						t.Error(err)
					}
				}
			})
			_, port, _ := net.SplitHostPort(originAddress)
			number, _ := strconv.Atoi(port)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var err error
			c, err = nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", NFSPort: number, Version: "4.1", Timeout: time.Second, TLS: policy})
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
			before := c.Locks()
			old := c
			unavailable.Store(true)
			err = s.FailoverLocks(ctx, session.ReferralTarget{Server: "approved.test", Target: nfs.ReadReplica{Address: targetAddress, TLSName: "referral.test"}})
			if (err == nil) != (mode == "valid-write") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			if sourceRPCs.Load() != 0 {
				t.Fatal("source RPC was required by unavailable-source failover")
			}
			if origin.opens.Load() != 1 || origin.locks.Load() != 1 || target.opens.Load() != 0 || target.locks.Load() != 0 {
				t.Fatal("replacement OPEN/LOCK issued")
			}
			if err != nil {
				if s.Client != old || len(old.Locks()) != 1 || !old.Locks()[0].Uncertain {
					t.Fatal("failed target lost quarantined inventory")
				}
				return
			}
			c = s.Client
			if c == old || s.Export != "/data" || !reflect.DeepEqual(before, c.Locks()) {
				t.Fatal("confirmed inventory changed")
			}
			var read bytes.Buffer
			if _, err = s.Cat(ctx, "file", &read); err != nil || !bytes.Equal(read.Bytes(), payload) {
				t.Fatal(fmt.Errorf("retained locked read: %w", err))
			}
			if err = c.Unlock(ctx, id); err != nil || target.unlocks.Load() != 1 {
				t.Fatalf("unlock: %v", err)
			}
		})
	}
}
