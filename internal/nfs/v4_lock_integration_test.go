package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"
)

// Actual TCP disconnect against the disposable six-second-lease MEM server.
// It is separate from the scripted malformed-reply and sequence tests.
func TestGaneshaLockDisconnect(t *testing.T) {
	portText := os.Getenv("NFS_VIEWER_TEST_PORT")
	if portText == "" {
		t.Skip("requires the disposable Ganesha fixture")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			cfg := Config{Host: "127.0.0.1", Version: version, NFSPort: port, Timeout: 3 * time.Second}
			a, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			root, err := a.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("lock-disconnect-%d", time.Now().UnixNano())
			n, err := a.Create(ctx, root.Handle, name, 0666, false)
			if err != nil {
				t.Fatal(err)
			}
			id, err := a.Lock(ctx, n.Handle, true)
			if err != nil {
				t.Fatal(err)
			}
			otherRoot, err := b.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			other, err := b.Lookup(ctx, otherRoot.Handle, name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Lock(ctx, other.Handle, false); !errors.Is(err, Status(10010)) {
				t.Fatal("initial conflict", err)
			}
			if err := a.nfs.conn.Close(); err != nil {
				t.Fatal(err)
			}
			if n, err := a.ReadTo(ctx, n.Handle, io.Discard); err == nil || n != 0 {
				t.Fatal("disconnected read", n, err)
			}
			if !a.Locks()[0].Uncertain {
				t.Fatal("lost lock not exposed")
			}
			if err := a.Unlock(ctx, id); !errors.Is(err, ErrLockUncertain) {
				t.Fatal(err)
			}
			if _, err := a.Reconnect(ctx); !errors.Is(err, ErrLocksHeld) {
				t.Fatal(err)
			}
			a.DiscardLocks()
			// A disconnect is not an unlock. Only the test retries a definitive
			// conflict to observe actual server lease cleanup; no mutation replay.
			var acquired uint64
			for {
				acquired, err = b.Lock(ctx, other.Handle, true)
				if err == nil {
					break
				}
				if !errors.Is(err, Status(10010)) || acquired != 0 {
					t.Fatal("lease cleanup", err)
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Second):
				}
			}
			if err := b.Unlock(ctx, acquired); err != nil {
				t.Fatal(err)
			}
			fresh, err := a.Reconnect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if len(fresh.Locks()) != 0 {
				t.Fatal("reconnect restored lock")
			}
			freshRoot, err := fresh.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			freshNode, err := fresh.Lookup(ctx, freshRoot.Handle, name)
			if err != nil {
				t.Fatal(err)
			}
			acquired, err = fresh.Lock(ctx, freshNode.Handle, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := fresh.Unlock(ctx, acquired); err != nil {
				t.Fatal(err)
			}
			if err := b.Remove(ctx, otherRoot.Handle, name); err != nil {
				t.Fatal(err)
			}
			t.Log("LOCK_DISCONNECT uncertain no_replay explicit_discard server_lease_cleanup fresh_lock")
		})
	}
}
