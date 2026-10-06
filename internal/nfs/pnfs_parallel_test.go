package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPNFSParallelismBounds(t *testing.T) {
	for _, value := range []int{-1, 0, 1, 2, 8, 9, 1024} {
		options, err := validatePNFSOptions(PNFSOptions{DataServers: map[string]string{"192.0.2.1:2049": "127.0.0.1:2049"}, Parallelism: value})
		if value < 0 || value > 8 {
			if err == nil {
				t.Fatal("invalid parallelism accepted", value)
			}
		} else if err != nil || options.Parallelism != max(1, value) {
			t.Fatal(value, options.Parallelism, err)
		}
	}
}

func TestPNFSParallelCancelsAndJoinsStalledRPC(t *testing.T) {
	for _, mode := range []string{"status", "cancel", "recall"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			entered, exited := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(exited)
				defer server.Close()
				if _, err := readRecord(server); err != nil {
					return
				}
				close(entered)
				// Never send a reply. Only cancellation/close can end this RPC;
				// its normal 30-second timeout is longer than the test bound.
				io.Copy(io.Discard, server)
			}()
			stalled := &Client{nfs: &rpcClient{conn: client, timeout: 30 * time.Second}}
			stalled.v4 = &v4Client{c: stalled, minor: 1}
			var recalled atomic.Bool
			otherEntered := make(chan struct{})
			recallErr := errors.New("layout recalled")
			other := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 25 {
					return nil, 0, errors.New("unexpected operation")
				}
				d.take(16)
				d.u64()
				d.u32()
				select {
				case <-entered:
				case <-time.After(time.Second):
					return nil, 0, errors.New("stalled DS was not contacted concurrently")
				}
				close(otherEntered)
				if mode == "status" {
					return nil, Status(13), nil
				}
				if mode == "recall" {
					recalled.Store(true)
				}
				var e encoder
				e.u32(1)
				e.opaque([]byte("data"))
				return e, 0, nil
			})
			batch := []*pnfsRead{
				{ds: stalled, handle: []byte("a"), limit: 4},
				{ds: other.c, handle: []byte("b"), limit: 4},
			}
			finished := make(chan error, 1)
			go func() {
				finished <- readPNFSBatch(ctx, batch, bytes.Repeat([]byte{7}, 16), func() error {
					if recalled.Load() {
						return recallErr
					}
					return nil
				})
			}()
			if mode == "cancel" {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("RPC did not start")
				}
				// Wait until the second reply is consumed before cancellation,
				// so the strict scripted peer is not interrupted while writing.
				select {
				case <-otherEntered:
				case <-time.After(time.Second):
					t.Fatal("second RPC did not start")
				}
				other.mu.Lock()
				//lint:ignore SA2001 Acquiring the mutex waits for the in-flight operation to finish.
				other.mu.Unlock()
				cancel()
			}
			select {
			case err := <-finished:
				if err == nil || mode == "status" && !errors.Is(err, Status(13)) || mode == "recall" && !errors.Is(err, recallErr) {
					t.Fatal("lost failure", err)
				}
			case <-time.After(2 * time.Second):
				client.Close()
				<-finished
				t.Fatal("failed batch did not interrupt and join stalled RPC")
			}
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("stalled peer still active after return")
			}
		})
	}
}
