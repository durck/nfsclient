package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPNFSWriteBatchOverlap(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"ok", "short", "mds-commit", "bad-verifier", "bad-count", "commit-error", "recall"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var arrived atomic.Int32
				barrier := make(chan struct{})
				var batch []*pnfsWrite
				var recalled atomic.Bool
				sid := bytes.Repeat([]byte{7}, 16)
				clear(sid[:4])
				for i := 0; i < 3; i++ {
					seen := 0
					writes := 0
					commits := 0
					ds := peer4WithHandle(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
						var e encoder
						switch code {
						case 38:
							if !bytes.Equal(d.take(16), sid) || d.u64() != uint64(100+seen) || d.u32() != 0 {
								return nil, 0, errors.New("wrong write request")
							}
							data := d.opaque(100)
							if !bytes.Equal(data, bytes.Repeat([]byte{byte(i)}, 12-seen)) {
								return nil, 0, errors.New("wrong stripe bytes")
							}
							if writes == 0 {
								if arrived.Add(1) == 3 {
									close(barrier)
								}
								select {
								case <-barrier:
								case <-ctx.Done():
									return nil, 0, ctx.Err()
								}
							}
							writes++
							n := len(data)
							if mode == "short" || mode == "bad-verifier" {
								n = min(n, 5)
							}
							seen += n
							e.u32(uint32(n))
							if mode == "bad-count" {
								e = nil
								e.u32(0)
							}
							e.u32(0)
							verifier := bytes.Repeat([]byte{1}, 8)
							if mode == "bad-verifier" && writes > 1 {
								verifier[0] = 2
							}
							e = append(e, verifier...)
							if mode == "recall" {
								recalled.Store(true)
							}
						case 5:
							commits++
							off, n := d.u64(), d.u32()
							if mode == "mds-commit" || off+uint64(n) != uint64(100+seen) {
								return nil, 0, errors.New("wrong DS COMMIT")
							}
							if mode == "commit-error" {
								return nil, 5, nil
							}
							e = append(e, bytes.Repeat([]byte{1}, 8)...)
						default:
							return nil, 0, fmt.Errorf("unexpected op %d", code)
						}
						return e, 0, nil
					}, nil, mode == "bad-verifier" || mode == "bad-count" || mode == "commit-error")
					batch = append(batch, &pnfsWrite{ds: ds.c, handle: []byte{byte(i)}, physical: 100, logical: uint64(i * 12), data: bytes.Repeat([]byte{byte(i)}, 12), mdsCommit: mode == "mds-commit"})
				}
				issued, err := writePNFSBatch(ctx, batch, sid, func(allowRecall bool) error {
					if recalled.Load() && !allowRecall {
						return errors.New("recalled")
					}
					return nil
				})
				success := mode == "ok" || mode == "short" || mode == "mds-commit" || mode == "recall"
				if !issued || (err == nil) != success {
					t.Fatal(issued, err)
				}
				if success {
					for _, w := range batch {
						if !bytes.Equal(w.verifier, bytes.Repeat([]byte{1}, 8)) {
							t.Fatal("verifier missing")
						}
						if mode == "mds-commit" && (len(w.commits) != 1 || w.commits[0].offset != w.logical || w.commits[0].length != 12) {
							t.Fatal("MDS durability ranges lost")
						}
					}
				}
			})
		}
	}
}

func TestPNFSWriteParallelPlacement(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, dense := range []bool{false, true} {
			for _, mode := range []string{"ok", "short", "mds-commit", "grow", "mds-failure", "layout-failure", "source-error", "verifier-change", "recall", "cancel"} {
				t.Run(fmt.Sprintf("4.%d/dense=%t/%s", minor, dense, mode), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					sid := bytes.Repeat([]byte{7}, 16)
					clear(sid[:4])
					layoutSID := bytes.Repeat([]byte{8}, 16)
					source := make([]byte, 257)
					for i := range source {
						source[i] = byte(i*7 + 3)
					}
					var writes, commits, layouts atomic.Int32
					var arrived atomic.Int32
					barrier := make(chan struct{})
					var recalled atomic.Bool
					endpoints := map[string]*Client{}
					for server := 0; server < 2; server++ {
						received := 0
						ds := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
							var e encoder
							switch code {
							case 38:
								if !bytes.Equal(d.take(16), sid) {
									return nil, 0, errors.New("stateid")
								}
								physical := d.u64()
								if d.u32() != 0 {
									return nil, 0, errors.New("stability")
								}
								data := d.opaque(64)
								logical := physical
								if dense {
									logical = (physical/64*2+uint64(server))*64 + physical%64
								}
								if logical/64%2 != uint64(server) || logical+uint64(len(data)) > 257 || !bytes.Equal(data, source[logical:logical+uint64(len(data))]) {
									return nil, 0, errors.New("stripe placement")
								}
								if received == 0 {
									if arrived.Add(1) == 2 {
										close(barrier)
									}
									select {
									case <-barrier:
									case <-ctx.Done():
										return nil, 0, ctx.Err()
									}
								}
								n := len(data)
								if mode == "short" {
									n = min(n, 7)
								}
								received += n
								writes.Add(1)
								e.u32(uint32(n))
								e.u32(0)
								v := bytes.Repeat([]byte{1}, 8)
								if mode == "verifier-change" && logical >= 128 {
									v[0] = 2
								}
								e = append(e, v...)
							case 5:
								if mode == "mds-commit" || mode == "mds-failure" {
									return nil, 0, errors.New("wrong COMMIT route")
								}
								d.u64()
								d.u32()
								commits.Add(1)
								v := bytes.Repeat([]byte{1}, 8)
								if mode == "verifier-change" && received > 64 {
									v[0] = 2
								}
								e = append(e, v...)
							default:
								return nil, 0, fmt.Errorf("unexpected DS op %d", code)
							}
							return e, 0, nil
						})
						endpoints[fmt.Sprint(server)] = ds.c
					}
					confirmed := uint64(0)
					mds := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
						var e encoder
						switch code {
						case 5:
							off, n := d.u64(), d.u32()
							if off%64 != 0 || n == 0 || n > 64 {
								return nil, 0, errors.New("MDS commit bounds")
							}
							if mode == "mds-failure" {
								return nil, 5, nil
							}
							commits.Add(1)
							e = append(e, bytes.Repeat([]byte{1}, 8)...)
						case 49:
							off, n := d.u64(), d.u64()
							if off != confirmed || n != min(uint64(128), 257-confirmed) || d.boolean() || !bytes.Equal(d.take(16), layoutSID) || !d.boolean() || d.u64() != off+n-1 || d.boolean() || d.u32() != 1 || len(d.opaque(64)) != 0 {
								return nil, 0, errors.New("layout commit ordering/bounds")
							}
							if mode == "layout-failure" {
								return nil, 5, nil
							}
							confirmed += n
							layouts.Add(1)
							e.u32(1)
							size := uint64(300)
							if mode == "grow" {
								size = confirmed
							}
							e.u64(size)
						default:
							return nil, 0, fmt.Errorf("unexpected MDS op %d", code)
						}
						return e, 0, nil
					})
					mds.recall = &layoutRecall{state: layoutSID}
					mds.c.WriteSize = 64
					for _, ds := range endpoints {
						ds.WriteSize = 64
					}
					util := uint32(64)
					if dense {
						util |= 1
					}
					if mode == "mds-commit" || mode == "mds-failure" {
						util |= 2
					}
					layout := &fileLayout{length: ^uint64(0), util: util, indices: []uint32{0, 1}, handles: [][]byte{[]byte("a"), []byte("b")}, endpoints: [][]string{{"0"}, {"1"}}}
					input := source
					if mode == "source-error" {
						input = source[:70]
					}
					size := uint64(300)
					if mode == "grow" {
						size = 0
					}
					progress := uint64(0)
					n, pending, err := mds.c.writePNFSParallel(ctx, []byte("file"), sid, 0, 257, size, bytes.NewReader(input), []*fileLayout{layout}, 8, func(paths []string) (*Client, string, error) { return endpoints[paths[0]], paths[0], nil }, func(allowRecall bool) error {
						if recalled.Load() && !allowRecall {
							return errors.New("recalled")
						}
						return nil
					}, func(done uint64) {
						if done != confirmed || done <= progress {
							t.Error("progress before durability")
						}
						progress = done
						if mode == "recall" {
							recalled.Store(true)
						}
						if mode == "cancel" {
							cancel()
						}
					})
					success := mode == "ok" || mode == "short" || mode == "mds-commit" || mode == "grow"
					if success {
						if err != nil || pending || n != 257 || progress != 257 || layouts.Load() != 3 {
							t.Fatal(n, pending, err, progress, layouts.Load())
						}
					} else if err == nil {
						t.Fatal("missing failure")
					}
					if mode == "source-error" && (n != 0 || pending || writes.Load() != 0) {
						t.Fatal("mutation before batch source read")
					}
					if (mode == "recall" || mode == "cancel") && (n != 128 || pending || layouts.Load() != 1) {
						t.Fatal("lost completed batch", n, pending)
					}
					if (mode == "mds-failure" || mode == "layout-failure") && (!pending || n != 0) {
						t.Fatal("undurable batch counted", n, pending)
					}
					if mode == "verifier-change" && (!pending || n != 128) {
						t.Fatal("restarted DS not quarantined", n, pending)
					}
				})
			}
		}
	}
}

func TestPNFSWriteBatchCancelsAndJoins(t *testing.T) {
	for _, mode := range []string{"status", "cancel", "recall-short"} {
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
				io.Copy(io.Discard, server)
			}()
			stalled := &Client{nfs: &rpcClient{conn: client, timeout: 30 * time.Second}}
			stalled.v4 = &v4Client{c: stalled, minor: 1}
			var recalled atomic.Bool
			replied := make(chan struct{})
			other := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 38 {
					return nil, 0, errors.New("unexpected op")
				}
				d.take(16)
				d.u64()
				d.u32()
				d.opaque(64)
				select {
				case <-entered:
				case <-time.After(time.Second):
					return nil, 0, errors.New("no overlap")
				}
				close(replied)
				if mode == "status" {
					return nil, 13, nil
				}
				if mode == "recall-short" {
					recalled.Store(true)
				}
				var e encoder
				if mode == "cancel" {
					e.u32(2)
				} else {
					e.u32(1)
				}
				e.u32(2)
				e = append(e, bytes.Repeat([]byte{1}, 8)...)
				return e, 0, nil
			})
			batch := []*pnfsWrite{{ds: stalled, handle: []byte("a"), data: []byte("aa")}, {ds: other.c, handle: []byte("b"), data: []byte("bb")}}
			finished := make(chan error, 1)
			go func() {
				issued, err := writePNFSBatch(ctx, batch, bytes.Repeat([]byte{0}, 16), func(allow bool) error {
					if recalled.Load() && !allow {
						return errors.New("recall")
					}
					return nil
				})
				if !issued {
					err = errors.New("issued state lost")
				}
				finished <- err
			}()
			if mode == "cancel" {
				<-replied
				other.mu.Lock()
				//lint:ignore SA2001 Acquiring the mutex waits for the in-flight operation to finish.
				other.mu.Unlock()
				cancel()
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("lost failure")
				}
			case <-time.After(2 * time.Second):
				client.Close()
				<-finished
				t.Fatal("stalled WRITE not cancelled and joined")
			}
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("worker leaked")
			}
		})
	}
}
