package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A distinct DS peer rejects MDS operations and checks the globally valid
// OPEN stateid, zero DS seqid and common client owner on actual wire requests.
func TestPNFSReadWire(t *testing.T) {
	for _, mode := range []string{"ok", "unapproved", "denied", "short", "recall", "writer", "return-failure", "return-revoked", "bad-layout", "verify-failure", "verify-recall", "verify-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			nonce := bytes.Repeat([]byte{6}, 16)
			openSID := bytes.Repeat([]byte{7}, 16)
			layoutSID := bytes.Repeat([]byte{8}, 16)
			var reads, returned, closed atomic.Int32
			var v *v4Client
			ds := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 42:
					if !bytes.Equal(d.take(8), nonce[:8]) || d.str() != fmt.Sprintf("nfs-viewer-%x", nonce) || d.u32() != 0x40000 || d.u32() != 0 || d.u32() != 0 {
						return nil, 0, errors.New("DS client owner/role differs from MDS")
					}
					e.u64(123) // May equal the MDS client ID.
					e.u32(2)
					e.u32(0x40000)
					e.u32(0)
					e.u64(1)
					e.opaque([]byte("server"))
					e.opaque([]byte("scope"))
					e.u32(0)
				case 43:
					d.u64()
					d.u32()
					d.u32()
					d.take(56)
					d.u32()
					d.u32()
					e = append(e, bytes.Repeat([]byte{9}, 16)...)
					e.u32(2)
					e.u32(0)
					for range 2 {
						e.u32(0)
						e.u32(1 << 20)
						e.u32(1 << 20)
						e.u32(65536)
						e.u32(16)
						e.u32(1)
						e.u32(0)
					}
				case 53:
					e = append(e, d.take(16)...)
					e.u32(d.u32())
					d.take(12)
					for range 4 {
						e.u32(0)
					}
				case 25:
					reads.Add(1)
					if d.u32() != 0 || !bytes.Equal(d.take(12), openSID[4:]) {
						return nil, 0, errors.New("DS READ must use OPEN other with seqid zero")
					}
					offset, count := d.u64(), d.u32()
					if offset >= 128 || count != 64 {
						return nil, 0, errors.New("bad DS stripe range")
					}
					if mode == "denied" {
						return nil, Status(13), nil
					}
					if mode == "short" {
						e.u32(1)
						e.opaque(nil)
						break
					}
					if mode == "recall" {
						v.recall.mu.Lock()
						v.recall.recalled = true
						v.recall.mu.Unlock()
					}
					e.u32(0)
					e.opaque(bytes.Repeat([]byte{'x'}, int(count)))
				case 44:
					d.take(16)
				default:
					return nil, 0, fmt.Errorf("unexpected DS operation %d (no MDS I/O or client-ID destruction)", code)
				}
				return e, 0, nil
			})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			bridgeDone := make(chan struct{})
			go func() {
				defer close(bridgeDone)
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				defer ds.c.nfs.conn.Close()
				upDone := make(chan struct{})
				go func() { io.Copy(ds.c.nfs.conn, c); ds.c.nfs.conn.Close(); close(upDone) }()
				io.Copy(c, ds.c.nfs.conn)
				c.Close()
				<-upDone
			}()
			t.Cleanup(func() { listener.Close(); <-bridgeDone })
			v = peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 18:
					d.take(12)
					d.u64()
					d.opaque(128)
					d.u32()
					d.u32()
					d.str()
					e = append(e, openSID...)
					e.u32(1)
					e.u64(1)
					e.u64(1)
					e.u32(0)
					e.u32(0)
					e.u32(0)
				case 10:
					e.opaque([]byte("file"))
				case 50:
					if d.u32() != 0 || d.u32() != 1 || d.u32() != 1 || d.u64() != 0 || d.u64() != ^uint64(0) || d.u64() != 1 || !bytes.Equal(d.take(16), openSID) || d.u32() != 32768 {
						return nil, 0, errors.New("bad LAYOUTGET")
					}
					e.u32(1)
					e = append(e, layoutSID...)
					e.u32(1)
					e.u64(0)
					e.u64(^uint64(0))
					e.u32(1)
					e.u32(1)
					body := encoder(make([]byte, 16))
					body.u32(64)
					body.u32(0)
					body.u64(0)
					body.u32(1)
					body.opaque([]byte("ds-file"))
					if mode == "bad-layout" {
						body = append(body, 1)
					}
					e.opaque(body)
				case 47:
					d.take(16)
					d.take(12)
					var body encoder
					body.u32(1)
					body.u32(0)
					body.u32(1)
					body.u32(1)
					body.str("tcp")
					body.str("192.0.2.10.8.1")
					e.u32(1)
					e.opaque(body)
					e.u32(0)
				case 51:
					returned.Add(1)
					if d.u32() != 0 || d.u32() != 1 || d.u32() != 3 || d.u32() != 1 || d.u64() != 0 || d.u64() != ^uint64(0) || !bytes.Equal(d.take(16), layoutSID) || len(d.opaque(64)) != 0 {
						return nil, 0, errors.New("bad LAYOUTRETURN")
					}
					if mode == "return-failure" {
						return nil, Status(10025), nil
					}
					if mode == "return-revoked" {
						v.stateLost.Store(true)
					}
					e.u32(0)
				case 4:
					closed.Add(1)
					d.u32()
					d.take(16)
					e = append(e, openSID...)
				default:
					return nil, 0, fmt.Errorf("unexpected MDS operation %d (no READ fallback)", code)
				}
				return e, 0, nil
			})
			v.clientNonce = nonce
			v.recall = &layoutRecall{}
			v.c.config = &Config{Timeout: time.Second, PNFS: true}
			options := PNFSOptions{DataServers: map[string]string{"192.0.2.10:2049": listener.Addr().String()}}
			if mode == "unapproved" {
				options.DataServers = map[string]string{"192.0.2.11:2049": listener.Addr().String()}
			}
			var out bytes.Buffer
			var writer io.Writer = &out
			if mode == "writer" {
				writer = pnfsShortWriter{}
			}
			verified := false
			n, err := v.c.ReadPNFSToProgressVerified(ctx, []byte("file"), 128, writer, options, nil, func() error {
				verified = true
				if reads.Load() != 2 || returned.Load() != 0 || closed.Load() != 0 || out.Len() != 128 {
					t.Fatal("verification must follow complete reads and precede state cleanup")
				}
				switch mode {
				case "verify-failure":
					return errors.New("source changed before layout return")
				case "verify-recall":
					v.recall.mu.Lock()
					v.recall.recalled = true
					v.recall.mu.Unlock()
				case "verify-cancel":
					cancel()
				}
				return nil
			})
			wantVerified := mode == "ok" || mode == "short" || mode == "return-failure" || mode == "return-revoked" || strings.HasPrefix(mode, "verify-")
			if verified != wantVerified {
				t.Fatal("verification path", mode, verified)
			}
			if mode == "ok" || mode == "short" {
				want := strings.Repeat("x", 128)
				if mode == "short" {
					want = string(make([]byte, 128))
				}
				if err != nil || n != 128 || out.String() != want || reads.Load() != 2 {
					t.Fatal(n, err, reads.Load())
				}
			} else if err == nil {
				t.Fatal("expected refusal", mode)
			}
			if mode != "bad-layout" && returned.Load() != 1 {
				t.Fatal("layout not returned exactly once", returned.Load())
			}
			if mode != "bad-layout" && mode != "return-failure" && mode != "return-revoked" && closed.Load() != 1 {
				t.Fatal("OPEN not closed", closed.Load())
			}
			if mode == "unapproved" || mode == "bad-layout" {
				if reads.Load() != 0 {
					t.Fatal("unapproved DS read")
				}
			}
		})
	}
}

type pnfsShortWriter struct{}

func (pnfsShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
