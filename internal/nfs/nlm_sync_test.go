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

	"nfs-viewer/internal/testutil/loopback"
)

func syncGrantCall(version uint32, l *nlmLock) encoder {
	var e encoder
	for _, v := range []uint32{123, 0, 2, nlmProgram, version, 5, 0, 0, 0, 0} {
		e.u32(v)
	}
	e.opaque([]byte("grant-cookie"))
	if l.info.Write {
		e.u32(1)
	} else {
		e.u32(0)
	}
	e.str("127.0.0.1")
	e.opaque(l.fh)
	e.opaque(l.owner)
	e.u32(l.svid)
	encodeNLMRange(&e, version, l.info.Offset, l.info.Length)
	return e
}

func TestNLMSynchronousGrantTransport(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(string(rune('0'+version))+"/"+transport, func(t *testing.T) {
				var epoch atomic.Uint32
				epoch.Store(3)
				cfg := Config{Version: "3", Transport: "tcp", Timeout: time.Second, PortmapPort: nsmPeer(t, &epoch), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
				tcp, udp, err := loopback.Pair()
				if err != nil {
					t.Fatal(err)
				}
				port := tcp.Addr().(*net.TCPAddr).Port
				tcp.Close()
				udp.Close()
				m, err := startNSM(context.Background(), cfg, "127.0.0.1", port, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer m.close()
				cb := &nlmCallbacks{version: version, monitor: m, entries: make(map[string]*nlmPending)}
				m.callbacks.Store(cb)
				l := &nlmLock{fh: bytes.Repeat([]byte{1}, 32), owner: []byte("owner"), svid: 7, info: LockInfo{Length: LockToEOF}}
				p := cb.register(l)
				for _, denied := range []bool{false, false, true} {
					if denied {
						cb.disable(l)
					}
					rpc, err := dialRPCTransport(context.Background(), "127.0.0.1", port, time.Second, false, transport)
					if err != nil {
						t.Fatal(err)
					}
					d, err := rpc.call(context.Background(), nlmProgram, version, 5, nil, syncGrantCall(version, l)[40:])
					rpc.conn.Close()
					if err != nil {
						t.Fatal(err)
					}
					want := uint32(0)
					if denied {
						want = 1
					}
					if !bytes.Equal(d.opaque(1024), []byte("grant-cookie")) || d.u32() != want || d.err != nil || len(d.b) != 0 {
						t.Fatal("bad wire grant reply")
					}
					if !denied {
						select {
						case err := <-p.done:
							if err != nil {
								t.Fatal(err)
							}
						case <-time.After(time.Second):
							t.Fatal("grant not delivered")
						}
					}
				}
			})
		}
	}
}

func TestNLMSynchronousGrantReply(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		for _, mode := range []string{"grant", "denied", "unknown", "write-failure", "short-reply", "malformed", "epoch-loss"} {
			t.Run(string(rune('0'+version))+"/"+mode, func(t *testing.T) {
				m := &nsmMonitor{cfg: Config{NLMClientIP: "127.0.0.1"}}
				cb := &nlmCallbacks{version: version, monitor: m, entries: make(map[string]*nlmPending)}
				m.callbacks.Store(cb)
				l := &nlmLock{fh: bytes.Repeat([]byte{1}, 32), owner: []byte("owner"), svid: 7, info: LockInfo{Write: true, Offset: 8, Length: LockToEOF}}
				p := cb.register(l)
				if mode == "denied" {
					cb.disable(l)
				}
				if mode == "unknown" {
					l.owner = []byte("unknown")
				}
				if mode == "epoch-loss" {
					m.lost.Store(true)
				}
				call := syncGrantCall(version, l)
				if mode == "malformed" {
					call = append(call, 1)
				}
				writes := 0
				m.respond(call, func(reply []byte) error {
					writes++
					if len(p.done) != 0 {
						t.Error("grant published before reply write")
					}
					d := &decoder{b: reply}
					d.take(20)
					status := d.u32()
					if mode == "malformed" {
						if status != 4 {
							t.Error("bad XDR accepted")
						}
						return nil
					}
					want := uint32(0)
					if mode == "denied" || mode == "unknown" || mode == "epoch-loss" {
						want = 1
					}
					if status != 0 || !bytes.Equal(d.opaque(1024), []byte("grant-cookie")) || d.u32() != want || d.err != nil || len(d.b) != 0 {
						t.Error("bad GRANTED response")
					}
					if mode == "write-failure" {
						return io.ErrClosedPipe
					}
					if mode == "short-reply" {
						return io.ErrShortWrite
					}
					return nil
				})
				if writes != 1 {
					t.Fatal("missing reply")
				}
				switch mode {
				case "grant":
					if err := <-p.done; err != nil {
						t.Fatal(err)
					}
				case "write-failure", "short-reply":
					if err := <-p.done; err == nil || !m.lost.Load() {
						t.Fatal("failed reply granted", err)
					}
				default:
					if len(p.done) != 0 {
						t.Fatal("denied grant accepted")
					}
				}
				if mode == "grant" {
					m.respond(call, func([]byte) error { return nil })
					if err := <-p.done; errors.Is(err, ErrLockUncertain) {
						t.Fatal("duplicate changed grant")
					}
				}
			})
		}
	}
}
