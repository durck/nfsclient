package nfs

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
)

func TestUDPConfiguredLimitsOnWire(t *testing.T) {
	for _, limit := range []uint32{512, 1024, 4096} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			var bad atomic.Bool
			_, port := udpPeer(t, func(s *net.UDPConn, addr *net.UDPAddr, packet []byte) {
				d := &decoder{b: packet}
				xid := d.u32()
				d.take(16) // CALL, RPC version, program, NFS version
				proc := d.u32()
				d.u32()
				d.opaque(400)
				d.u32()
				d.opaque(400)
				d.opaque(64)
				e := encoder(udpReply(xid, 0))
				e.u32(0) // absent post-op attributes
				if proc == 19 {
					for _, n := range []uint32{768, 768, 1, 32768, 32768, 1, 32768} {
						e.u32(n)
					}
					e.u64(1 << 40)
					e.u32(1)
					e.u32(0)
					e.u32(0)
				} else {
					d.take(16) // cookie and verifier
					if (proc != 16 && proc != 17) || d.u32() != limit {
						bad.Store(true)
					}
					if proc == 17 && d.u32() != limit {
						bad.Store(true)
					}
					e.u64(0)
					e.u32(0) // no directory entries
					e.u32(1) // EOF
				}
				if d.err != nil || len(d.b) != 0 {
					bad.Store(true)
				}
				s.WriteToUDP(e, addr)
			})
			c := &Client{nfs: udpClient(t, port), version: "3", config: &Config{UDPSize: limit}}
			if err := c.Tune(context.Background(), []byte("fh")); err != nil || c.ReadSize != min(limit, 768) || c.WriteSize != limit {
				t.Fatal("server/config bounds not intersected", err, c.ReadSize, c.WriteSize)
			}
			for _, plus := range []bool{false, true} {
				if entries, err := c.readDir(context.Background(), []byte("fh"), plus); err != nil || len(entries) != 0 {
					t.Fatal("bounded directory reply", err)
				}
			}
			if bad.Load() {
				t.Fatal("wrong directory request limit or RPC layout")
			}
		})
	}
}
