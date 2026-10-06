package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

// Exercise the duplex reader with a real callback before the initial reply,
// a later completion, and a retransmission on the same transport.
func TestOffloadDuplexCompletion(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(fmt.Sprint(disconnect), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			r := &layoutRecall{session: bytes.Repeat([]byte{9}, 16), minor: 2, offloadEnabled: true}
			rpc := &rpcClient{conn: client, timeout: time.Second}
			c := &Client{nfs: rpc, Auth: Auth{}}
			v := &v4Client{c: c, minor: 2, session: bytes.Clone(r.session), sequence: 1, recall: r, locks: map[uint64]*v4Lock{}}
			c.v4 = v
			id := bytes.Repeat([]byte{8}, 16)
			v.locks[1] = &v4Lock{info: LockInfo{ID: 1, Length: LockToEOF, Write: true}, sid: id, file: &v4Open{fh: []byte("file"), auth: c.Auth}}
			rpc.duplex = startDuplex(rpc, r.callback)
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				server.SetDeadline(time.Now().Add(3 * time.Second))
				request, err := readRecord(server)
				if err != nil {
					done <- err
					return
				}
				d := &decoder{b: request}
				xid := d.u32()
				d.take(20)
				d.u32()
				d.opaque(400)
				d.u32()
				d.opaque(400)
				d.str()
				minor := d.u32()
				ops := d.u32()
				if minor != 2 || ops != 3 || d.u32() != 53 {
					done <- fmt.Errorf("unexpected initial compound")
					return
				}
				sid := bytes.Clone(d.take(16))
				sequence := d.u32()
				d.take(12)
				if d.u32() != 22 || string(d.opaque(128)) != "file" || d.u32() != 70 {
					done <- fmt.Errorf("missing WRITE_SAME")
					return
				}
				if !bytes.Equal(d.take(16), id) || d.u32() != 2 || d.u64() != 0 || d.u64() != 2 || d.u64() != 3 || d.u64() != ^uint64(0) || d.u32() != 0 || d.u64() != 0 || !bytes.Equal(d.opaque(4096), []byte{1, 2}) || d.err != nil || len(d.b) != 0 {
					done <- fmt.Errorf("bad WRITE_SAME arguments")
					return
				}
				if disconnect {
					done <- nil
					return
				}
				callback := func(seq uint32) ([]byte, error) {
					call := offloadCallback(r, seq, []byte("file"), id, offloadReply{count: 6, stable: 2, verifier: []byte("verifier")})
					if _, err := server.Write(record(call, true)); err != nil {
						return nil, err
					}
					return readRecord(server)
				}
				early, err := callback(1)
				if err != nil || binary.BigEndian.Uint32(early[24:28]) != 10008 {
					done <- fmt.Errorf("early callback: %x %v", early, err)
					return
				}
				var reply encoder
				for _, n := range []uint32{xid, 1, 0, 0, 0, 0, 0} {
					reply.u32(n)
				}
				reply.str("")
				reply.u32(3)
				reply.u32(53)
				reply.u32(0)
				reply = append(reply, sid...)
				reply.u32(sequence)
				for range 4 {
					reply.u32(0)
				}
				reply.u32(22)
				reply.u32(0)
				reply.u32(70)
				reply.u32(0)
				reply.u32(1)
				reply = append(reply, id...)
				reply.u64(0)
				reply.u32(0)
				reply = append(reply, []byte("verifier")...)
				if _, err := server.Write(record(reply, true)); err != nil {
					done <- err
					return
				}
				for seq := uint32(2); seq < 100; seq++ {
					response, err := callback(seq)
					if err != nil {
						done <- err
						return
					}
					status := binary.BigEndian.Uint32(response[24:28])
					if status == 10008 {
						time.Sleep(time.Millisecond)
						continue
					}
					if status != 0 {
						done <- fmt.Errorf("callback status %d", status)
						return
					}
					duplicate, err := callback(seq)
					if err != nil || !bytes.Equal(response, duplicate) {
						done <- fmt.Errorf("duplicate callback: %v", err)
						return
					}
					done <- nil
					return
				}
				done <- fmt.Errorf("completion never became eligible")
			}()
			n, err := c.WriteSame(context.Background(), []byte("file"), 0, 3, []byte{1, 2}, 2*time.Second)
			if disconnect {
				if err == nil || n != 0 || !v.stateLost.Load() {
					t.Fatal(n, err)
				}
			} else if err != nil || n != 6 {
				t.Fatal(n, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
