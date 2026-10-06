// Package kdcfixture serves bounded synthetic KDC transport replies on loopback.
// It never constructs successful authentication; real MIT tests supply that.
package kdcfixture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"nfsclient/internal/testutil/loopback"
)

type Server struct {
	Address  string
	TCP, UDP atomic.Int32
}

// A nil reply models a silent endpoint. Handles exactly one TCP record per
// connection, as the client's KDC transport does. No request bytes are logged.
func Start(t *testing.T, reply func(network string, request []byte) []byte) *Server {
	t.Helper()
	l, u, err := loopback.Pair()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Address: l.Addr().String()}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	t.Cleanup(func() { cancel(); l.Close(); u.Close(); wg.Wait() })
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, addr, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			s.UDP.Add(1)
			if b := reply("udp", buf[:n]); b != nil {
				u.WriteTo(b, addr)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				var prefix [4]byte
				if _, err := io.ReadFull(c, prefix[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(prefix[:])
				if size == 0 || size > 4<<20 {
					return
				}
				request := make([]byte, size)
				if _, err := io.ReadFull(c, request); err != nil {
					return
				}
				s.TCP.Add(1)
				b := reply("tcp", request)
				if b == nil {
					io.Copy(io.Discard, c)
					return
				}
				packet := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
				packet = append(packet, b...)
				io.Copy(c, bytes.NewReader(packet))
			}()
		}
	}()
	return s
}
