// Package dnsfixture serves synthetic DNS on ephemeral loopback TCP/UDP ports.
package dnsfixture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"nfs-viewer/internal/testutil/loopback"

	"golang.org/x/net/dns/dnsmessage"
)

type Server struct {
	Address  string
	UDP, TCP atomic.Int32
}

// A nil response deliberately drops a query. The handler can run concurrently.
func Start(t *testing.T, handle func(string, dnsmessage.Message) *dnsmessage.Message) *Server {
	t.Helper()
	l, u, err := loopback.Pair()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Address: l.Addr().String()}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	answer := func(network string, b []byte) []byte {
		var q dnsmessage.Message
		if err := q.Unpack(b); err != nil {
			t.Error(err)
			return nil
		}
		if network == "udp" {
			s.UDP.Add(1)
		} else {
			s.TCP.Add(1)
		}
		r := handle(network, q)
		if r == nil {
			return nil
		}
		wire, err := r.Pack()
		if err != nil {
			t.Error(err)
		}
		return wire
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, addr, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			if reply := answer("udp", buf[:n]); reply != nil {
				u.WriteTo(reply, addr)
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
				for {
					var header [2]byte
					if _, err := io.ReadFull(c, header[:]); err != nil {
						return
					}
					buf := make([]byte, binary.BigEndian.Uint16(header[:]))
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					if reply := answer("tcp", buf); reply != nil {
						packet := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
						packet = append(packet, reply...)
						if _, err := io.Copy(c, bytes.NewReader(packet)); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { cancel(); l.Close(); u.Close(); wg.Wait() })
	return s
}

// Loopback answers A queries and returns a valid empty AAAA response.
func Loopback(q dnsmessage.Message) *dnsmessage.Message {
	r := &dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: q.Questions}
	if len(q.Questions) == 1 && q.Questions[0].Type == dnsmessage.TypeA {
		r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
	}
	return r
}
