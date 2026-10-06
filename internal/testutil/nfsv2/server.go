// Package nfsv2 is a test-only, memory-backed RFC 1094 peer. Its wire codec is
// independent of the client's encoder/decoder. It is not a real-server
// interoperability claim and deliberately implements only fixture operations.
package nfsv2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
)

type Options struct {
	UDP             bool
	RaceName        string // create a competing destination immediately before LINK/RENAME
	FailProcedure   uint32
	DropProcedure   uint32 // execute then close without replying
	MkdirCollisions int
}
type object struct {
	id, kind, mode uint32
	data           []byte
	names          map[string]*object
}
type Server struct {
	Port        int
	Transport   string
	mu          sync.Mutex
	listener    net.Listener
	connections []net.Conn
	wg          sync.WaitGroup
	objects     map[uint32]*object
	root        *object
	next        uint32
	options     Options
	events      []uint32
	errors      []string
}

func Start(t *testing.T, options Options) *Server {
	t.Helper()
	if options.UDP {
		return startUDP(t, options)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Port: l.Addr().(*net.TCPAddr).Port, listener: l, objects: map[uint32]*object{}, options: options}
	s.root = s.newObject(2, 0755)
	accepted := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(accepted)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.connections = append(s.connections, c)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() { defer s.wg.Done(); defer c.Close(); s.serve(c) }()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-accepted
		s.mu.Lock()
		for _, c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		for _, err := range s.errors {
			t.Error(err)
		}
	})
	return s
}
func (s *Server) newObject(kind, mode uint32) *object {
	s.next++
	n := &object{id: s.next, kind: kind, mode: mode, names: map[string]*object{}}
	s.objects[n.id] = n
	return n
}
func (s *Server) Seed(name string, data []byte, mode uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.newObject(1, mode)
	n.data = append([]byte(nil), data...)
	s.root.names[name] = n
}
func (s *Server) File(name string) ([]byte, uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.root.names[name]
	if !ok {
		return nil, 0, false
	}
	return append([]byte(nil), n.data...), n.mode, true
}

// UpdateFile mutates an existing fixture object without replacing its handle.
func (s *Server) UpdateFile(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.root.names[name]
	if !ok || n.kind != 1 {
		return fmt.Errorf("fixture file %q does not exist", name)
	}
	n.data = append([]byte(nil), data...)
	return nil
}
func (s *Server) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for k := range s.root.names {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
func (s *Server) Events() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.events...)
}

// Panic on malformed fixture requests, recover into a test error in serve.
type wire struct{ *bytes.Reader }

func (w wire) word() uint32 {
	var n uint32
	if err := binary.Read(w.Reader, binary.BigEndian, &n); err != nil {
		panic(err)
	}
	return n
}
func (w wire) take(n uint32) []byte {
	if n > 1<<20 {
		panic("oversized fixture field")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(w.Reader, b); err != nil {
		panic(err)
	}
	return b
}
func (w wire) opaque() []byte        { n := w.word(); b := w.take(n); w.take((4 - n%4) % 4); return b }
func (w wire) name() string          { return string(w.opaque()) }
func word(b *bytes.Buffer, n uint32) { binary.Write(b, binary.BigEndian, n) }
func opaque(b *bytes.Buffer, v []byte) {
	word(b, uint32(len(v)))
	b.Write(v)
	b.Write(make([]byte, (4-len(v)%4)%4))
}
func fh(b *bytes.Buffer, n *object) { word(b, n.id); b.Write(make([]byte, 28)) }
func attr(b *bytes.Buffer, n *object) {
	for _, v := range []uint32{n.kind, n.mode, 1, 1000, 1000, uint32(len(n.data)), 4096, 0, 1, 7, n.id, 0, 0, 1800000000, 0, 0, 0} {
		word(b, v)
	}
}
func (s *Server) node(w wire) *object {
	id := w.word()
	w.take(28)
	n := s.objects[id]
	if n == nil {
		panic(fmt.Sprintf("unknown fixture handle %d", id))
	}
	return n
}

func (s *Server) serve(c net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			s.mu.Lock()
			s.errors = append(s.errors, fmt.Sprint(err))
			s.mu.Unlock()
		}
	}()
	for {
		var marker uint32
		if err := binary.Read(c, binary.BigEndian, &marker); err != nil {
			return
		}
		if marker>>31 != 1 || marker&0x7fffffff > 1<<20 {
			panic("unexpected RPC fixture record")
		}
		data := make([]byte, marker&0x7fffffff)
		if _, err := io.ReadFull(c, data); err != nil {
			return
		}
		reply, drop := s.reply(data)
		if drop {
			return
		}
		var record bytes.Buffer
		word(&record, uint32(len(reply))|1<<31)
		record.Write(reply)
		if _, err := c.Write(record.Bytes()); err != nil {
			return
		}
	}
}
func (s *Server) reply(data []byte) ([]byte, bool) {
	w := wire{bytes.NewReader(data)}
	xid := w.word()
	if w.word() != 0 || w.word() != 2 {
		panic("not RPC CALL v2")
	}
	prog, version, proc := w.word(), w.word(), w.word()
	w.word()
	w.opaque()
	w.word()
	w.opaque() // credentials and verifier
	body, drop := s.dispatch(prog, version, proc, w)
	if drop {
		return nil, true
	}
	var reply bytes.Buffer
	for _, v := range []uint32{xid, 1, 0, 0, 0, 0} {
		word(&reply, v)
	}
	reply.Write(body)
	return reply.Bytes(), false
}

func (s *Server) dispatch(prog, version, proc uint32, w wire) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b bytes.Buffer
	if prog == 100005 {
		if version != 1 {
			panic("not MOUNTv1")
		}
		switch proc {
		case 1:
			w.name()
			word(&b, 0)
			fh(&b, s.root)
		case 3:
			w.name()
		default:
			panic("unexpected mount operation")
		}
		return b.Bytes(), false
	}
	if prog != 100003 || version != 2 {
		panic("not NFSv2")
	}
	if proc == 0 {
		return nil, false
	}
	s.events = append(s.events, proc)
	if proc == s.options.FailProcedure {
		word(&b, 13)
		return b.Bytes(), false
	}
	if proc == 14 && s.options.MkdirCollisions > 0 {
		s.options.MkdirCollisions--
		word(&b, 17)
		return b.Bytes(), false
	}
	n := s.node(w)
	status := uint32(0)
	var payload bytes.Buffer
	switch proc {
	case 1:
		attr(&payload, n)
	case 2:
		mode := w.word()
		w.take(28)
		n.mode = mode
		attr(&payload, n)
	case 4:
		name := w.name()
		child := n.names[name]
		if name == "." || name == ".." {
			child = n
		}
		if child == nil {
			status = 2
		} else {
			fh(&payload, child)
			attr(&payload, child)
		}
	case 6:
		offset, count := w.word(), w.word()
		w.word()
		if count > 8192 {
			panic("oversized READ")
		}
		attr(&payload, n)
		start := min(uint64(offset), uint64(len(n.data)))
		end := min(start+uint64(count), uint64(len(n.data)))
		opaque(&payload, n.data[start:end])
	case 8:
		if w.word() != 0 {
			panic("WRITE beginoffset")
		}
		offset := w.word()
		if w.word() != 0 {
			panic("WRITE totalcount")
		}
		data := w.opaque()
		if len(data) > 8192 || offset+uint32(len(data)) > 1<<20 {
			panic("invalid fixture WRITE size")
		}
		end := int(offset) + len(data)
		if end > len(n.data) {
			n.data = append(n.data, make([]byte, end-len(n.data))...)
		}
		copy(n.data[offset:], data)
		attr(&payload, n)
	case 9, 14:
		name := w.name()
		mode := w.word()
		w.word()
		w.word()
		size := w.word()
		w.take(16)
		child := n.names[name]
		if proc == 14 && child != nil {
			status = 17
			break
		}
		if proc == 9 && (n == s.root || n.mode != 0700) {
			panic("unguarded CREATE outside private staging")
		}
		kind := uint32(1)
		if proc == 14 {
			kind = 2
		}
		if child == nil {
			child = s.newObject(kind, mode)
			n.names[name] = child
		}
		if proc == 9 {
			if size != 0 {
				panic("CREATE did not set size zero")
			}
			child.data = nil
		}
		fh(&payload, child)
		attr(&payload, child)
	case 10, 15:
		name := w.name()
		child := n.names[name]
		if child == nil {
			status = 2
			break
		}
		if proc == 15 && len(child.names) > 0 {
			status = 66
			break
		}
		delete(n.names, name)
	case 11:
		name := w.name()
		dest := s.node(w)
		newName := w.name()
		if s.options.RaceName == newName {
			rival := s.newObject(1, 0600)
			rival.data = []byte("competing writer")
			dest.names[newName] = rival
		}
		child := n.names[name]
		if child == nil {
			status = 2
		} else if old := dest.names[newName]; old != nil && old.kind != 1 {
			status = 21
		} else {
			dest.names[newName] = child
			delete(n.names, name)
		}
	case 12:
		dest := s.node(w)
		name := w.name()
		if s.options.RaceName == name {
			rival := s.newObject(1, 0600)
			rival.data = []byte("competing writer")
			dest.names[name] = rival
		}
		if dest.names[name] != nil {
			status = 17
		} else {
			dest.names[name] = n
		}
	case 16:
		cookie, count := w.word(), w.word()
		if cookie != 0 || (count != 8192 && count != 4096) {
			panic("unexpected READDIR arguments")
		}
		var names []string
		for name := range n.names {
			names = append(names, name)
		}
		sort.Strings(names)
		for i, name := range names {
			word(&payload, 1)
			word(&payload, n.names[name].id)
			opaque(&payload, []byte(name))
			word(&payload, uint32(i+1))
		}
		word(&payload, 0)
		word(&payload, 1)
	case 17:
		for _, v := range []uint32{4096, 4096, 100, 80, 80} {
			word(&payload, v)
		}
	default:
		panic(fmt.Sprintf("unexpected NFSv2 procedure %d", proc))
	}
	if w.Len() != 0 {
		panic(fmt.Sprintf("trailing arguments for procedure %d: %d", proc, w.Len()))
	}
	word(&b, status)
	if status == 0 {
		b.Write(payload.Bytes())
	}
	return b.Bytes(), proc == s.options.DropProcedure
}

func startUDP(t *testing.T, options Options) *Server {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Port: c.LocalAddr().(*net.UDPAddr).Port, Transport: "udp", objects: map[uint32]*object{}, options: options}
	s.root = s.newObject(2, 0755)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if err := recover(); err != nil {
				s.errors = append(s.errors, fmt.Sprint(err))
			}
		}()
		buf := make([]byte, 65536)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply, drop := s.reply(buf[:n])
			if !drop {
				c.WriteToUDP(reply, addr)
			}
		}
	}()
	t.Cleanup(func() {
		c.Close()
		<-done
		for _, err := range s.errors {
			t.Error(err)
		}
	})
	return s
}
