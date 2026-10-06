// Package testiscsi is an independent TCP target used only by test callers.
// It decodes protocol bytes directly, without importing the initiator codec.
package testiscsi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

const Initiator = "iqn.2026-10.test:viewer"
const Name = "iqn.2026-10.test:disk"

type Options struct {
	DeviceIDForSession           func() [8]byte
	SectorSizeForSession         func() uint32
	CHAPUsername, TargetUsername string
	CHAPSecret, TargetSecret     []byte
	HeaderDigest, DataDigest     bool
	SectorSize                   uint32
	OSDSystemID                  []byte
	OSDName                      []byte
	OSDObjects                   map[[2]uint64][]byte
	OSDKey                       []byte
	OSDDataFirst                 bool
	OSDSplitR2T                  bool
	ReadSequencePDUs             int
	ReadPDUBytes                 int
	ReadDropAfter                int // Drop the selected per-session READ, after earlier probes succeed.
	BeforeReadDrop               func()
	SeparateReadStatus           bool
	Fault                        string
	WriteObserved                chan<- struct{}
	ContinueWrite                <-chan struct{}
	// Allow reset/abort errors only when the caller deliberately kills or
	// disconnects the initiator, including rejection of an injected fault.
	AllowProcessKill bool
	ReadAllowed      func(uint64, uint64) bool
	// Reject data reads of INVALID storage. Signature reads use a different range.
	InvalidStart, InvalidEnd uint64
}

type Target struct {
	osdActions  []uint16
	writeGate   sync.Once
	mu          sync.Mutex
	listener    net.Listener
	connections map[net.Conn]bool
	wg          sync.WaitGroup
	path        string
	options     Options
	errors      []error
	events      []byte
	id          [8]byte
	osdNonces   map[string]bool
}

func Start(t testing.TB, path string, options Options) *Target {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Target{listener: l, path: path, options: options, connections: map[net.Conn]bool{}}
	hash := sha256.Sum256([]byte(path))
	copy(s.id[:], hash[:8])
	s.id[0] = s.id[0]&15 | 0x50
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			s.mu.Lock()
			s.connections[c] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				err := s.serve(c)
				s.mu.Lock()
				delete(s.connections, c)
				if !expectedDisconnect(err, options.AllowProcessKill) {
					s.errors = append(s.errors, err)
				}
				s.mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		s.listener.Close()
		s.mu.Lock()
		for c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		for _, e := range s.errors {
			t.Error("independent target:", e)
		}
	})
	return s
}

func expectedDisconnect(err error, allowProcessKill bool) bool {
	reset := errors.Is(err, syscall.ECONNRESET) || runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(10054)) || errors.Is(err, syscall.Errno(10053)))
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || allowProcessKill && reset
}

func (s *Target) URL() string    { return "iscsi://" + s.listener.Addr().String() + "/" + Name + "/0" }
func (s *Target) Events() []byte { s.mu.Lock(); defer s.mu.Unlock(); return bytes.Clone(s.events) }
func (s *Target) event(op byte)  { s.mu.Lock(); s.events = append(s.events, op); s.mu.Unlock() }

type frame struct {
	ahs     []byte
	header  [48]byte
	payload []byte
}

func word(h []byte, off int) uint32   { return binary.BigEndian.Uint32(h[off : off+4]) }
func set(h []byte, off int, v uint32) { binary.BigEndian.PutUint32(h[off:off+4], v) }
func receive(c net.Conn) (p frame, err error) {
	if _, err = io.ReadFull(c, p.header[:]); err != nil {
		return p, err
	}
	n := int(p.header[5])<<16 | int(p.header[6])<<8 | int(p.header[7])
	if int(p.header[4])*4 > 248 || p.header[4] != 0 && p.header[0] != 1 || n > 65536 {
		return p, errors.New("unexpected initiator PDU geometry")
	}
	p.ahs = make([]byte, int(p.header[4])*4)
	if _, err = io.ReadFull(c, p.ahs); err != nil {
		return p, err
	}
	if d, ok := c.(*digestConnection); ok && d.header {
		var check [4]byte
		if _, err = io.ReadFull(c, check[:]); err != nil {
			return p, err
		}
		hdr := append(append([]byte{}, p.header[:]...), p.ahs...)
		if binary.LittleEndian.Uint32(check[:]) != wireCRC(hdr) {
			return p, errors.New("initiator header CRC mismatch")
		}
	}
	p.payload = make([]byte, (n+3)&^3)
	_, err = io.ReadFull(c, p.payload)
	if err != nil {
		return p, err
	}
	if d, ok := c.(*digestConnection); ok && d.data && n != 0 {
		var check [4]byte
		if _, err = io.ReadFull(c, check[:]); err != nil {
			return p, err
		}
		if binary.LittleEndian.Uint32(check[:]) != wireCRC(p.payload) {
			return p, errors.New("initiator data CRC mismatch")
		}
	}
	p.payload = p.payload[:n]
	return p, err
}
func send(c net.Conn, p frame) error {
	n := len(p.payload)
	p.header[5] = byte(n >> 16)
	p.header[6] = byte(n >> 8)
	p.header[7] = byte(n)
	b := append([]byte{}, p.header[:]...)
	if d, ok := c.(*digestConnection); ok && d.header {
		b = appendDigest(b, wireCRC(b))
		if (d.fault == "header-corrupt" || d.fault == "header-corrupt-read" && len(p.payload) >= 512) && !d.corrupted {
			b[48] ^= 1
			d.corrupted = true
		}
	}
	dataStart := len(b)
	b = append(b, p.payload...)
	b = append(b, make([]byte, (-n)&3)...)
	if d, ok := c.(*digestConnection); ok && d.data && n != 0 {
		b = appendDigest(b, wireCRC(b[dataStart:]))
		if (d.fault == "data-corrupt" || d.fault == "data-corrupt-read" && len(p.payload) >= 512) && !d.corrupted {
			b[len(b)-1] ^= 1
			d.corrupted = true
		}
	}
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (s *Target) serve(c net.Conn) error {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	f, err := os.OpenFile(s.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	deviceID := s.id
	if s.options.DeviceIDForSession != nil {
		deviceID = s.options.DeviceIDForSession()
	}
	sector := s.options.SectorSize
	if s.options.SectorSizeForSession != nil {
		sector = s.options.SectorSizeForSession()
	}
	if sector == 0 {
		sector = 512
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var stat uint32 = 41
	var cmd uint32 = 1
	firstPhase := 0
	if s.options.CHAPUsername != "" {
		ok, e := s.securityLogin(c, &stat)
		if e != nil || !ok {
			return e
		}
		firstPhase = 1
	}
	for phase := firstPhase; phase < 2; phase++ {
		p, e := receive(c)
		if e != nil {
			return e
		}
		flags := byte(0x81)
		if phase == 1 {
			flags = 0x87
		}
		if p.header[0] != 0x43 || p.header[1] != flags || word(p.header[:], 24) != 1 || word(p.header[:], 16) != 1 || phase == 1 && word(p.header[:], 28) != stat || p.header[14] != 0 || p.header[15] != 0 {
			return errors.New("incorrect initiator login sequencing")
		}
		if phase == 0 && (!bytes.Contains(p.payload, []byte("TargetName="+Name+"\x00")) || !bytes.Contains(p.payload, []byte("InitiatorName="+Initiator+"\x00")) || !bytes.Contains(p.payload, []byte("AuthMethod=None\x00"))) {
			return errors.New("incorrect approved target/initiator")
		}
		var r frame
		r.header[0] = 0x23
		r.header[1] = flags
		copy(r.header[8:14], p.header[8:14])
		if phase == 1 {
			r.header[15] = 9
		}
		set(r.header[:], 16, 1)
		set(r.header[:], 24, stat)
		set(r.header[:], 28, 1)
		set(r.header[:], 32, 64)
		if phase == 0 {
			r.payload = []byte("AuthMethod=None\x00")
		} else {
			r.payload = []byte("HeaderDigest=None\x00DataDigest=None\x00MaxConnections=1\x00InitialR2T=Yes\x00ImmediateData=No\x00MaxRecvDataSegmentLength=512\x00MaxBurstLength=65536\x00FirstBurstLength=65536\x00MaxOutstandingR2T=1\x00DataPDUInOrder=Yes\x00DataSequenceInOrder=Yes\x00ErrorRecoveryLevel=0\x00")
		}
		if phase == 1 {
			if s.options.HeaderDigest {
				if !bytes.Contains(p.payload, []byte("HeaderDigest=CRC32C")) {
					return errors.New("missing header digest offer")
				}
				r.payload = bytes.ReplaceAll(r.payload, []byte("HeaderDigest=None"), []byte("HeaderDigest=CRC32C"))
			}
			if s.options.DataDigest {
				if !bytes.Contains(p.payload, []byte("DataDigest=CRC32C")) {
					return errors.New("missing data digest offer")
				}
				r.payload = bytes.ReplaceAll(r.payload, []byte("DataDigest=None"), []byte("DataDigest=CRC32C"))
			}
		}
		fault := s.options.Fault
		if phase == 0 && fault == "redirect" {
			r.header[36] = 1
			r.header[37] = 1
			r.payload = []byte("TargetAddress=127.0.0.2:3260,1\x00")
		}
		if phase == 0 && fault == "chap" {
			r.payload = []byte("AuthMethod=CHAP\x00")
		}
		if phase == 1 && fault == "digest" {
			r.payload = bytes.ReplaceAll(r.payload, []byte("HeaderDigest=None"), []byte("HeaderDigest=CRC32C"))
		}
		if phase == 1 && fault == "login-stat" {
			set(r.header[:], 24, stat+1)
		}
		if phase == 1 && fault == "login-id" {
			r.header[8] ^= 1
		}
		if phase == 1 && fault == "login-continue" {
			r.header[1] = 0x44
		}
		if phase == 1 && fault == "duplicate-key" {
			r.payload = append(r.payload, []byte("ImmediateData=No\x00")...)
		}
		if e = send(c, r); e != nil {
			return e
		}
		stat++
		if fault == "redirect" || fault == "chap" || phase == 1 && (fault == "digest" || fault == "login-stat" || fault == "login-id" || fault == "login-continue" || fault == "duplicate-key") {
			return nil
		}
	}
	if s.options.HeaderDigest || s.options.DataDigest {
		c = &digestConnection{Conn: c, header: s.options.HeaderDigest, data: s.options.DataDigest, fault: s.options.Fault}
	}
	readCount := 0
	for {
		p, e := receive(c)
		if e != nil {
			return e
		}
		h := p.header[:]
		if h[0] != 1 || h[9] != 0 || !bytes.Equal(h[8:16], make([]byte, 8)) || word(h, 24) != cmd || word(h, 28) != stat || len(p.payload) != 0 {
			return errors.New("incorrect SCSI command sequencing/LUN")
		}
		cmd++
		if len(s.options.OSDSystemID) != 0 {
			if e := s.serveObject(c, p, stat, cmd); e != nil {
				return e
			}
			stat++
			continue
		}
		if len(p.ahs) != 0 {
			return errors.New("unexpected disk command AHS")
		}
		op := h[32]
		s.event(op)
		var data []byte
		var residual uint32
		r := frame{}
		r.header[0] = 0x21
		r.header[1] = 0x80
		set(r.header[:], 16, word(h, 16))
		set(r.header[:], 24, stat)
		set(r.header[:], 28, cmd)
		set(r.header[:], 32, cmd+63)
		fault := s.options.Fault
		switch op {
		case 0x12:
			if h[33] != 1 || h[34] != 0x83 || h[36] != 252 || word(h, 20) != 252 || h[1] != 0xc1 {
				return errors.New("incorrect VPD inquiry")
			}
			data = append([]byte{0, 0x83, 0, 12, 1, 3, 0, 8}, deviceID[:]...)
			residual = 252 - uint32(len(data))
			if fault == "identity" {
				data[5] = 1
			}
		case 0x9e:
			if h[33] != 0x10 || word(h, 42) != 32 || word(h, 20) != 32 || h[1] != 0xc1 {
				return errors.New("incorrect READ CAPACITY 16")
			}
			data = make([]byte, 32)
			binary.BigEndian.PutUint64(data, uint64(info.Size()/int64(sector)-1))
			set(data, 8, sector)
			if fault == "sector" {
				set(data, 8, 1024)
			}
			if fault == "capacity" {
				binary.BigEndian.PutUint64(data, ^uint64(0))
			}
		case 0x88, 0x8a:
			start := binary.BigEndian.Uint64(h[34:42]) * uint64(sector)
			n := uint64(word(h, 42)) * uint64(sector)
			if n == 0 || n > 65536 || start > uint64(info.Size()) || n > uint64(info.Size())-start || word(h, 20) != uint32(n) {
				return errors.New("incorrect SCSI data geometry")
			}
			if op == 0x88 {
				readCount++
				if h[1] != 0xc1 {
					return errors.New("incorrect read flags")
				}
				if s.options.InvalidEnd != 0 && start < s.options.InvalidEnd && start+n > s.options.InvalidStart && !(s.options.ReadAllowed != nil && s.options.ReadAllowed(start, n)) {
					return errors.New("initiator read INVALID storage")
				}
				data = make([]byte, n)
				if _, e = f.ReadAt(data, int64(start)); e != nil {
					return e
				}
				if fault == "read-drop" || s.options.ReadDropAfter > 0 && readCount == s.options.ReadDropAfter {
					if s.options.BeforeReadDrop != nil {
						s.options.BeforeReadDrop()
					}
					return nil
				}
				if fault == "unit-attention" {
					r.header[3] = 2
					r.payload = []byte{0, 4, 0x70, 0, 6, 0}
					if e = send(c, r); e != nil {
						return e
					}
					return nil
				}
			} else {
				if h[1] != 0xa1 {
					return errors.New("incorrect write flags")
				}
				var received uint64
				var r2tsn uint32
				for received < n {
					burst := min(n-received, uint64(1024))
					q := r
					q.header[0] = 0x31
					set(q.header[:], 20, 77)
					set(q.header[:], 36, r2tsn)
					set(q.header[:], 40, uint32(received))
					set(q.header[:], 44, uint32(burst))
					r2tsn++
					if fault == "r2t-offset" {
						set(q.header[:], 40, 1)
					}
					if fault == "r2t-lun" {
						q.header[9] = 1
					}
					if fault == "r2t-tag" {
						set(q.header[:], 20, ^uint32(0))
					}
					if fault == "r2t-sequence" {
						set(q.header[:], 36, 1)
					}
					if fault == "r2t-length" {
						set(q.header[:], 44, 0)
					}
					if e = send(c, q); e != nil {
						return e
					}
					if fault == "r2t-offset" || fault == "r2t-lun" || fault == "r2t-tag" || fault == "r2t-sequence" || fault == "r2t-length" {
						return nil
					}
					var sn uint32
					for done := uint64(0); done < burst; {
						q, e = receive(c)
						if e != nil {
							return e
						}
						size := uint64(len(q.payload))
						want := min(burst-done, uint64(512))
						flags := byte(0)
						if size == burst-done {
							flags = 0x80
						}
						if q.header[0] != 5 || q.header[1] != flags || word(q.header[:], 16) != word(h, 16) || word(q.header[:], 20) != 77 || word(q.header[:], 28) != stat || word(q.header[:], 36) != sn || word(q.header[:], 40) != uint32(received) || size != want || !bytes.Equal(q.header[8:16], h[8:16]) {
							return errors.New("incorrect solicited Data-Out")
						}
						if _, e = f.WriteAt(q.payload, int64(start+received)); e != nil {
							return e
						}
						sn++
						done += size
						received += size
					}
				}
				if s.options.WriteObserved != nil {
					blocked := false
					s.writeGate.Do(func() {
						blocked = true
						s.options.WriteObserved <- struct{}{}
						<-s.options.ContinueWrite
					})
					if blocked {
						return nil
					}
				}
				if fault == "write-drop" {
					return nil
				}
				if fault == "write-status" {
					r.header[3] = 2
				}
			}
		case 0x91:
			if h[1] != 0x81 || word(h, 20) != 0 || !bytes.Equal(h[33:48], make([]byte, 15)) {
				return errors.New("incorrect SYNCHRONIZE CACHE 16")
			}
			if e = f.Sync(); e != nil {
				return e
			}
			if fault == "sync-drop" {
				return nil
			}
			if fault == "sync-status" {
				r.header[3] = 2
			}
		default:
			return fmt.Errorf("unexpected SCSI opcode %x", op)
		}
		if len(data) > 0 {
			if op == 0x88 && fault == "noop" {
				ping := r
				ping.header[0] = 0x20
				set(ping.header[:], 16, ^uint32(0))
				set(ping.header[:], 20, 99)
				ping.payload = []byte("ping")
				if e = send(c, ping); e != nil {
					return e
				}
				pong, e := receive(c)
				if e != nil {
					return e
				}
				if pong.header[0] != 0x40 || word(pong.header[:], 16) != ^uint32(0) || word(pong.header[:], 20) != 99 || word(pong.header[:], 28) != stat || !bytes.Equal(pong.payload, ping.payload) {
					return errors.New("incorrect ping reply")
				}
			}
			// VPD short data is independently encoded with a valid residual.
			sn, offset := uint32(0), 0
			separateStatus := op == 0x88 && (s.options.SeparateReadStatus || fault == "separate-status" || fault == "separate-status-open-sequence" || fault == "separate-status-sequence")
			for offset < len(data) {
				n := min(512, len(data)-offset)
				if s.options.ReadPDUBytes > 0 {
					n = min(n, s.options.ReadPDUBytes)
				}
				if op == 0x88 && fault == "data-pdu-limit" {
					n = 1
				}
				q := r
				q.header[0] = 0x25
				q.header[1] = 0
				if s.options.ReadSequencePDUs > 0 && (sn+1)%uint32(s.options.ReadSequencePDUs) == 0 {
					q.header[1] = 0x80
				}
				q.payload = data[offset : offset+n]
				set(q.header[:], 36, sn)
				set(q.header[:], 40, uint32(offset))
				set(q.header[:], 44, 0)
				if offset+n == len(data) {
					q.header[1] = 0x81
					if residual != 0 {
						q.header[1] |= 2
						set(q.header[:], 44, residual)
					}
				}
				if op == 0x88 {
					switch fault {
					case "data-sequence":
						set(q.header[:], 36, 1)
					case "data-offset":
						set(q.header[:], 40, 1)
					case "data-sequence-reset":
						q.header[1] |= 0x80
						set(q.header[:], 36, 0)
					case "task-tag":
						set(q.header[:], 16, word(h, 16)+1)
					case "status-sequence":
						set(q.header[:], 24, stat+1)
					case "residual":
						q.header[1] |= 2
						set(q.header[:], 44, 1)
					case "window":
						set(q.header[:], 28, cmd+1)
					case "ahs":
						q.header[4] = 1
					case "oversize":
						q.header[5] = 1
						q.header[6] = 0
						q.header[7] = 1
						if _, e = c.Write(q.header[:]); e != nil {
							return e
						}
						return nil
					case "payload-drop":
						if _, e = c.Write(q.header[:]); e != nil {
							return e
						}
						return nil
					}
				}
				if separateStatus && offset+n == len(data) {
					q.header[1] = 0x80
				}
				if op == 0x88 && offset+n == len(data) {
					if fault == "status-without-final" {
						q.header[1] = 1
					}
					if fault == "separate-status-open-sequence" {
						q.header[1] = 0
					}
				}
				if e = send(c, q); e != nil {
					return e
				}
				sn++
				offset += n
				if op == 0x88 && isReadFault(fault) {
					return nil
				}
				if op == 0x88 && (fault == "data-sequence-reset" && sn == 2 || fault == "data-pdu-limit" && sn == 1025) {
					return nil
				}
			}
			if separateStatus {
				set(r.header[:], 36, sn)
				if fault == "separate-status-sequence" {
					set(r.header[:], 36, sn-1)
				}
				if e = send(c, r); e != nil {
					return e
				}
			}
		} else {
			if e = send(c, r); e != nil {
				return e
			}
			if r.header[3] != 0 {
				return nil
			}
		}
		stat++
	}
}

func isReadFault(fault string) bool {
	switch fault {
	case "data-sequence", "data-offset", "task-tag", "status-sequence", "residual", "window", "ahs", "oversize", "payload-drop":
		return true
	}
	return false
}
