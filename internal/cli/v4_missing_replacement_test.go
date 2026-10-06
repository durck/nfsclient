package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

// Exercise the session's missing-target branch through a real v4.0 RPC socket.
// An initial NOENT is an observation, not permission to replace a later arrival.
func TestV4MissingOverwriteUsesGuardedCreate(t *testing.T) {
	for _, race := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "competing-arrival"}[race], func(t *testing.T) {
			peer := &missingV4Peer{race: race}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- peer.serve(listener) }()
			var client *nfs.Client
			var once sync.Once
			stop := func() {
				once.Do(func() {
					if client != nil {
						client.Close()
					}
					listener.Close()
					if err := <-done; err != nil {
						t.Errorf("v4 wire fixture: %v", err)
					}
				})
			}
			t.Cleanup(stop)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err = nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: "4.0", NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			s := session.New(client, "127.0.0.1", false, false, nil)
			// Root discovery is outside this regression; the wire peer owns root.
			s.Export, s.Root = "/", nfs.Node{Handle: []byte("root"), Attr: nfs.Attr{Type: 2}}
			source := filepath.Join(t.TempDir(), "source")
			payload := []byte("new payload\x00\xff")
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			var progressed bool
			count, uploadErr := s.PutWithOptions(ctx, source, "target", session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) { progressed = progressed || done != 0 }})
			stop() // Join before inspecting peer state, including mutation counts.
			if peer.creates != 1 || peer.renames != 0 || !reflect.DeepEqual(peer.createNames, []string{"target"}) {
				t.Fatalf("publication used staging/replacement: creates=%d names=%v renames=%d", peer.creates, peer.createNames, peer.renames)
			}
			if race {
				if !errors.Is(uploadErr, session.ErrDestinationExists) || count != 0 || progressed || peer.writes != 0 || !bytes.Equal(peer.data, []byte("competing writer")) || peer.mode != 0600 {
					t.Fatalf("arrival changed: count=%d progress=%t writes=%d mode=%o data=%q err=%v", count, progressed, peer.writes, peer.mode, peer.data, uploadErr)
				}
			} else if uploadErr != nil || count != int64(len(payload)) || !progressed || peer.writes != 1 || !bytes.Equal(peer.data, payload) || peer.mode != 0644 {
				t.Fatalf("new upload: count=%d writes=%d mode=%o data=%q err=%v", count, peer.writes, peer.mode, peer.data, uploadErr)
			}
		})
	}
}

type missingV4Peer struct {
	race, exists             bool
	data                     []byte
	mode                     uint32
	creates, writes, renames int
	createNames              []string
}

func (p *missingV4Peer) serve(listener net.Listener) error {
	conn, err := listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	for {
		record, _, err := readObservedRPC(conn)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		d := &missingV4Decoder{b: record}
		xid := d.word()
		if d.word() != 0 || d.word() != 2 || d.word() != 100003 || d.word() != 4 || d.word() != 1 {
			return errors.New("expected NFSv4 COMPOUND call")
		}
		d.word()
		d.opaque() // Credential; this fixture tests publication, not AUTH_SYS.
		d.word()
		d.opaque()
		d.opaque() // COMPOUND tag.
		if d.word() != 0 {
			return errors.New("expected minor version zero")
		}
		count := d.word()
		if count > 16 {
			return errors.New("excessive fixture operation count")
		}
		var body []byte
		var status, completed uint32
		current := ""
		for completed < count {
			code := d.word()
			value, opStatus, err := p.operation(code, d, &current)
			if err != nil {
				return err
			}
			body = missingV4Words(body, code, opStatus)
			body = append(body, value...)
			completed++
			status = opStatus
			if status != 0 {
				break
			}
		}
		if d.err != nil || (status == 0 && len(d.b) != 0) {
			return fmt.Errorf("malformed/trailing fixture request: %v (%d bytes)", d.err, len(d.b))
		}
		reply := missingV4Words(nil, xid, 1, 0, 0, 0, 0, status, 0, completed)
		reply = append(reply, body...)
		wire := missingV4Words(nil, uint32(len(reply))|0x80000000)
		wire = append(wire, reply...)
		if _, err := io.Copy(conn, bytes.NewReader(wire)); err != nil {
			return err
		}
	}
}

func (p *missingV4Peer) operation(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error) {
	var result []byte
	switch code {
	case 35: // SETCLIENTID
		d.take(8)
		d.opaque()
		d.word()
		d.opaque()
		d.opaque()
		d.word()
		result = missingV4Words(nil, 0, 123, 0, 0)
	case 36: // SETCLIENTID_CONFIRM
		d.take(16)
	case 24: // PUTROOTFH
		*current = "root"
	case 22: // PUTFH
		*current = string(d.opaque())
	case 10: // GETFH
		result = missingV4Opaque(nil, []byte(*current))
	case 9: // GETATTR
		bits := d.bitmap()
		if reflect.DeepEqual(bits, []uint32{10}) {
			result = missingV4Words(nil, 1, 1<<10)
			result = missingV4Opaque(result, missingV4Words(nil, 60))
		} else {
			// ACL capture here would be a regression: no old object was selected.
			for _, bit := range bits {
				if bit == 0 || bit == 12 {
					return nil, 0, errors.New("missing target entered ACL replacement path")
				}
			}
			result = missingV4Words(nil, 2, 1<<1|1<<4, 1<<1)
			attrs := missingV4Words(nil, 1, 0, uint32(len(p.data)), p.mode)
			result = missingV4Opaque(result, attrs)
		}
	case 15: // LOOKUP: publish competitor immediately after observing absence.
		if string(d.opaque()) != "target" || *current != "root" {
			return nil, 0, errors.New("unexpected lookup path")
		}
		if !p.exists {
			if p.race {
				p.exists, p.data, p.mode = true, []byte("competing writer"), 0600
			}
			return nil, 2, nil
		}
		*current = "target"
	case 18: // OPEN
		d.word()
		share, deny := d.word(), d.word()
		d.take(8)
		d.opaque()
		create := d.word()
		if share != 2 || deny != 0 || *current != "root" || create > 1 {
			return nil, 0, errors.New("unexpected OPEN arguments")
		}
		var mode uint32
		if create == 1 {
			p.creates++
			if d.word() != 1 || !reflect.DeepEqual(d.bitmap(), []uint32{33}) {
				return nil, 0, errors.New("new target OPEN must use GUARDED with mode")
			}
			attrs := &missingV4Decoder{b: d.opaque()}
			mode = attrs.word()
			if attrs.err != nil || len(attrs.b) != 0 {
				return nil, 0, errors.New("invalid OPEN mode attributes")
			}
		}
		claim, name := d.word(), string(d.opaque())
		if create == 1 {
			p.createNames = append(p.createNames, name)
		}
		if claim != 0 || name != "target" {
			return nil, 0, errors.New("unexpected OPEN name or claim")
		}
		if create == 1 && p.exists {
			return nil, 17, nil
		}
		if create == 1 {
			p.exists, p.mode = true, mode
		} else if !p.exists {
			return nil, 2, nil
		}
		*current = "target"
		result = append(result, bytes.Repeat([]byte{7}, 16)...)
		result = missingV4Words(result, 1, 0, 1, 0, 2, 0, 0, 0)
	case 4: // CLOSE
		d.word()
		result = append(result, d.take(16)...)
	case 38: // WRITE
		p.writes++
		d.take(16)
		hi, offset, stable := d.word(), d.word(), d.word()
		data := d.opaque()
		if *current != "target" || hi != 0 || offset != uint32(len(p.data)) || stable != 2 {
			return nil, 0, errors.New("unexpected WRITE target/offset/stability")
		}
		p.data = append(p.data, data...)
		result = missingV4Words(nil, uint32(len(data)), 2, 0, 1)
	case 29: // Never permit publication through replacement RENAME.
		p.renames++
		return nil, 0, errors.New("missing-target upload attempted RENAME")
	default:
		return nil, 0, fmt.Errorf("unexpected NFSv4 operation %d", code)
	}
	return result, 0, nil
}

type missingV4Decoder struct {
	b   []byte
	err error
}

func (d *missingV4Decoder) take(n uint32) []byte {
	if d.err != nil || uint64(n) > uint64(len(d.b)) {
		d.err = io.ErrUnexpectedEOF
		return nil
	}
	b := d.b[:n]
	d.b = d.b[n:]
	return b
}
func (d *missingV4Decoder) word() uint32 {
	b := d.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (d *missingV4Decoder) opaque() []byte {
	n := d.word()
	b := d.take(n)
	d.take((4 - n%4) % 4)
	return b
}
func (d *missingV4Decoder) bitmap() []uint32 {
	n := d.word()
	if n > 3 {
		d.err = errors.New("excessive fixture bitmap")
		return nil
	}
	var bits []uint32
	for i := uint32(0); i < n; i++ {
		word := d.word()
		for j := uint32(0); j < 32; j++ {
			if word&(1<<j) != 0 {
				bits = append(bits, i*32+j)
			}
		}
	}
	return bits
}
func missingV4Words(b []byte, words ...uint32) []byte {
	for _, word := range words {
		b = binary.BigEndian.AppendUint32(b, word)
	}
	return b
}
func missingV4Opaque(b, value []byte) []byte {
	b = missingV4Words(b, uint32(len(value)))
	b = append(b, value...)
	return append(b, make([]byte, (4-len(value)%4)%4)...)
}
