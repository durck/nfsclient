package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

type operationReply4 func(uint32, *decoder) (encoder, Status, error)

func TestV4ParentLookup(t *testing.T) {
	for _, status := range []Status{0, 2} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls []uint32
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				calls = append(calls, code)
				var e encoder
				switch code {
				case 16:
					return nil, status, nil
				case 10:
					e.opaque([]byte("parent"))
				case 9:
					readBitmap4(d)
					bitmap4(&e, 1, 8, 20)
					var a encoder
					a.u32(2)
					a.u64(10)
					a.u64(20)
					a.u64(30)
					e.opaque(a)
				default:
					return nil, 0, fmt.Errorf("unexpected parent operation %d", code)
				}
				return e, 0, nil
			})
			n, err := v.lookup(context.Background(), []byte("child"), "..")
			if status != 0 {
				if !errors.Is(err, status) || fmt.Sprint(calls) != "[16]" {
					t.Fatalf("boundary: %v %v", calls, err)
				}
				return
			}
			if err != nil || string(n.Handle) != "parent" || n.Attr.FSIDMinor != 20 || n.Attr.FileID != 30 || fmt.Sprint(calls) != "[16 10 9]" {
				t.Fatalf("parent: %+v %v %v", n, calls, err)
			}
			if _, ok := v.parents["parent"]; ok {
				t.Fatal("parent lookup polluted OPEN name cache")
			}
		})
	}
}

func peer4(t *testing.T, minor uint32, reply operationReply4) *v4Client {
	t.Helper()
	return peer4WithHandle(t, minor, reply, nil)
}

func peer4WithHandle(t *testing.T, minor uint32, reply operationReply4, checkHandle func([]byte) error, allowCancelledWrite ...bool) *v4Client {
	t.Helper()
	c := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
		if program != nfsProgram || proc != 1 {
			return nil, fmt.Errorf("not COMPOUND: %d/%d", program, proc)
		}
		d.str()
		if got := d.u32(); got != minor {
			return nil, fmt.Errorf("minor version %d", got)
		}
		count := d.u32()
		var body encoder
		var status Status
		var done uint32
		for done < count {
			code := d.u32()
			var payload encoder
			var err error
			if code == 22 {
				fh := d.opaque(128)
				if checkHandle != nil {
					err = checkHandle(fh)
				}
			} else {
				payload, status, err = reply(code, d)
			}
			if err != nil {
				return nil, err
			}
			if d.err != nil {
				return nil, d.err
			}
			body.u32(code)
			body.u32(uint32(status))
			body = append(body, payload...)
			done++
			if status != 0 {
				break
			}
		}
		if status == 0 && len(d.b) != 0 {
			return nil, fmt.Errorf("trailing request bytes: %d", len(d.b))
		}
		var e encoder
		e.u32(uint32(status))
		e.str("")
		e.u32(done)
		e = append(e, body...)
		return e, nil
	}, allowCancelledWrite...)
	v := &v4Client{c: c, minor: minor, clientID: 123, root: []byte("root"), parents: map[string]v4Name{"file": {[]byte("root"), "file"}}}
	c.v4 = v
	c.version = fmt.Sprintf("4.%d", minor)
	return v
}

func transferPeer4(t *testing.T, other operationReply4) (*v4Client, *bool) {
	t.Helper()
	closed := false
	sid := bytes.Repeat([]byte{7}, 16)
	confirmed := bytes.Repeat([]byte{8}, 16)
	v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 18:
			seq := d.u32()
			share := d.u32()
			deny := d.u32()
			client := d.u64()
			owner := d.opaque(128)
			create := d.u32()
			claim := d.u32()
			name := d.str()
			if seq != 0 || share < 1 || share > 2 || deny != 0 || client != 123 || len(owner) != 16 || create != 0 || claim != 0 || name != "file" {
				return nil, 0, errors.New("invalid OPEN")
			}
			e = append(e, sid...)
			e.u32(1)
			e.u64(1)
			e.u64(1)
			e.u32(2)
			e.u32(0)
			e.u32(0)
		case 10:
			e.opaque([]byte("file"))
		case 20:
			if !bytes.Equal(d.take(16), sid) || d.u32() != 1 {
				return nil, 0, errors.New("invalid OPEN_CONFIRM")
			}
			e = append(e, confirmed...)
		case 4:
			if d.u32() != 2 || !bytes.Equal(d.take(16), confirmed) {
				return nil, 0, errors.New("invalid CLOSE")
			}
			closed = true
			e = append(e, confirmed...)
		default:
			if code == 25 || code == 38 {
				if !bytes.Equal(d.take(16), confirmed) {
					return nil, 0, errors.New("I/O did not use confirmed OPEN state")
				}
			}
			return other(code, d)
		}
		return e, 0, nil
	})
	return v, &closed
}

func TestV4WriteStableProgress(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint(mismatch), func(t *testing.T) {
			var received bytes.Buffer
			var progress []uint64
			v, closed := transferPeer4(t, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 38:
					offset := d.u64()
					stable := d.u32()
					data := d.opaque(32768)
					if offset != uint64(received.Len()) || stable != 2 {
						return nil, 0, errors.New("invalid WRITE")
					}
					n := min(2, len(data))
					received.Write(data[:n])
					e.u32(uint32(n))
					e.u32(0)
					e = append(e, []byte("verifier")...)
				case 5:
					d.u64()
					d.u32()
					if mismatch {
						e = append(e, []byte("rebooted")...)
					} else {
						e = append(e, []byte("verifier")...)
					}
				default:
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				return e, 0, nil
			})
			n, err := v.write(context.Background(), []byte("file"), bytes.NewBufferString("payload"), func(n uint64) { progress = append(progress, n) })
			if !mismatch && !*closed {
				t.Fatal("open state was not closed")
			}
			if mismatch {
				if *closed || !v.c.nfs.closed || !v.stateLost.Load() {
					t.Fatal("rebooted state was reused instead of closing the connection")
				}
				if err == nil || n != 0 || len(progress) != 0 {
					t.Fatalf("uncommitted bytes reported: %d %v %v", n, progress, err)
				}
			} else if err != nil || n != 7 || received.String() != "payload" || fmt.Sprint(progress) != "[2 4 6 7]" {
				t.Fatalf("transfer: %d %q %v %v", n, received.String(), progress, err)
			}
		})
	}
}

func TestV4ReadUsesOpenAndClosesOnWriterError(t *testing.T) {
	v, closed := transferPeer4(t, func(code uint32, d *decoder) (encoder, Status, error) {
		if code != 25 {
			return nil, 0, fmt.Errorf("unexpected operation %d", code)
		}
		if d.u64() != 0 || d.u32() != 32768 {
			return nil, 0, errors.New("invalid READ")
		}
		var e encoder
		e.u32(1)
		e.opaque([]byte("data"))
		return e, 0, nil
	})
	_, err := v.read(context.Background(), []byte("file"), failingWriter4{}, nil)
	if !errors.Is(err, io.ErrClosedPipe) || !*closed {
		t.Fatalf("writer error/close: %v %v", err, *closed)
	}
}

type failingWriter4 struct{}

func (failingWriter4) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestV4AttributeBoundsAndOwners(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 9 {
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				readBitmap4(d)
				var e encoder
				if bad {
					e.u32(^uint32(0))
					return e, 0, nil
				}
				bitmap4(&e, 1, 4, 8, 20, 33, 36, 37, 53)
				var a encoder
				a.u32(1)
				a.u64(1 << 40)
				a.u64(7)
				a.u64(9)
				a.u64(1 << 40)
				a.u32(0644)
				a.str("alice@example.test")
				a.str("staff@example.test")
				a.u64(1800000000)
				a.u32(123)
				e.opaque(a)
				return e, 0, nil
			})
			a, err := v.getAttr(context.Background(), []byte("file"))
			if bad {
				if err == nil {
					t.Fatal("oversized bitmap accepted")
				}
				return
			}
			if err != nil || a.Owner != "alice@example.test" || a.Group != "staff@example.test" || a.Size != 1<<40 || a.FSIDMinor != 9 || a.MTime.Nanosecond() != 123 {
				t.Fatalf("attrs: %+v %v", a, err)
			}
		})
	}
}

func TestV4SessionSequenceOnOperationFailure(t *testing.T) {
	sid := bytes.Repeat([]byte{3}, 16)
	expected := uint32(1)
	v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		if code == 53 {
			if !bytes.Equal(d.take(16), sid) || d.u32() != expected || d.u32() != 0 || d.u32() != 0 || !d.boolean() {
				return nil, 0, errors.New("invalid SEQUENCE")
			}
			e = append(e, sid...)
			e.u32(expected)
			e.u32(0)
			e.u32(0)
			e.u32(0)
			e.u32(0)
			expected++
			return e, 0, nil
		}
		return nil, Status(13), nil
	})
	v.session = sid
	v.sequence = 1
	for i := 0; i < 2; i++ {
		if err := v.compound(context.Background(), op4(24, nil, nil)); !errors.Is(err, Status(13)) {
			t.Fatal(err)
		}
	}
	if v.sequence != 3 {
		t.Fatalf("sequence did not advance: %d", v.sequence)
	}
}

func TestV4LeaseRenewalStops(t *testing.T) {
	renewed := make(chan struct{}, 2)
	v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 9:
			readBitmap4(d)
			bitmap4(&e, 10)
			var a encoder
			a.u32(3)
			e.opaque(a)
		case 30:
			if d.u64() != 123 {
				return nil, 0, errors.New("invalid RENEW")
			}
			renewed <- struct{}{}
		default:
			return nil, 0, fmt.Errorf("unexpected operation %d", code)
		}
		return e, 0, nil
	})
	if err := v.keepAlive(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer v.close(context.Background())
	select {
	case <-renewed:
		v.mu.Lock()
		v.mu.Unlock()
	case <-time.After(3 * time.Second):
		t.Fatal("lease was not renewed")
	}
}

func FuzzV4AttributeBitmap(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 2})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		d := &decoder{b: b}
		bits := readBitmap4(d)
		if len(bits) > 96 {
			t.Fatal("unbounded bitmap")
		}
	})
}

func TestV4ReadDirPagedAttributes(t *testing.T) {
	sid := []byte("verifier")
	calls := 0
	v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
		if code != 26 {
			return nil, 0, fmt.Errorf("unnecessary attribute lookup %d", code)
		}
		cookie := d.u64()
		verifier := d.take(8)
		d.u32()
		d.u32()
		readBitmap4(d)
		calls++
		if cookie != 0 && (cookie != 42 || !bytes.Equal(verifier, sid)) {
			return nil, 0, errors.New("invalid page cookie/verifier")
		}
		var e encoder
		e = append(e, sid...)
		if cookie == 0 {
			e.u32(1)
			e.u64(42)
			e.str("file")
			bitmap4(&e, 1, 4, 19, 33, 36, 37)
			var a encoder
			a.u32(1)
			a.u64(7)
			a.opaque([]byte("file"))
			a.u32(0644)
			a.str("alice")
			a.str("staff")
			e.opaque(a)
			e.u32(0)
			e.u32(0)
		} else {
			e.u32(0)
			e.u32(1)
		}
		return e, 0, nil
	})
	entries, err := v.readdir(context.Background(), []byte("root"))
	if err != nil || calls != 2 || len(entries) != 1 || entries[0].Attr.Owner != "alice" || v.parents["file"].name != "file" {
		t.Fatalf("paged listing: %+v %v", entries, err)
	}
}
