package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

func attrReply2(e *encoder, size uint32) {
	for _, v := range []uint32{1, 0644, 1, 1000, 1001, size, 4096, 0, 1, 7, 123, 0, 0, 1800000000, 123, 0, 0} {
		e.u32(v)
	}
}
func TestV2ReadAndLimits(t *testing.T) {
	for _, size := range []uint32{7, 1 << 31} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			fh := bytes.Repeat([]byte{7}, 32)
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				if proc != 6 || !bytes.Equal(d.take(32), fh) || d.u32() != 0 || d.u32() != 8192 || d.u32() != 0 || len(d.b) != 0 {
					return nil, fmt.Errorf("invalid NFSv2 READ")
				}
				var e encoder
				e.u32(0)
				attrReply2(&e, size)
				e.opaque([]byte("payload"))
				return e, nil
			})
			c.version = "2"
			c.ReadSize = 8192
			var out bytes.Buffer
			n, err := c.ReadTo(context.Background(), fh, &out)
			if size > maxV2File {
				if err == nil || n != 0 {
					t.Fatalf("large file accepted: %d %v", n, err)
				}
			} else if err != nil || n != 7 || out.String() != "payload" {
				t.Fatalf("read: %d %q %v", n, out.String(), err)
			}
		})
	}
}
func TestV2RejectsUnsafeCreateBeforeRPC(t *testing.T) {
	c := &Client{version: "2"}
	if _, err := c.Create(context.Background(), make([]byte, 32), "exists", 0644, false); err == nil {
		t.Fatal("unguarded CREATE allowed")
	}
	if _, err := c.GetAttr(context.Background(), []byte("short")); err == nil {
		t.Fatal("short file handle accepted")
	}
}

func TestV2WriteWireAndAcknowledgement(t *testing.T) {
	for _, bad := range []string{"", "short attributes", "wrong size", "non-file", "oversized attributes"} {
		t.Run(bad, func(t *testing.T) {
			fh := bytes.Repeat([]byte{9}, 32)
			var offset uint32
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				if prog != nfsProgram || proc != 8 || !bytes.Equal(d.take(32), fh) || d.u32() != 0 || d.u32() != offset || d.u32() != 0 {
					return nil, fmt.Errorf("invalid WRITE header")
				}
				data := d.opaque(8192)
				if d.err != nil || len(d.b) != 0 || len(data) == 0 {
					return nil, fmt.Errorf("invalid WRITE payload")
				}
				offset += uint32(len(data))
				var e encoder
				e.u32(0)
				if bad == "short attributes" {
					return e, nil
				}
				size := offset
				if bad == "wrong size" {
					size--
				}
				if bad == "oversized attributes" {
					size = 1 << 31
				}
				attrReply2(&e, size)
				if bad == "non-file" {
					binary.BigEndian.PutUint32(e[4:8], 2)
				}
				return e, nil
			})
			c.version, c.WriteSize = "2", 32768
			var progress uint64
			n, err := c.WriteFromProgress(context.Background(), fh, bytes.NewReader(bytes.Repeat([]byte{255}, 8193)), func(done uint64) { progress = done })
			if bad == "" {
				if err != nil || n != 8193 || progress != 8193 {
					t.Fatalf("write %d %d %v", n, progress, err)
				}
			} else if err == nil || n != 0 || progress != 0 {
				t.Fatalf("invalid acknowledgement counted: %d %d %v", n, progress, err)
			}
		})
	}
}

type emptyV2Reader struct{}

func (emptyV2Reader) Read([]byte) (int, error) { return 0, nil }

func TestV2WriteStopsWithoutRPC(t *testing.T) {
	c := &Client{version: "2", WriteSize: 8192}
	if _, err := c.write2(context.Background(), make([]byte, 32), emptyV2Reader{}, nil); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.write2(ctx, make([]byte, 32), bytes.NewReader([]byte("a")), nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	c.WriteSize = 0
	if _, err := c.write2(context.Background(), make([]byte, 32), emptyV2Reader{}, nil); err == nil {
		t.Fatal("zero chunk size accepted")
	}
}

func TestV2MountListAndMetadata(t *testing.T) {
	fh := bytes.Repeat([]byte{1}, 32)
	file := bytes.Repeat([]byte{2}, 32)
	lookups := 0
	c := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
		var e encoder
		e.u32(0)
		if program == mountProgram {
			if proc != 1 || d.str() != "/data" {
				return nil, fmt.Errorf("invalid MOUNTv1")
			}
			e = append(e, fh...)
			return e, nil
		}
		handle := d.take(32)
		if !bytes.Equal(handle, fh) && !bytes.Equal(handle, file) {
			return nil, fmt.Errorf("invalid handle")
		}
		switch proc {
		case 1:
			attrReply2(&e, 4096)
			binary.BigEndian.PutUint32(e[4:8], 2)
		case 4:
			if d.str() != "file" {
				return nil, fmt.Errorf("invalid LOOKUP")
			}
			lookups++
			e = append(e, file...)
			attrReply2(&e, 7)
		case 16:
			if d.u32() != 0 || d.u32() != 8192 {
				return nil, fmt.Errorf("invalid READDIR")
			}
			e.u32(1)
			e.u32(123)
			e.str("file")
			e.u32(42)
			e.u32(0)
			e.u32(1)
		case 17:
			for _, n := range []uint32{4096, 4096, 100, 50, 40} {
				e.u32(n)
			}
		case 2:
			if d.u32() != 0600 {
				return nil, fmt.Errorf("invalid mode")
			}
			for i := 0; i < 7; i++ {
				if d.u32() != ^uint32(0) {
					return nil, fmt.Errorf("SETATTR unexpectedly changes ownership/size/time")
				}
			}
			attrReply2(&e, 7)
		case 5:
			e.str("../target")
		case 14:
			if d.str() != "newdir" || d.u32() != 0755 {
				return nil, fmt.Errorf("invalid MKDIR")
			}
			d.take(28)
			e = append(e, file...)
			attrReply2(&e, 0)
			binary.BigEndian.PutUint32(e[36:40], 2)
		default:
			return nil, fmt.Errorf("unexpected v2 procedure %d", proc)
		}
		if len(d.b) != 0 {
			return nil, fmt.Errorf("trailing arguments")
		}
		return e, nil
	})
	c.version = "2"
	n, err := c.Mount(context.Background(), "/data")
	if err != nil || n.Attr.Type != 2 {
		t.Fatalf("mount: %+v %v", n, err)
	}
	if err := c.Tune(context.Background(), fh); err != nil || c.ReadSize != 4096 {
		t.Fatalf("STATFS: %v", err)
	}
	entries, err := c.ReadDir(context.Background(), fh)
	if err != nil || len(entries) != 1 || lookups != 1 || entries[0].Attr.GID != 1001 {
		t.Fatalf("listing: %+v %v", entries, err)
	}
	if err := c.Chmod(context.Background(), file, 0600); err != nil {
		t.Fatal(err)
	}
	if target, err := c.Readlink(context.Background(), file); err != nil || target != "../target" {
		t.Fatalf("readlink: %q %v", target, err)
	}
	if n, err := c.Create(context.Background(), fh, "newdir", 0755, true); err != nil || n.Attr.Type != 2 {
		t.Fatalf("mkdir: %+v %v", n, err)
	}
}
