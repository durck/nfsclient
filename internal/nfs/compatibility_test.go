package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// These are protocol-boundary checks, not certification of any server product.
func TestCompatibilityVersionMismatch(t *testing.T) {
	for _, serverVersion := range []uint32{2, 4} {
		t.Run(fmt.Sprint(serverVersion), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				data, err := readRecord(server)
				if err != nil {
					done <- err
					return
				}
				d := &decoder{b: data}
				xid := d.u32()
				kind, rpcVersion, program, version, procedure, auth := d.u32(), d.u32(), d.u32(), d.u32(), d.u32(), d.u32()
				if kind != 0 || rpcVersion != 2 || program != nfsProgram || version != 3 || procedure != 1 || auth != 1 {
					done <- fmt.Errorf("unexpected request: %d/%d/%d/%d/%d/%d", kind, rpcVersion, program, version, procedure, auth)
					return
				}
				var response encoder
				for _, v := range []uint32{xid, 1, 0, 0, 0, 2, serverVersion, serverVersion} {
					response.u32(v)
				}
				_, err = server.Write(record(response, true))
				done <- err
			}()
			c := &Client{nfs: &rpcClient{conn: client, timeout: time.Second}}
			_, err := c.GetAttr(context.Background(), []byte("opaque"))
			if err == nil || !strings.Contains(err.Error(), "RPC accept status 2") {
				t.Fatalf("version mismatch not surfaced: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func compatibilityAttr(e *encoder) {
	for _, v := range []uint32{1, 0644, 1, 1000, 1000} {
		e.u32(v)
	}
	e.u64(1 << 40)
	e.u64(4096)
	e.u32(0)
	e.u32(0)
	e.u64(123)
	e.u64(1 << 40)
	for i := 0; i < 6; i++ {
		e.u32(0)
	}
}

func TestCompatibilityOpaqueHandlesAndOptionalAttributes(t *testing.T) {
	for _, length := range []int{1, 32, 64} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			fh := bytes.Repeat([]byte{0xab}, length)
			calls := 0
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				calls++
				var e encoder
				e.u32(0)
				switch proc {
				case 3:
					if !bytes.Equal(d.opaque(64), []byte("directory")) || d.str() != "large-file" {
						return nil, fmt.Errorf("bad lookup")
					}
					e.opaque(fh)
					e.u32(0)
					e.u32(0)
				case 1:
					if !bytes.Equal(d.opaque(64), fh) {
						return nil, fmt.Errorf("file handle changed")
					}
					compatibilityAttr(&e)
				default:
					return nil, fmt.Errorf("unexpected procedure %d", proc)
				}
				return e, d.err
			})
			n, err := c.Lookup(context.Background(), []byte("directory"), "large-file")
			if err != nil || calls != 2 || !bytes.Equal(n.Handle, fh) || n.Attr.Size != 1<<40 || n.Attr.FileID != 1<<40 {
				t.Fatalf("lookup: %+v calls=%d err=%v", n, calls, err)
			}
		})
	}
}

func TestCompatibilityTransferLimits(t *testing.T) {
	for _, tc := range []struct{ read, write uint32 }{{1024, 4096}, {1 << 20, 65536}, {0, 4096}} {
		t.Run(fmt.Sprintf("%d-%d", tc.read, tc.write), func(t *testing.T) {
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				if proc != 19 {
					return nil, fmt.Errorf("expected FSINFO")
				}
				var e encoder
				for _, v := range []uint32{0, 0, tc.read, tc.read, 1, tc.write, tc.write, 1, 4096} {
					e.u32(v)
				}
				e.u64(1 << 40)
				e.u32(1)
				e.u32(0)
				e.u32(0)
				return e, nil
			})
			err := c.Tune(context.Background(), []byte("fh"))
			if tc.read == 0 {
				if err == nil {
					t.Fatal("zero maximum accepted")
				}
				return
			}
			if err != nil || c.ReadSize != min(tc.read, 32768) || c.WriteSize != min(tc.write, 32768) {
				t.Fatalf("limits: %d/%d %v", c.ReadSize, c.WriteSize, err)
			}
		})
	}
}

func TestCompatibilityCapabilityErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		proc   uint32
		status Status
	}{
		{"readdirplus permission denied", 17, 13},
		{"fsinfo unsupported", 19, 10004},
		{"read-only create", 8, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				if proc != tc.proc {
					return nil, fmt.Errorf("unexpected fallback procedure %d", proc)
				}
				var e encoder
				e.u32(uint32(tc.status))
				return e, nil
			})
			var err error
			switch tc.proc {
			case 17:
				_, err = c.ReadDir(context.Background(), []byte("fh"))
			case 19:
				err = c.Tune(context.Background(), []byte("fh"))
			case 8:
				_, err = c.Create(context.Background(), []byte("fh"), "new", 0644, false)
			}
			var status Status
			if !errors.As(err, &status) || status != tc.status {
				t.Fatalf("expected status %d: %v", tc.status, err)
			}
		})
	}
}

func TestCompatibilityRejectsKerberosOnlyExport(t *testing.T) {
	c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
		if prog != mountProgram || proc != 1 {
			return nil, fmt.Errorf("unexpected call %d/%d", prog, proc)
		}
		var e encoder
		e.u32(0)
		e.opaque([]byte("fh"))
		e.u32(1)
		e.u32(390003)
		return e, nil
	})
	if _, err := c.Mount(context.Background(), "/data"); err == nil || !strings.Contains(err.Error(), "AUTH_SYS") {
		t.Fatalf("accepted Kerberos-only export: %v", err)
	}
}
