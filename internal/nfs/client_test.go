package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type replyFunc func(program, procedure uint32, args *decoder) (encoder, error)

// A scripted peer tests wire-level behavior not implemented by the integration
// server, including EXPORT, short writes, and unstable-write COMMIT replies.
func scriptedClient(t *testing.T, reply replyFunc, allowCancelledWrite ...bool) *Client {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		for {
			data, err := readRecord(server)
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				done <- err
				return
			}
			d := &decoder{b: data}
			xid := d.u32()
			d.u32()
			d.u32()
			program := d.u32()
			d.u32()
			procedure := d.u32()
			d.u32()
			d.opaque(400)
			d.u32()
			d.opaque(400)
			payload, err := reply(program, procedure, d)
			if err != nil {
				done <- err
				return
			}
			var response encoder
			response.u32(xid)
			response.u32(1)
			response.u32(0)
			response.u32(0)
			response.u32(0)
			response.u32(0)
			response = append(response, payload...)
			if _, err := server.Write(record(response, true)); err != nil {
				// A cancelled parallel batch can close a peer while its valid
				// response is being written. Request/decoder errors stay strict.
				if len(allowCancelledWrite) > 0 && allowCancelledWrite[0] && errors.Is(err, io.ErrClosedPipe) {
					err = nil
				}
				done <- err
				return
			}
		}
	}()
	rpc := &rpcClient{conn: client, timeout: time.Second}
	t.Cleanup(func() {
		client.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return &Client{nfs: rpc, mount: rpc, ReadSize: 32768, WriteSize: 32768, mounted: make(map[string]bool)}
}

func TestExports(t *testing.T) {
	c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
		if prog != mountProgram || proc != 5 {
			return nil, fmt.Errorf("wrong EXPORT call: %d/%d", prog, proc)
		}
		var e encoder
		e.u32(1)
		e.str("/data")
		e.u32(1)
		e.str("192.0.2.0/24")
		e.u32(1)
		e.str("@team")
		e.u32(0)
		e.u32(1)
		e.str("/other")
		e.u32(0)
		e.u32(0)
		return e, nil
	})
	exports, err := c.Exports(context.Background())
	if err != nil || len(exports) != 2 || exports[0].Path != "/data" || strings.Join(exports[0].Clients, ",") != "192.0.2.0/24,@team" || len(exports[1].Clients) != 0 {
		t.Fatalf("%+v %v", exports, err)
	}
}

func TestShortWriteAndCommit(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint(mismatch), func(t *testing.T) {
			var written bytes.Buffer
			commits := 0
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				d.opaque(64)
				offset := d.u64()
				count := d.u32()
				var e encoder
				e.u32(0)
				e.u32(0)
				e.u32(0)
				if proc == 7 {
					stable := d.u32()
					data := d.opaque(32768)
					if prog != nfsProgram || stable != 2 || len(data) != int(count) || offset != uint64(written.Len()) || d.err != nil {
						return nil, fmt.Errorf("bad WRITE request")
					}
					n := min(3, len(data))
					written.Write(data[:n])
					e.u32(uint32(n))
					e.u32(0)
					e = append(e, []byte("verifier")...)
				} else if proc == 21 {
					if offset+uint64(count) != uint64(written.Len()) {
						return nil, fmt.Errorf("bad COMMIT range")
					}
					commits++
					if mismatch {
						e = append(e, []byte("rebooted")...)
					} else {
						e = append(e, []byte("verifier")...)
					}
				} else {
					return nil, fmt.Errorf("unexpected procedure %d", proc)
				}
				return e, nil
			})
			var updates []uint64
			n, err := c.WriteFromProgress(context.Background(), []byte("fh"), strings.NewReader("abcdefgh"), func(done uint64) { updates = append(updates, done) })
			if mismatch {
				if len(updates) != 0 {
					t.Fatalf("progress reported uncommitted bytes: %v", updates)
				}
				if err == nil || !strings.Contains(err.Error(), "verifier changed") {
					t.Fatalf("%d %v", n, err)
				}
			} else if err != nil || n != 8 || written.String() != "abcdefgh" || commits != 3 {
				t.Fatalf("%d %v %q commits=%d", n, err, written.String(), commits)
			}
			if !mismatch && fmt.Sprint(updates) != "[3 6 8]" {
				t.Fatalf("short-write progress: %v", updates)
			}
		})
	}
}

func TestReadRejectsInvalidCountAndNoProgress(t *testing.T) {
	for _, tc := range []struct {
		count uint32
		data  string
		eof   bool
		bad   bool
	}{{1, "ab", true, true}, {0, "", false, true}, {0, "", true, false}, {2, "ab", true, false}} {
		t.Run(fmt.Sprintf("%d/%s/%t", tc.count, tc.data, tc.eof), func(t *testing.T) {
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				var e encoder
				e.u32(0)
				e.u32(0)
				e.u32(tc.count)
				if tc.eof {
					e.u32(1)
				} else {
					e.u32(0)
				}
				e.str(tc.data)
				return e, nil
			})
			var out bytes.Buffer
			_, err := c.ReadTo(context.Background(), []byte("fh"), &out)
			if (err != nil) != tc.bad {
				t.Fatalf("err=%v, bad=%t", err, tc.bad)
			}
		})
	}
}

func TestReadDirRejectsRepeatedCookie(t *testing.T) {
	c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
		var e encoder
		e.u32(0)
		e.u32(0)
		e = append(e, make([]byte, 8)...)
		e.u32(0)
		e.u32(0)
		return e, nil
	})
	if _, err := c.ReadDir(context.Background(), []byte("fh")); err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Fatalf("%v", err)
	}
}
