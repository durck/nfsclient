package nfs

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// go-nfs v0.0.4's LINK handler mistakenly decodes SYMLINK XDR. Keep the
// standard LINK3args verified independently, without adapting to that defect.
func TestNFS3LinkWire(t *testing.T) {
	calls := 0
	c := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
		calls++
		if program != nfsProgram || proc != 15 || !bytes.Equal(d.opaque(64), []byte("source")) || !bytes.Equal(d.opaque(64), []byte("parent")) || d.str() != "alias" || d.err != nil || len(d.b) != 0 {
			return nil, errors.New("invalid LINK3args")
		}
		var e encoder
		e.u32(0) // status
		e.u32(0) // source post-op attributes
		e.u32(0)
		e.u32(0) // destination WCC
		return e, nil
	})
	if err := c.Link(context.Background(), []byte("source"), []byte("parent"), "alias"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if err := c.Link(context.Background(), []byte("source"), []byte("parent"), name); err == nil {
			t.Fatal("invalid link name accepted", name)
		}
	}
	if calls != 1 {
		t.Fatal("invalid name reached the server")
	}
}
