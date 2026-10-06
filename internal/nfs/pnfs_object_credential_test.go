package nfs

import (
	"bytes"
	"nfsclient/internal/iscsi"
	"nfsclient/internal/testiscsi"
	"testing"
	"time"
)

func TestObjectCredentialDecodeLifetime(t *testing.T) {
	id := bytes.Repeat([]byte{0x81}, 16)
	cap, key := testiscsi.OSDCredential(bytes.Repeat([]byte{2}, 20), bytes.Repeat([]byte{3}, 20), 0x10000, 0x10001, iscsi.ObjectRead|iscsi.ObjectGetAttributes, time.Now().Add(time.Hour))
	wire := append(encoder(nil), id...)
	wire.u64(0x10000)
	wire.u64(0x10001)
	wire.u32(1)
	wire.u32(0)
	wire.opaque(key)
	wire.opaque(cap)
	d := &decoder{b: bytes.Clone(wire)}
	raw := d.b
	c := decodeObjectCredential(d, false)
	if d.err != nil || !c.credential.Secured() {
		t.Fatal(d.err)
	}
	if !bytes.Equal(raw[44:64], make([]byte, 20)) {
		t.Fatal("decoded response retains capability key")
	}
	if c.credential.Check(c.partition, c.object, iscsi.ObjectRead) != nil {
		t.Fatal("owned credential erased prematurely")
	}
	l := &fileLayout{object: &objectLayout{components: []objectCredential{c}}}
	closeObjectLayouts([]*fileLayout{l, l})
	if c.credential.Check(c.partition, c.object, iscsi.ObjectRead) == nil {
		t.Fatal("returned layout retains usable key")
	}
	// A duplicate component aborts decoding after both credentials were read;
	// neither accepted prefix nor the failing component may keep its key.
	var body encoder
	body.u32(2)
	body.u64(97)
	for _, n := range []uint32{0, 0, 0, 1, 0, 2} {
		body.u32(n)
	}
	body = append(body, wire...)
	body = append(body, wire...)
	bad := &decoder{b: body}
	decoded := decodeObjectLayout(bad)
	if bad.err == nil {
		t.Fatal("duplicate accepted")
	}
	for _, part := range decoded.components {
		if part.credential.Check(part.partition, part.object, 0) == nil {
			t.Fatal("rejected layout retains usable key")
		}
	}
}
