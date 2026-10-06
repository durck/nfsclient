package iscsi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// ObjectDevice implements the OSD-1 NOSEC read and ALLDATA profiles. Device identity
// is established by root attributes before any user object is read.
type ObjectDevice struct {
	session *Volume
	secured bool
}

func ValidObjectCapability(cap []byte) bool {
	return len(cap) == 80 && (cap[0] == 0 || cap[0] == 1) && cap[2] == 0
}

func objectCDB(action uint16, partition, object uint64, cap []byte) []byte {
	b := make([]byte, 200)
	b[0], b[7], b[11] = 0x7f, 192, 0x30
	binary.BigEndian.PutUint16(b[8:], action)
	binary.BigEndian.PutUint64(b[16:], partition)
	binary.BigEndian.PutUint64(b[24:], object)
	for _, off := range []int{56, 64, 72, 192, 196} {
		binary.BigEndian.PutUint32(b[off:], math.MaxUint32)
	}
	copy(b[80:160], cap)
	return b
}

func OpenObject(ctx context.Context, target Target, initiator string, timeout time.Duration, systemID, name, rootCap []byte) (_ *ObjectDevice, resultErr error) {
	return OpenObjectWithSecurity(ctx, target, initiator, timeout, systemID, name, rootCap, Security{})
}

func OpenObjectWithSecurity(ctx context.Context, target Target, initiator string, timeout time.Duration, systemID, name, rootCap []byte, policy Security) (_ *ObjectDevice, resultErr error) {
	root, err := NewObjectCredential(0, 0, rootCap, nil)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return OpenObjectWithCredential(ctx, target, initiator, timeout, systemID, name, root, policy)
}

func OpenObjectWithCredential(ctx context.Context, target Target, initiator string, timeout time.Duration, systemID, name []byte, root *ObjectCredential, policy Security) (_ *ObjectDevice, resultErr error) {
	if len(systemID) != 20 || bytes.Equal(systemID, make([]byte, 20)) || len(name) > 255 {
		return nil, errors.New("invalid OSD root identity")
	}
	if err := root.Check(0, 0, ObjectGetAttributes); err != nil {
		return nil, err
	}
	v, err := openSessionSecurity(ctx, target, initiator, timeout, false, policy)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			v.Close()
		}
	}()
	var cdb [16]byte
	cdb[0], cdb[4] = 0x12, 36
	inquiry := make([]byte, 36)
	if _, err = v.command(cdb, inquiry, nil, false); err != nil {
		return nil, err
	}
	if inquiry[0]&0x1f != 0x11 || inquiry[0]&0xe0 != 0 {
		return nil, errors.New("approved LUN is not an OSD logical unit")
	}
	o := &ObjectDevice{session: v, secured: root.Secured()}
	if root.Secured() {
		algorithm, err := o.attributeWithCredential(0, 0, root, 0x90000005, 0x80000000, 1)
		if err != nil {
			return nil, err
		}
		if algorithm[0] != 1 {
			return nil, errors.New("OSD algorithm slot zero is not HMAC-SHA1")
		}
	}
	got, err := o.attributeWithCredential(0, 0, root, 0x90000001, 3, 20)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got, systemID) {
		return nil, errors.New("OSD system ID mismatch")
	}
	if len(name) != 0 {
		got, err = o.attributeWithCredential(0, 0, root, 0x90000001, 9, len(name))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, name) {
			return nil, errors.New("OSD name mismatch")
		}
	}
	return o, nil
}

// attribute uses the OSD-1 list format: a bidirectional command carries an
// eight-byte attribute descriptor after the four-byte request list header.
func (o *ObjectDevice) attribute(partition, object uint64, cap []byte, page, number uint32, length int) ([]byte, error) {
	if o.secured || !ValidObjectCapability(cap) || length < 1 || length > 255 {
		return nil, errors.New("unsupported OSD attribute request")
	}
	v := o.session
	v.mu.Lock()
	defer v.mu.Unlock()
	cdb := objectCDB(0x880e, partition, object, cap)
	binary.BigEndian.PutUint32(cdb[52:], 12)
	binary.BigEndian.PutUint32(cdb[56:], 0)
	binary.BigEndian.PutUint32(cdb[60:], uint32(14+length))
	binary.BigEndian.PutUint32(cdb[64:], 0)
	out := make([]byte, 12)
	out[0] = 1
	binary.BigEndian.PutUint32(out[4:], page)
	binary.BigEndian.PutUint32(out[8:], number)
	in := make([]byte, 14+length)
	if _, err := v.commandBytes(cdb, in, out, false); err != nil {
		return nil, err
	}
	if in[0] != 9 || in[1] != 0 || binary.BigEndian.Uint16(in[2:]) != uint16(len(in)-4) || binary.BigEndian.Uint32(in[4:]) != page || binary.BigEndian.Uint32(in[8:]) != number || binary.BigEndian.Uint16(in[12:]) != uint16(length) {
		return nil, v.poison(errors.New("OSD attribute reply mismatch"))
	}
	return in[14:], nil
}

func (o *ObjectDevice) Length(partition, object uint64, cap []byte) (uint64, error) {
	if partition < 0x10000 || object < 0x10000 {
		return 0, errors.New("reserved OSD object identifier")
	}
	b, err := o.attribute(partition, object, cap, 1, 0x82, 8)
	if err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint64(b)
	if n > math.MaxInt64 {
		o.session.mu.Lock()
		defer o.session.mu.Unlock()
		return 0, o.session.poison(errors.New("OSD object length exceeds int64"))
	}
	return n, nil
}

func (o *ObjectDevice) Read(partition, object, offset uint64, cap, data []byte) error {
	if o.secured || partition < 0x10000 || object < 0x10000 || !ValidObjectCapability(cap) || len(data) == 0 || len(data) > maxSegment || offset > math.MaxInt64-uint64(len(data)) {
		return errors.New("unsupported OSD object read")
	}
	v := o.session
	v.mu.Lock()
	defer v.mu.Unlock()
	cdb := objectCDB(0x8805, partition, object, cap)
	binary.BigEndian.PutUint64(cdb[36:], uint64(len(data)))
	binary.BigEndian.PutUint64(cdb[44:], offset)
	_, err := v.commandBytes(cdb, data, nil, false)
	return err
}

func (o *ObjectDevice) Check() error { return o.session.Check() }
func (o *ObjectDevice) Close() error { return o.session.Close() }
