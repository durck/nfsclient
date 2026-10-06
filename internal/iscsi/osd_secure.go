package iscsi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

func objectMAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha1.New, key)
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}
func objectAlign(n int) int { return (n + 255) &^ 255 }

// secureCommand implements T10/04-193r4 4.9.3.5 and OSD-1 data integrity
// structures. It stages all incoming bytes until both data and status MACs
// validate. No failed or ambiguous command is retried.
// The credential lock spans the command, so Close cannot erase an active key.
func (o *ObjectDevice) secureCommand(partition, object, offset uint64, c *ObjectCredential, action uint16, data []byte, page, number uint32, length int) ([]byte, error) {
	rights := ObjectGetAttributes
	switch action {
	case 0x8805:
		rights |= ObjectRead
	case 0x8806:
		rights |= ObjectWrite
	case 0x8808:
		rights |= ObjectManage
	case 0x880e:
	default:
		return nil, errors.New("unsupported secured OSD action")
	}
	if !o.secured || c == nil || !c.Secured() || len(data) > ObjectMaxTransfer || offset > math.MaxInt64-uint64(len(data)) {
		return nil, errors.New("invalid secured OSD command")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLocked(partition, object, rights); err != nil {
		return nil, err
	}
	v := o.session
	v.mu.Lock()
	defer v.mu.Unlock()
	b := objectCDB(action, partition, object, c.cap)
	if action == 0x8805 || action == 0x8806 {
		binary.BigEndian.PutUint64(b[36:], uint64(len(data)))
		binary.BigEndian.PutUint64(b[44:], offset)
	}
	// Every command requests the response ICV. Attribute reads request their
	// value first and the response ICV second, with exact bounded list lengths.
	get := make([]byte, 12)
	get[0] = 1
	binary.BigEndian.PutUint32(get[4:], 0xfffffffe)
	binary.BigEndian.PutUint32(get[8:], 1)
	attrLength := 34
	if action == 0x880e {
		if length < 1 || length > 255 {
			return nil, errors.New("invalid OSD attribute length")
		}
		get = make([]byte, 20)
		get[0] = 1
		binary.BigEndian.PutUint32(get[4:], page)
		binary.BigEndian.PutUint32(get[8:], number)
		binary.BigEndian.PutUint32(get[12:], 0xfffffffe)
		binary.BigEndian.PutUint32(get[16:], 1)
		attrLength += 10 + length
	}
	outCommand, inCommand := 0, 0
	if action == 0x8806 {
		outCommand = len(data)
	}
	if action == 0x8805 {
		inCommand = len(data)
	}
	getOff := objectAlign(outCommand)
	outICV := objectAlign(getOff + len(get))
	attrOff := objectAlign(inCommand)
	inICV := objectAlign(attrOff + attrLength)
	out := make([]byte, outICV+44)
	in := make([]byte, inICV+36)
	defer clear(out)
	defer clear(in)
	copy(out, data[:outCommand])
	copy(out[getOff:], get)
	binary.BigEndian.PutUint64(out[outICV:], uint64(outCommand))
	binary.BigEndian.PutUint64(out[outICV+16:], uint64(len(get)))
	copy(out[outICV+24:], objectMAC(c.key, out[:outCommand], get))
	binary.BigEndian.PutUint32(b[52:], uint32(len(get)))
	binary.BigEndian.PutUint32(b[56:], uint32(getOff>>8))
	binary.BigEndian.PutUint32(b[60:], uint32(attrLength))
	binary.BigEndian.PutUint32(b[64:], uint32(attrOff>>8))
	binary.BigEndian.PutUint32(b[192:], uint32(inICV>>8))
	binary.BigEndian.PutUint32(b[196:], uint32(outICV>>8))
	stamp := time.Now().UnixMilli()
	for i := 185; i >= 180; i-- {
		b[i] = byte(stamp)
		stamp >>= 8
	}
	if _, err := rand.Read(b[186:192]); err != nil {
		return nil, err
	}
	copy(b[160:180], objectMAC(c.key, b))
	if _, err := v.commandBytes(b, in, out, false); err != nil {
		return nil, err
	}
	fail := func() ([]byte, error) { return nil, v.poison(errors.New("OSD authenticated reply rejected")) }
	integrity := in[inICV:]
	attrs := in[attrOff : attrOff+attrLength]
	if binary.BigEndian.Uint64(integrity) != uint64(inCommand) || binary.BigEndian.Uint64(integrity[8:]) != uint64(attrLength) || !hmac.Equal(integrity[16:], objectMAC(c.key, in[:inCommand], attrs)) {
		return fail()
	}
	if attrs[0] != 9 || attrs[1] != 0 || int(binary.BigEndian.Uint16(attrs[2:])) != attrLength-4 {
		return fail()
	}
	at := 4
	var value []byte
	if action == 0x880e {
		if binary.BigEndian.Uint32(attrs[at:]) != page || binary.BigEndian.Uint32(attrs[at+4:]) != number || int(binary.BigEndian.Uint16(attrs[at+8:])) != length {
			return fail()
		}
		value = attrs[at+10 : at+10+length]
		at += 10 + length
	}
	if binary.BigEndian.Uint32(attrs[at:]) != 0xfffffffe || binary.BigEndian.Uint32(attrs[at+4:]) != 1 || binary.BigEndian.Uint16(attrs[at+8:]) != 20 || !hmac.Equal(attrs[at+10:], objectMAC(c.key, b[180:192], []byte{0})) {
		return fail()
	}
	if err := c.checkLocked(partition, object, rights); err != nil {
		return nil, v.poison(err)
	}
	if action == 0x8805 {
		copy(data, in[:inCommand])
	}
	return append([]byte(nil), value...), nil
}

func (o *ObjectDevice) attributeWithCredential(partition, object uint64, c *ObjectCredential, page, number uint32, length int) ([]byte, error) {
	if c == nil || o.secured != c.Secured() {
		return nil, errors.New("OSD credential is required")
	}
	if c.Secured() {
		return o.secureCommand(partition, object, 0, c, 0x880e, nil, page, number, length)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLocked(partition, object, ObjectGetAttributes); err != nil {
		return nil, err
	}
	return o.attribute(partition, object, c.cap, page, number, length)
}
func (o *ObjectDevice) LengthWithCredential(partition, object uint64, c *ObjectCredential) (uint64, error) {
	if partition < 0x10000 || object < 0x10000 {
		return 0, errors.New("reserved OSD object identifier")
	}
	b, err := o.attributeWithCredential(partition, object, c, 1, 0x82, 8)
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
func (o *ObjectDevice) ReadWithCredential(partition, object, offset uint64, c *ObjectCredential, data []byte) error {
	if c == nil || o.secured != c.Secured() || len(data) == 0 {
		return errors.New("invalid OSD read")
	}
	if c.Secured() {
		_, err := o.secureCommand(partition, object, offset, c, 0x8805, data, 0, 0, 0)
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLocked(partition, object, ObjectRead); err != nil {
		return err
	}
	return o.Read(partition, object, offset, c.cap, data)
}
func (o *ObjectDevice) WriteWithCredential(partition, object, offset uint64, c *ObjectCredential, data []byte) error {
	if len(data) == 0 || partition < 0x10000 || object < 0x10000 {
		return errors.New("invalid OSD write")
	}
	_, err := o.secureCommand(partition, object, offset, c, 0x8806, data, 0, 0, 0)
	return err
}
func (o *ObjectDevice) FlushWithCredential(partition, object uint64, c *ObjectCredential) error {
	if partition < 0x10000 || object < 0x10000 {
		return errors.New("invalid OSD flush")
	}
	_, err := o.secureCommand(partition, object, 0, c, 0x8808, nil, 0, 0, 0)
	return err
}
