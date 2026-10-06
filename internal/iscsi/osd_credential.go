package iscsi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	ObjectRead          byte = 0x80
	ObjectWrite         byte = 0x40
	ObjectGetAttributes byte = 0x20
	ObjectManage        byte = 0x02
	ObjectMaxTransfer        = 65024
)

// ObjectCredential owns an immutable OSD-1 credential. Close waits for an
// in-flight authenticated command before erasing the capability key.
type ObjectCredential struct {
	mu                sync.Mutex
	cap, key          []byte
	partition, object uint64
	expiry            int64
	secured, closed   bool
}

func NewObjectCredential(partition, object uint64, cap, key []byte) (*ObjectCredential, error) {
	if len(cap) != 80 || (partition == 0) != (object == 0) || partition != 0 && (partition < 0x10000 || object < 0x10000) {
		return nil, errors.New("invalid OSD credential identity")
	}
	c := &ObjectCredential{partition: partition, object: object}
	if ValidObjectCapability(cap) && len(key) == 0 {
		c.cap = bytes.Clone(cap)
		return c, nil
	}
	// This bounded profile supports slot zero with HMAC-SHA1, confirmed by an
	// authenticated Root Policy/Security attribute during device discovery.
	if cap[0] != 1 || cap[1]&15 != 0 || cap[2] != 3 || cap[3] != 0 || len(key) != 20 || cap[50]&31 != 0 || !bytes.Equal(cap[51:55], make([]byte, 4)) || !bytes.Equal(cap[76:], make([]byte, 4)) {
		return nil, errors.New("OSD requires ALLDATA, algorithm slot zero and a 20-byte capability key")
	}
	if partition == 0 {
		if cap[48] != 1 || cap[55] != 0x20 || !bytes.Equal(cap[60:76], make([]byte, 16)) {
			return nil, errors.New("OSD root capability scope mismatch")
		}
	} else if cap[48] != 0x80 || cap[55] != 0x10 || binary.BigEndian.Uint64(cap[60:]) != partition || binary.BigEndian.Uint64(cap[68:]) != object {
		return nil, errors.New("OSD capability object scope mismatch")
	}
	for _, b := range cap[4:10] {
		c.expiry = c.expiry<<8 | int64(b)
	}
	if c.expiry == 0 || time.Now().UnixMilli() > c.expiry {
		return nil, errors.New("OSD capability expired or has no bounded expiry")
	}
	c.cap, c.key, c.secured = bytes.Clone(cap), bytes.Clone(key), true
	return c, nil
}

func (c *ObjectCredential) Secured() bool { return c != nil && c.secured }
func (c *ObjectCredential) checkLocked(partition, object uint64, rights byte) error {
	if c.closed || c.partition != partition || c.object != object {
		return errors.New("OSD credential closed or bound to another object")
	}
	if c.secured && (time.Now().UnixMilli() > c.expiry || c.cap[49]&rights != rights) {
		return errors.New("OSD capability expired or missing command rights")
	}
	return nil
}
func (c *ObjectCredential) Check(partition, object uint64, rights byte) error {
	if c == nil {
		return errors.New("OSD credential is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkLocked(partition, object, rights)
}
func (c *ObjectCredential) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.key)
	clear(c.cap)
	c.closed = true
}
