package iscsi

import (
	"encoding/binary"
	"errors"
	"math"
)

func decodeCapacity(data []byte) (size, sector int64, err error) {
	if len(data) != 32 {
		return 0, 0, errors.New("invalid SCSI capacity length")
	}
	last := binary.BigEndian.Uint64(data[:8])
	block := binary.BigEndian.Uint32(data[8:12])
	if block != 512 && block != 4096 {
		return 0, 0, errors.New("iSCSI supports only 512-byte and 4096-byte logical sectors")
	}
	if last >= uint64(math.MaxInt64)/uint64(block) {
		return 0, 0, errors.New("iSCSI capacity exceeds int64")
	}
	return int64(last+1) * int64(block), int64(block), nil
}
