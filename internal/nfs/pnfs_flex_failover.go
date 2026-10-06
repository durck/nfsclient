package nfs

import "errors"

// Successful path recovery does not erase the original device error: RFC 8435
// section 7 requires reporting it at LAYOUTRETURN. Bound recovery attempts so
// the return can also hold every error from a final parallel batch.
func (v *v4Client) flexReadRecovery(recoverRead func(*pnfsRead) error) func(*pnfsRead) error {
	attempts := 0
	return func(r *pnfsRead) error {
		if attempts == 8 {
			return errors.New("flex read recovery limit reached")
		}
		attempts++
		v.recordFlexError(r.flex, r.offset, uint64(r.limit), r.ioErr)
		r.ioErr = nil // A failed replacement READ may record a new error.
		return recoverRead(r)
	}
}
