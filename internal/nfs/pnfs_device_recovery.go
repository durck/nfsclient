package nfs

import (
	"context"
	"errors"
)

func deviceRecoveryBarrier(err error) bool {
	return errors.Is(err, errPNFSDeviceChange) || errors.Is(err, errPNFSDeviceDeleted) || errors.Is(err, errPNFSDevicePending)
}

func (v *v4Client) hasActiveLayout() bool {
	v.recall.mu.Lock()
	defer v.recall.mu.Unlock()
	return v.recall.active
}

// Batch-local cancellation from a notification may accompany the barrier.
// An independent wire, authentication or server failure must never be hidden.
func onlyDeviceBarrier(err error) bool {
	if err == nil {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if !onlyDeviceBarrier(cause) {
				return false
			}
		}
		return true
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		return onlyDeviceBarrier(single.Unwrap())
	}
	return err == context.Canceled || err == errPNFSDeviceChange || err == errPNFSDeviceDeleted || err == errPNFSDevicePending
}

// Caller has joined all workers, committed every reported byte and retained
// the original OPEN/LOCK. A fresh grant never authorizes replay of old writes.
func (v *v4Client) recoverLayoutDevices(ctx context.Context, fh, sid []byte, size uint64, layouts []*fileLayout, o PNFSOptions, write bool, attempts *int) ([]*fileLayout, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := v.layoutUsable(fh); err != nil && !deviceRecoveryBarrier(err) {
		return nil, err
	}
	v.recall.mu.Lock()
	deleted := false
	for _, notice := range v.recall.devices {
		deleted = deleted || notice.deleted
	}
	v.recall.mu.Unlock()
	if deleted {
		if *attempts >= 8 {
			return nil, errors.New("pNFS device recovery limit reached")
		}
		*attempts++
		if err := v.returnLayoutAfterDelete(fh, true); err != nil {
			return nil, err
		}
		mode, kind := uint32(1), uint32(1)
		if write {
			mode = 2
		}
		if o.Layout == "flex" {
			kind = 4
		}
		fresh, err := v.getLayoutType(ctx, fh, sid, size, mode, kind)
		if err != nil {
			return nil, err
		}
		layouts = fresh
		if err := v.recall.registerLayoutDevices(layouts, write); err != nil {
			return nil, err
		}
		for _, l := range layouts {
			if l.flex != nil {
				if write {
					err = v.prepareFlexWriteDevices(ctx, l.flex, o)
				} else {
					err = v.prepareFlexReadDevices(ctx, l.flex, o)
				}
			} else {
				err = v.prepareLayoutDevice(ctx, l, o)
			}
			if err != nil {
				return nil, err
			}
		}
		v.recall.acknowledgeDeviceGenerations(layouts)
	}
	if err := v.refreshLayoutDevices(ctx, fh, layouts, o, attempts); err != nil {
		return nil, err
	}
	return layouts, nil
}
