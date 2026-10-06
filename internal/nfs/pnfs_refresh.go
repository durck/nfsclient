package nfs

import (
	"bytes"
	"context"
	"errors"
	"slices"
)

type deviceNotice struct {
	generation, applied uint64
	invalid             bool
	deleted             bool
}

var errPNFSDeviceChange = errors.New("pNFS device immediately changed; refresh required")
var errPNFSDeviceDeleted = errors.New("pNFS device deleted; fresh layout required")
var errPNFSDevicePending = errors.New("pNFS device changed during a read batch; refresh required")

func cloneDeviceNotices(original map[string]deviceNotice) map[string]deviceNotice {
	copy := make(map[string]deviceNotice, len(original))
	for id, notice := range original {
		copy[id] = notice
	}
	return copy
}

// Decode transactionally into the callback's private copy. Unknown device IDs
// and other layout types are ignored without growing the retained inventory.
func decodeDeviceNotices(d *decoder, notices map[string]deviceNotice, layoutType uint32) {
	n := d.u32()
	if n > 64 {
		d.err = errors.New("pNFS device notification limit")
		return
	}
	for range n {
		bits := readBitmap4(d)
		sub := &decoder{b: d.opaque(4096)}
		if len(bits) == 0 {
			d.err = errors.New("empty pNFS device notification")
			return
		}
		for _, bit := range bits {
			if bit != 1 && bit != 2 {
				d.err = errors.New("unsupported pNFS device notification")
				return
			}
			kind, id := sub.u32(), string(sub.take(16))
			invalid := bit == 2
			if bit == 1 {
				invalid = sub.boolean()
			}
			if notice, ok := notices[id]; ok && kind == layoutType {
				if notice.generation == ^uint64(0) {
					d.err = errors.New("pNFS device generation exhausted")
					return
				}
				notice.generation++
				notice.invalid = notice.invalid || invalid
				notice.deleted = notice.deleted || bit == 2
				notices[id] = notice
			}
		}
		if sub.err != nil || len(sub.b) != 0 {
			d.err = errors.New("malformed pNFS device notification body")
			return
		}
	}
}

func (r *layoutRecall) devicesPending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, notice := range r.devices {
		if notice.generation != notice.applied {
			return true
		}
	}
	return false
}

// Several initial segment queries can share a device ID. A newer query must
// not acknowledge a generation still missing from an earlier segment.
func (r *layoutRecall) acknowledgeDeviceGenerations(layouts []*fileLayout) {
	minimum := map[string]uint64{}
	add := func(device []byte, generation uint64) {
		id := string(device)
		if old, ok := minimum[id]; !ok || generation < old {
			minimum[id] = generation
		}
	}
	for _, l := range layouts {
		if l.flex != nil {
			for _, ds := range layoutDeviceComponents(l, r.writeDevices) {
				add(ds.device, ds.deviceGeneration)
			}
		} else {
			add(l.device, l.deviceGeneration)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, generation := range minimum {
		if notice, ok := r.devices[id]; ok {
			notice.applied = generation
			if notice.generation == generation && !notice.deleted {
				notice.invalid = false
			}
			r.devices[id] = notice
		}
	}
}

func layoutDeviceComponents(l *fileLayout, write bool) []*flexDS {
	if l.flex == nil {
		return nil
	}
	if !write {
		return l.flex.selected
	}
	var components []*flexDS
	for _, mirror := range l.flex.writeMirrors() {
		components = append(components, mirror...)
	}
	return components
}

func (r *layoutRecall) registerLayoutDevices(layouts []*fileLayout, write bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.deletedDevices) > 4096 {
		return errors.New("pNFS deleted-device tombstone limit; reconnect")
	}
	notices := map[string]deviceNotice{}
	add := func(device []byte) error {
		id := string(device)
		if r.deletedDevices[id] {
			return errors.New("server reused a deleted pNFS device ID")
		}
		notices[id] = r.devices[id]
		return nil
	}
	for _, l := range layouts {
		if l.flex == nil {
			if err := add(l.device); err != nil {
				return err
			}
			continue
		}
		for _, ds := range layoutDeviceComponents(l, write) {
			if err := add(ds.device); err != nil {
				return err
			}
		}
	}
	r.deviceNotifications, r.writeDevices, r.devices = true, write, notices
	return nil
}

// Only address mappings may change. Stripe positions and filehandle semantics
// still belong to the original grant. Workers have joined before this runs.
func (v *v4Client) refreshLayoutDevices(ctx context.Context, fh []byte, layouts []*fileLayout, o PNFSOptions, attempts *int) error {
	for {
		if err := errors.Join(ctx.Err(), v.layoutRefreshUsable(fh)); err != nil {
			return err
		}
		v.recall.mu.Lock()
		var pending string
		for id, notice := range v.recall.devices {
			if notice.deleted {
				v.recall.mu.Unlock()
				return errPNFSDeviceDeleted
			}
			if notice.generation != notice.applied {
				pending = id
				break
			}
		}
		v.recall.mu.Unlock()
		if pending == "" {
			return nil
		}
		if *attempts == 8 {
			return errors.New("pNFS device refresh limit reached")
		}
		*attempts++
		if o.Layout == "flex" {
			if err := v.refreshFlexDevice(ctx, fh, layouts, []byte(pending), o); err != nil {
				return err
			}
			continue
		}
		var matching []*fileLayout
		for _, l := range layouts {
			if bytes.Equal(l.device, []byte(pending)) {
				matching = append(matching, l)
			}
		}
		if len(matching) == 0 {
			return errors.New("pNFS changed device has no retained layout")
		}
		next := *matching[0]
		next.indices, next.servers, next.endpoints = nil, nil, nil
		if err := v.prepareLayoutDevice(ctx, &next, o); err != nil {
			return err
		}
		for _, l := range matching {
			if !slices.Equal(l.indices, next.indices) || len(l.servers) != len(next.servers) {
				return errors.New("pNFS device refresh changed stripe topology")
			}
		}
		if err := errors.Join(ctx.Err(), v.layoutRefreshUsable(fh)); err != nil {
			return err
		}
		for _, l := range matching {
			l.servers, l.endpoints = next.servers, next.endpoints
			l.deviceGeneration = next.deviceGeneration
		}
		v.recall.acknowledgeDeviceGenerations(matching)
		// A callback racing GETDEVICEINFO leaves generation > applied. Query
		// again within the same global budget before opening any new DS path.
	}
}

// Only the notification barrier is bypassed for an address query. Metadata
// lease/lock/recall checks still run; DELETE cannot reuse the existing layout.
func (v *v4Client) layoutRefreshUsable(fh []byte) error {
	err := v.layoutUsable(fh)
	if errors.Is(err, errPNFSDeviceChange) {
		return nil
	}
	return err
}
