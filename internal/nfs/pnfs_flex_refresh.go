package nfs

import (
	"bytes"
	"context"
	"errors"
)

// A shared device describes protocol/address choices, while every segment
// retains its own filehandle and stateid. Decode one new mapping against each
// retained handle array before committing any component.
func (v *v4Client) refreshFlexDevice(ctx context.Context, fh []byte, layouts []*fileLayout, device []byte, o PNFSOptions) error {
	var matching []*flexDS
	for _, l := range layouts {
		if l.flex == nil {
			return errors.New("mixed layout types during Flex device refresh")
		}
		for _, ds := range layoutDeviceComponents(l, v.recall.writeDevices) {
			if bytes.Equal(ds.device, device) {
				matching = append(matching, ds)
			}
		}
	}
	if len(matching) == 0 {
		return errors.New("changed Flex device has no selected component")
	}
	next := make([]flexDS, len(matching))
	var body []byte
	for i, old := range matching {
		next[i] = *old
		next[i].endpoints, next[i].handle = nil, nil
		if i == 0 {
			var err error
			body, err = v.fetchFlexDevice(ctx, &next[i], o)
			if err != nil {
				return err
			}
		} else {
			d := &decoder{b: body}
			decodeFlexDevice(d, &next[i], o)
			if d.err != nil {
				return d.err
			}
			next[i].deviceGeneration = next[0].deviceGeneration
		}
		if old.major != 4 || next[i].major != old.major || next[i].minor != old.minor ||
			next[i].rsize != old.rsize || next[i].wsize != old.wsize || !bytes.Equal(next[i].handle, old.handle) || len(next[i].endpoints) == 0 {
			return errors.New("flex device refresh changed protocol/handle/limits or has no approved address")
		}
	}
	if err := errors.Join(ctx.Err(), v.layoutRefreshUsable(fh)); err != nil {
		return err
	}
	for i, ds := range matching {
		ds.endpoints, ds.deviceGeneration = next[i].endpoints, next[i].deviceGeneration
	}
	v.recall.acknowledgeDeviceGenerations(layouts)
	return nil
}
