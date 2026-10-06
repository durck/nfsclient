package nfs

import (
	"context"
	"errors"
	"slices"
)

func (v *v4Client) prepareFlexReadDevices(ctx context.Context, l *flexLayout, o PNFSOptions) error {
	if !o.MirrorFailover {
		return v.prepareFlexDevices(ctx, l, o)
	}
	// Approve and decode every possible replacement before opening any DS.
	for _, mirror := range l.mirrors {
		copy := *l
		copy.selected = mirror
		if err := v.prepareFlexDevices(ctx, &copy, o); err != nil {
			return err
		}
	}
	return nil
}

// A layout grants access to each mirror's distinct handle/global stateid.
// Unlike a path change, this may authenticate a different DS identity/SPN.
// The MDS principal and integrity/privacy service must remain unchanged.
func (c *Client) flexMirrorRecovery(ctx context.Context, usable func() error, get func(*flexDS) (*Client, string, error), retire func(*pnfsRead)) func(*pnfsRead) error {
	originals := map[*flexLayout][]*flexDS{}
	return func(r *pnfsRead) error {
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return err
		}
		if c.Security() != "krb5i" && c.Security() != "krb5p" {
			return errors.New("flex mirror recovery requires krb5i or krb5p")
		}
		l := r.flexLayout
		if l == nil || r.flex == nil || r.flex.major != 4 || r.ds == nil || r.ds.v4 == nil || r.ds.v4.serverIdentity == nil || r.ds.Security() != c.Security() || r.ds.principal != c.principal {
			return errors.New("flex failed mirror has no matching protected identity")
		}
		original, switched := originals[l]
		if !switched {
			original = l.selected
		}
		index := slices.Index(original, r.flex)
		if index < 0 {
			return errors.New("flex mirror recovery already used for this segment")
		}
		if !switched {
			var replacement []*flexDS
			var best uint64
			for _, mirror := range l.mirrors {
				if len(mirror) != len(original) || slices.Equal(mirror, original) {
					continue
				}
				var score uint64
				for _, ds := range mirror {
					score += uint64(ds.efficiency)
				}
				if replacement == nil || score > best {
					replacement, best = mirror, score
				}
			}
			if replacement == nil {
				return errors.New("flex layout has no alternate mirror")
			}
			originals[l], l.selected = original, replacement
		}
		component := l.selected[index]
		if component.major != 4 || component.rsize == 0 || len(component.endpoints) == 0 {
			return errors.New("flex alternate mirror was not approved as tight NFSv4")
		}
		retire(r)
		ds, endpoint, err := get(component)
		if err != nil {
			return err
		}
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return err
		}
		if ds.v4 == nil || ds.v4.serverIdentity == nil || ds.Security() != c.Security() || ds.principal != c.principal {
			return errors.New("flex alternate mirror changed protected identity or service")
		}
		r.ds, r.endpoint, r.flex = ds, endpoint, component
		r.handle, r.paths = component.handle, component.endpoints
		return nil
	}
}
