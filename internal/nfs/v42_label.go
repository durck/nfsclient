package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

const MaxSecurityLabel = 4096

// SecurityLabel transports an opaque RFC 7862 sec_label attribute. It does
// not interpret a MAC policy or provide local label enforcement.
type SecurityLabel struct {
	Format uint32 `json:"format"`
	Policy uint32 `json:"policy"`
	Data   []byte `json:"data"`
}

func (c *Client) GetSecurityLabel(ctx context.Context, fh []byte) (SecurityLabel, error) {
	if c.v4 == nil || c.v4.minor != 2 {
		return SecurityLabel{}, ErrRequiresV42
	}
	if err := ctx.Err(); err != nil {
		return SecurityLabel{}, err
	}
	if err := c.v4.checkLockedIO(fh, 1); err != nil {
		return SecurityLabel{}, err
	}
	var result SecurityLabel
	present := false
	err := c.v4.attrs(ctx, fh, []uint32{80}, func(_ uint32, d *decoder) {
		present = true
		result.Format, result.Policy = d.u32(), d.u32()
		result.Data = append([]byte(nil), d.opaque(MaxSecurityLabel)...)
	})
	if err == nil && !present {
		err = Status(10032)
	} // ATTRNOTSUPP: never invent an empty label.
	if err == nil {
		err = c.v4.checkLockedIO(fh, 1)
	}
	if err != nil {
		return SecurityLabel{}, err
	}
	return result, nil
}

// SetSecurityLabel performs one SETATTR and verifies its readback on the same
// handle. An error can follow a successful mutation; there is no replay/rollback.
func (c *Client) SetSecurityLabel(ctx context.Context, fh []byte, label SecurityLabel) error {
	if c.v4 == nil || c.v4.minor != 2 {
		return ErrRequiresV42
	}
	if len(label.Data) > MaxSecurityLabel {
		return fmt.Errorf("security label exceeds %d bytes", MaxSecurityLabel)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v := c.v4
	if err := v.checkLockedIO(fh, 2); err != nil {
		return err
	}
	var value encoder
	value.u32(label.Format)
	value.u32(label.Policy)
	value.opaque(label.Data)
	e := make(encoder, 16) // Metadata-only SETATTR permits the anonymous stateid.
	if l := v.lockFor(fh); l != nil {
		copy(e, l.sid)
	}
	bitmap4(&e, 80)
	e.opaque(value)
	if v.channel.Request == 0 && v.maxRequestPayload != 0 && uint32(len(e)) > v.maxRequestPayload {
		return errors.New("security label exceeds negotiated request budget")
	}
	op := op4(34, e, func(d *decoder) {
		bits := readBitmap4(d)
		if d.err == nil && (len(bits) != 1 || bits[0] != 80) {
			d.err = errors.New("server did not acknowledge the security label")
		}
	})
	op.failure = func(d *decoder) {
		// SETATTR carries attrsset on failure too. Only the requested bit is valid.
		for _, bit := range readBitmap4(d) {
			if bit != 80 {
				d.err = errors.New("unsolicited attribute in failed label SETATTR")
			}
		}
	}
	if err := v.compound(ctx, fh4(fh), op); err != nil {
		return fmt.Errorf("security label change failed; inspect the target before retrying (no replay): %w", err)
	}
	if err := v.checkLockedIO(fh, 2); err != nil {
		return fmt.Errorf("label acknowledged, but lock state lost: %w", err)
	}
	got, err := c.GetSecurityLabel(ctx, fh)
	if err != nil {
		return fmt.Errorf("label acknowledged, but readback failed: %w", err)
	}
	if got.Format != label.Format || got.Policy != label.Policy || !bytes.Equal(got.Data, label.Data) {
		return errors.New("label acknowledged, but readback differs; no rollback or replay")
	}
	return nil
}
