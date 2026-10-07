package nfs

import (
	"context"
	"errors"
)

// AccessReport is a server observation for one object and identity. It is not
// a promise that a later operation succeeds. No permission is inferred from mode.
type AccessReport struct {
	Identity  string `json:"identity"`
	Requested uint32 `json:"requested"`
	Supported uint32 `json:"supported"`
	Allowed   uint32 `json:"allowed"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// Decision describes one requested permission bit, retaining unsupported checks.
func (r AccessReport) Decision(bit uint32) string {
	if r.Error != "" || bit == 0 || bit&(bit-1) != 0 || r.Requested&bit == 0 {
		return "unknown"
	}
	if !r.Available || r.Supported&bit == 0 {
		return "unsupported"
	}
	if r.Allowed&bit != 0 {
		return "allowed"
	}
	return "denied"
}

// ReadDecision includes NFSv4 regular-file EXECUTE authorization for READ.
// Callers retain the raw READ/EXECUTE decisions for diagnostic display.
func (r AccessReport) ReadDecision(v4Regular bool) string {
	read := r.Decision(1)
	if !v4Regular || read == "allowed" {
		return read
	}
	execute := r.Decision(32)
	if execute == "allowed" {
		return "allowed"
	}
	if read == "denied" && execute == "denied" {
		return "denied"
	}
	if read == "unknown" || execute == "unknown" {
		return "unknown"
	}
	return "unsupported"
}

// CheckAccess never opens or reads content, changes credentials, or creates a
// probe file. NFSv2 has no ACCESS; absence of that operation is not a denial.
func (c *Client) CheckAccess(ctx context.Context, fh []byte, requested uint32) (r AccessReport, resultErr error) {
	r.Identity, r.Requested = c.Identity(), requested
	defer func() {
		if resultErr != nil {
			r.Available = false
			r.Error = resultErr.Error()
		}
	}()
	if requested == 0 || requested & ^uint32(63) != 0 {
		return r, errors.New("ACCESS requires a nonempty mask of the six standard permissions")
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	if c.Version() == "2" {
		return r, nil
	}
	if c.v4 != nil {
		var e encoder
		e.u32(requested)
		resultErr = c.v4.compound(ctx, fh4(fh), op4(3, e, func(d *decoder) {
			r.Supported, r.Allowed = d.u32(), d.u32()
			if r.Supported & ^requested != 0 || r.Allowed & ^r.Supported != 0 {
				d.err = errors.New("invalid ACCESS response mask")
			}
		}))
	} else {
		var e encoder
		e.opaque(fh)
		e.u32(requested)
		var d *decoder
		d, resultErr = c.call(ctx, 4, e)
		if resultErr == nil {
			postAttr(d)
			r.Supported, r.Allowed = requested, d.u32()
			if r.Allowed & ^requested != 0 {
				d.err = errors.New("invalid ACCESS response mask")
			}
			resultErr = d.err
			if resultErr == nil && len(d.b) != 0 {
				resultErr = errors.New("trailing ACCESS response data")
			}
		}
	}
	r.Available = resultErr == nil
	return r, resultErr
}
