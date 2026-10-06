package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SECINFO advertises a mechanism OID's contents, without ASN.1 tag/length.
var krb5OID = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 1, 2, 2}

func readSecurity4(d *decoder) []string {
	count := d.u32()
	if count > 64 {
		d.err = errors.New("NFSv4 SECINFO exceeds 64 security tuples")
		return nil
	}
	var modes []string
	for i := uint32(0); i < count && d.err == nil; i++ {
		flavor := d.u32()
		var mode string
		switch flavor {
		case 0:
			mode = "AUTH_NONE"
		case 1:
			mode = "sys"
		case 6:
			oid, qop, service := d.opaque(128), d.u32(), d.u32()
			mode = "RPCSEC_GSS (unsupported tuple)"
			if bytes.Equal(oid, krb5OID) && qop == 0 && service >= 1 && service <= 3 {
				mode = []string{"krb5", "krb5i", "krb5p"}[service-1]
			}
		default:
			mode = fmt.Sprintf("RPC flavor %d", flavor)
		}
		if !slices.Contains(modes, mode) {
			modes = append(modes, mode)
		}
	}
	return modes
}

// Diagnose a named security boundary under the current identity/protection.
// Never pick another flavor, acquire another identity or replay the failed call.
func (v *v4Client) wrongSecurity(ctx context.Context, dir []byte, name string) error {
	var e encoder
	e.str(name)
	var modes []string
	err := v.compound(ctx, fh4(dir), op4(33, e, func(d *decoder) { modes = readSecurity4(d) }))
	if err != nil {
		return fmt.Errorf("%w: requested %s; SECINFO unavailable: %v (no security fallback)", Status(10016), v.c.Security(), err)
	}
	available := strings.Join(modes, ", ")
	if available == "" {
		available = "no security tuples"
	}
	return fmt.Errorf("%w: requested %s; server advertises %s; select --sec explicitly (no security fallback)", Status(10016), v.c.Security(), available)
}
