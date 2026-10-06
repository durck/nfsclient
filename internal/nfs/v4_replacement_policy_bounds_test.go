package nfs

import (
	"context"
	"fmt"
	"testing"
)

func TestReplacementPolicyBounds(t *testing.T) {
	for _, mode := range []string{"dacl-flags", "sacl-flags", "dacl-audit", "sacl-allow", "sacl-unadvertised", "label-too-large", "label-missing"} {
		t.Run(mode, func(t *testing.T) {
			fields := replacementExtendedAttrs("all")
			switch mode {
			case "dacl-flags":
				fields[58] = append(replacementTestU32(8), replacementTestU32(0)...)
			case "sacl-flags":
				fields[59] = append(replacementTestU32(8), replacementTestU32(0)...)
			case "dacl-audit":
				fields[58] = append(replacementTestU32(0), replacementTestACL(replacementTestACE{2, 0x10, 1, "OWNER@"})...)
			case "sacl-allow":
				fields[59] = append(replacementTestU32(0), replacementTestACL(replacementTestACE{0, 0, 1, "OWNER@"})...)
			case "sacl-unadvertised":
				fields[13] = replacementTestU32(3)
			case "label-too-large":
				var e encoder
				e.u32(7)
				e.u32(42)
				e.opaque(make([]byte, MaxSecurityLabel+1))
				fields[80] = e
			case "label-missing":
				delete(fields, 80)
			}
			v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 9 {
					return nil, 0, fmt.Errorf("unexpected mutation %d", code)
				}
				return replacementTestReply(readBitmap4(d), fields), 0, nil
			})
			if got, err := v.c.CaptureV4Replacement(context.Background(), []byte("original")); err == nil || got != nil {
				t.Fatal("unsafe policy captured")
			}
		})
	}
}
