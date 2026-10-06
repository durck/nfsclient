package nfs

import (
	"context"
	"fmt"
	"testing"
)

func TestReadDirFallbackAndPaging(t *testing.T) {
	plus, basic := 0, 0
	c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
		var e encoder
		switch proc {
		case 17:
			plus++
			e.u32(10004)
		case 16:
			basic++
			d.opaque(64)
			cookie := d.u64()
			verifier := d.take(8)
			d.u32()
			if len(d.b) != 0 || (cookie != 0 && (cookie != 8 || string(verifier) != "verifier")) {
				return nil, fmt.Errorf("invalid READDIR args")
			}
			e.u32(0)
			e.u32(0)
			e = append(e, []byte("verifier")...)
			if cookie == 0 {
				e.u32(1)
				e.u64(123)
				e.str("file")
				e.u64(8)
				e.u32(0)
				e.u32(0)
			} else {
				e.u32(0)
				e.u32(1)
			}
		case 3:
			e.u32(0)
			e.opaque([]byte("file-handle"))
			e.u32(1)
			compatibilityAttr(&e)
			e.u32(0)
		default:
			return nil, fmt.Errorf("unexpected call %d", proc)
		}
		return e, nil
	})
	for i := 0; i < 2; i++ {
		entries, err := c.ReadDir(context.Background(), []byte("root"))
		if err != nil || len(entries) != 1 || entries[0].Name != "file" {
			t.Fatalf("entries: %+v %v", entries, err)
		}
	}
	if plus != 1 || basic != 4 {
		t.Fatalf("fallback was not remembered: %d/%d", plus, basic)
	}
}
