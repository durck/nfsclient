package nfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A peer may restart at the beginning with entirely new opaque cookies and a
// zero verifier (UNFS3 after REMOVE/RENAME). Never publish the mixed listing.
func TestReadDirRestart(t *testing.T) {
	for _, plus := range []bool{false, true} {
		for _, reason := range []string{"duplicate", "verifier", "bad-cookie"} {
			for _, persistent := range []bool{false, true} {
				t.Run(fmt.Sprintf("plus=%t/%s/persistent=%t", plus, reason, persistent), func(t *testing.T) {
					starts, pages := 0, 0
					c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
						if proc == 3 { // Basic READDIR requires LOOKUP attributes.
							var e encoder
							e.u32(0)
							e.opaque([]byte("entry"))
							e.u32(1)
							compatibilityAttr(&e)
							e.u32(0)
							return e, nil
						}
						wantProc := uint32(16)
						if plus {
							wantProc = 17
						}
						if prog != nfsProgram || proc != wantProc {
							return nil, fmt.Errorf("unexpected procedure %d", proc)
						}
						d.opaque(64)
						cookie := d.u64()
						verifier := d.take(8)
						if cookie == 0 {
							starts++
							if string(verifier) != string(make([]byte, 8)) {
								return nil, fmt.Errorf("restart retained verifier")
							}
						}
						pages++
						changed := cookie != 0 && (persistent || starts == 1)
						var e encoder
						if changed && reason == "bad-cookie" {
							e.u32(10003)
							e.u32(0)
							return e, nil
						}
						e.u32(0)
						e.u32(0)
						v := uint64(0)
						if reason == "verifier" {
							v = 11
							if changed {
								v = 22
							}
						}
						e.u64(v)
						name := "new-first"
						if starts == 1 || persistent {
							name = "old-first"
						}
						if cookie != 0 && !(changed && reason == "duplicate") {
							name = "last"
						}
						e.u32(1)
						e.u64(uint64(pages))
						e.str(name)
						e.u64(uint64(pages)) // Always fresh, including on restart.
						if plus {
							e.u32(1)
							compatibilityAttr(&e)
							e.u32(1)
							e.opaque([]byte(name))
						}
						e.u32(0)
						if cookie == 0 {
							e.u32(0)
						} else {
							e.u32(1)
						}
						return e, nil
					})
					c.basicReadDir = !plus
					entries, err := c.ReadDir(context.Background(), []byte("dir"))
					if starts != 2 || pages != 4 {
						t.Fatalf("unbounded or missing restart: starts=%d pages=%d error=%v", starts, pages, err)
					}
					if persistent {
						if err == nil || !strings.Contains(err.Error(), "directory changed") || entries != nil {
							t.Fatalf("published unstable listing: %v %v", entries, err)
						}
					} else if err != nil || len(entries) != 2 || entries[0].Name != "last" || entries[1].Name != "new-first" {
						t.Fatalf("mixed listing after restart: %v %v", entries, err)
					}
				})
			}
		}
	}
}

func TestReadDirDoesNotRestartDenialOrCancellation(t *testing.T) {
	for _, cancelRead := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelRead), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelRead {
				cancel()
			}
			calls := 0
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				calls++
				var e encoder
				e.u32(13)
				e.u32(0)
				return e, nil
			})
			entries, err := c.ReadDir(ctx, []byte("dir"))
			want := error(Status(13))
			wantCalls := 1
			if cancelRead {
				want = context.Canceled
				wantCalls = 0
			}
			if calls != wantCalls || entries != nil || !errors.Is(err, want) {
				t.Fatalf("retried denial/cancellation: calls=%d entries=%v error=%v", calls, entries, err)
			}
		})
	}
}
