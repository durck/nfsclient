package nfs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestVersionNegotiation(t *testing.T) {
	for _, target := range []uint32{0, 2, 3} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var mu sync.Mutex
			var versions []uint32
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						packet, err := readRecord(conn)
						if err != nil {
							return
						}
						d := &decoder{b: packet}
						xid := d.u32()
						d.u32()
						d.u32()
						program, version, proc := d.u32(), d.u32(), d.u32()
						d.u32()
						d.opaque(400)
						d.u32()
						d.opaque(400)
						mu.Lock()
						versions = append(versions, version)
						mu.Unlock()
						var e encoder
						e.u32(xid)
						e.u32(1)
						if target == 0 {
							e.u32(1)
							e.u32(1)
							e.u32(1)
						} else {
							e.u32(0)
							e.u32(0)
							e.u32(0)
							if version == 4 {
								e.u32(0)
								e.u32(10021)
								e.str("")
								e.u32(0)
							} else if version != target {
								e.u32(2)
								e.u32(target)
								e.u32(target)
							} else if program == nfsProgram && proc == 0 {
								e.u32(0)
							} else {
								e.u32(3)
							}
						}
						conn.Write(record(e, true))
					}()
				}
			}()
			t.Cleanup(func() { listener.Close(); wg.Wait() })
			port := listener.Addr().(*net.TCPAddr).Port
			c, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "auto", NFSPort: port, MountPort: port, Timeout: time.Second})
			if target == 0 {
				var denied RPCDenied
				if !errors.As(err, &denied) {
					t.Fatalf("expected denial: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if c.Version() != fmt.Sprint(target) {
					t.Fatalf("selected %s", c.Version())
				}
			}
			mu.Lock()
			defer mu.Unlock()
			want := "[4 4 4 3]"
			if target == 2 {
				want = "[4 4 4 3 2]"
			}
			if target == 0 {
				want = "[4]"
			}
			if fmt.Sprint(versions) != want {
				t.Fatalf("negotiation order %v; want %s", versions, want)
			}
		})
	}
}

func TestInvalidVersionDoesNotDial(t *testing.T) {
	if _, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "4.9", Timeout: time.Second}); err == nil {
		t.Fatal("invalid version accepted")
	}
}
