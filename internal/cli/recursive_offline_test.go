package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func offlineTreeBitmap(bits []uint32) []byte {
	words := []uint32{0, 0, 0}
	for _, bit := range bits {
		words[bit/32] |= 1 << (bit % 32)
	}
	return missingV4Words(nil, 3, words[0], words[1], words[2])
}

func TestRecursiveSkipOfflineWire(t *testing.T) {
	for _, mode := range []string{"offline", "unknown", "error", "first-offline", "last-offline", "default-hardlinks"} {
		t.Run(mode, func(t *testing.T) {
			peer := &missingV4Peer{minor: 2}
			opens, reads := 0, 0
			peer.inspectOperation = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error) {
				var e []byte
				switch code {
				case 42:
					d.take(8)
					d.opaque()
					d.take(12)
					e = missingV4Words(nil, 0, 123, 1, 0, 0, 0, 1)
					e = missingV4Opaque(e, []byte("server"))
					e = missingV4Opaque(e, []byte("scope"))
					e = missingV4Words(e, 0)
				case 43:
					d.take(8)
					seq := d.word()
					d.take(68)
					e = missingV4Words(bytes.Repeat([]byte{9}, 16), seq, 0)
					for range 2 {
						e = missingV4Words(e, 0, 1<<20, 1<<20, 65536, 16, 1, 0)
					}
				case 53:
					e = append(e, d.take(16)...)
					seq, slot := d.word(), d.word()
					d.word()
					d.word()
					e = missingV4Words(e, seq, slot, 0, 0, 0)
				case 58:
					d.word()
				case 44:
					d.take(16)
				case 57:
					d.take(8)
				case 24:
					*current = "root"
				case 22:
					*current = string(d.opaque())
				case 10:
					e = missingV4Opaque(nil, []byte(*current))
				case 15:
					*current = string(d.opaque())
				case 9:
					bits := d.bitmap()
					if mode == "default-hardlinks" {
						for _, bit := range bits {
							if bit == 0 || bit == 83 {
								return nil, 0, errors.New("ordinary hardlink download requested offline metadata")
							}
						}
					}
					if reflect.DeepEqual(bits, []uint32{0}) {
						if mode == "error" {
							return nil, 13, nil
						}
						supported := []uint32{0}
						if mode != "unknown" {
							supported = append(supported, 83)
						}
						e = append(offlineTreeBitmap(bits), missingV4Opaque(nil, offlineTreeBitmap(supported))...)
						break
					}
					if reflect.DeepEqual(bits, []uint32{83}) {
						value := uint32(0)
						if mode == "offline" || mode == "first-offline" && *current == "a" || mode == "last-offline" && *current == "b" {
							value = 1
						}
						e = append(offlineTreeBitmap(bits), missingV4Opaque(nil, missingV4Words(nil, value))...)
						break
					}
					typ := uint32(1)
					if *current == "root" {
						typ = 2
					}
					values := map[uint32][]byte{1: missingV4Words(nil, typ), 3: missingV4Words(nil, 0, 7), 4: missingV4Words(nil, 0, 4), 8: missingV4Words(nil, 0, 1, 0, 0), 10: missingV4Words(nil, 60), 20: missingV4Words(nil, 0, 77), 33: missingV4Words(nil, 0600), 52: missingV4Words(nil, 0, 1700000000, 0), 53: missingV4Words(nil, 0, 1700000000, 0)}
					var returned []uint32
					var a []byte
					for _, bit := range bits {
						if value, ok := values[bit]; ok {
							returned = append(returned, bit)
							a = append(a, value...)
						}
					}
					e = append(offlineTreeBitmap(returned), missingV4Opaque(nil, a)...)
				case 26:
					d.take(8)
					d.take(8)
					d.word()
					d.word()
					d.bitmap()
					e = make([]byte, 8)
					for i, name := range []string{"a", "b", "c"} {
						e = missingV4Words(e, 1, 0, uint32(i+1))
						e = missingV4Opaque(e, []byte(name))
						e = append(e, offlineTreeBitmap([]uint32{1})...)
						e = missingV4Opaque(e, missingV4Words(nil, 1))
					}
					e = missingV4Words(e, 0, 1)
				case 18:
					opens++
					d.word()
					share, deny := d.word(), d.word()
					d.take(8)
					d.opaque()
					create, claim := d.word(), d.word()
					*current = string(d.opaque())
					if mode == "offline" || mode == "error" || share != 1 || deny != 0 || create != 0 || claim != 0 {
						return nil, 0, errors.New("unexpected content OPEN")
					}
					e = missingV4Words(bytes.Repeat([]byte{7}, 16), 1, 0, 1, 0, 1, 0, 0, 0)
				case 25:
					reads++
					d.take(16)
					d.take(8)
					d.word()
					e = missingV4Opaque(missingV4Words(nil, 1), []byte("data"))
				case 4:
					d.word()
					e = append(e, d.take(16)...)
				default:
					return nil, 0, fmt.Errorf("unexpected tree operation %d", code)
				}
				return e, 0, nil
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- peer.serve(listener) }()
			var client *nfs.Client
			var once sync.Once
			stop := func() {
				once.Do(func() {
					if client != nil {
						client.Close()
					}
					listener.Close()
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
			}
			t.Cleanup(stop)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err = nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: "4.2", NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			var notices, out bytes.Buffer
			s := session.New(client, "127.0.0.1", false, false, &notices)
			s.Export = "/"
			s.Root = nfs.Node{Handle: []byte("root"), Attr: nfs.Attr{Type: 2}}
			sh := &Shell{Session: s, Out: &out, Err: &notices, LocalDir: t.TempDir()}
			command := "gettree --skip-offline"
			if mode == "default-hardlinks" {
				command = "gettree --hardlinks"
			}
			if strings.Contains(mode, "-offline") {
				command += " --hardlinks"
			}
			command += " / result"
			_, err = sh.Execute(ctx, command)
			stop()
			if mode == "error" {
				if err == nil || opens != 0 || reads != 0 || strings.Contains(notices.String(), "Skipped") {
					t.Fatal(err, opens, reads, notices.String())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantOpens := 3
			if mode == "offline" {
				wantOpens = 0
			}
			if strings.Contains(mode, "-offline") || mode == "default-hardlinks" {
				wantOpens = 1
			}
			if opens != wantOpens || reads != wantOpens {
				t.Fatalf("OPEN=%d READ=%d want=%d", opens, reads, wantOpens)
			}
			for _, name := range []string{"a", "b", "c"} {
				data, err := os.ReadFile(filepath.Join(sh.LocalDir, "result", name))
				skipped := mode == "offline" || mode == "first-offline" && name == "a" || mode == "last-offline" && name == "b"
				if skipped {
					if !errors.Is(err, os.ErrNotExist) || !strings.Contains(notices.String(), `"/`+name+`"`) {
						t.Fatal(name, err, notices.String())
					}
				} else if err != nil || string(data) != "data" {
					t.Fatal(name, string(data), err)
				}
			}
			if mode == "default-hardlinks" {
				first, err := os.Stat(filepath.Join(sh.LocalDir, "result", "a"))
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"b", "c"} {
					alias, err := os.Stat(filepath.Join(sh.LocalDir, "result", name))
					if err != nil || !os.SameFile(first, alias) {
						t.Fatalf("%s is not a hardlink: %v", name, err)
					}
				}
				if strings.Contains(notices.String(), "Skipped") {
					t.Fatal(notices.String())
				}
			}
		})
	}
}

func TestRecursiveSkipOfflineRejectsUpload(t *testing.T) {
	sh, _, _ := testShell(t)
	if _, err := sh.Execute(context.Background(), "puttree --skip-offline missing remote"); err == nil || !strings.Contains(err.Error(), "skip-offline") {
		t.Fatal(err)
	}
	if _, err := sh.Session.PutTreeWithOptions(context.Background(), "missing", "remote", session.TreeOptions{SkipOffline: true}, nil); err == nil {
		t.Fatal("API accepted upload skip")
	}
}
