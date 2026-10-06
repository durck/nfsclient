package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func (p *blockCLIPeer) writeOperation(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
	openSID, lockSID := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{6}, 16)
	layoutSID := append(missingV4Words(nil, 1), bytes.Repeat([]byte{8}, 12)...)
	var e []byte
	switch code {
	case 18:
		d.word()
		share, deny := d.word(), d.word()
		d.take(8)
		d.opaque()
		create := d.word()
		if p.upload && create == 1 {
			if share != 2 || deny != 0 || d.word() != 1 || !reflect.DeepEqual(d.bitmap(), []uint32{33}) || !bytes.Equal(d.opaque(), missingV4Words(nil, 0644)) || d.word() != 0 || string(d.opaque()) != "target" {
				return nil, 0, errors.New("new upload did not use guarded CREATE"), true
			}
			if p.mode == "create-denied" {
				return nil, 13, nil, true
			}
			if p.created.Add(1) != 1 || p.mode == "collision" {
				return nil, 17, nil, true
			}
			*current = "target"
			if p.mode == "create-truncated" {
				return nil, 0, nil, true
			}
		} else if share != 3 || deny != 0 || create != 0 || d.word() != 0 || string(d.opaque()) != "target" {
			return nil, 0, errors.New("write OPEN profile changed"), true
		}
		*current = "target"
		e = append(e, openSID...)
		e = missingV4Words(e, 1, 0, 1, 0, 1, 0, 0, 0)
	case 15:
		if !p.upload {
			return nil, 0, nil, false
		}
		if string(d.opaque()) != "target" || *current != "root" {
			return nil, 0, errors.New("invalid upload lookup"), true
		}
		if p.created.Load() == 0 {
			return nil, 2, nil, true
		}
		*current = "target"
	case 4:
		if p.upload && p.mode == "create-close-error" && p.closed.Load() == 0 {
			p.closed.Add(1)
			d.word()
			d.take(16)
			return nil, 5, nil, true
		}
		return nil, 0, nil, false
	case 12:
		if d.word() != 2 || d.word() != 0 || !bytes.Equal(d.take(8), make([]byte, 8)) || !bytes.Equal(d.take(8), bytes.Repeat([]byte{255}, 8)) || d.word() != 1 {
			return nil, 0, errors.New("block write needs whole-file nonreclaim LOCK"), true
		}
		d.word()
		if !bytes.Equal(d.take(16), openSID) {
			return nil, 0, errors.New("incorrect open lock owner"), true
		}
		d.word()
		d.take(8)
		d.opaque()
		e = append(e, lockSID...)
	case 14:
		if d.word() != 2 || d.word() != 1 || !bytes.Equal(d.take(16), lockSID) {
			return nil, 0, errors.New("bad unlock"), true
		}
		d.take(16)
		e = append(e, lockSID...)
	case 45:
		d.take(16)
	case 34:
		if !bytes.Equal(d.take(16), lockSID) || !reflect.DeepEqual(d.bitmap(), []uint32{63}) {
			return nil, 0, errors.New("hint used another lock"), true
		}
		value := &missingV4Decoder{b: d.opaque()}
		if value.word() != 3 || !bytes.Equal(value.opaque(), bytes.Repeat([]byte{255}, 8)) || value.err != nil || len(value.b) != 0 {
			return nil, 0, errors.New("bad hint"), true
		}
		p.hints.Add(1)
		e = blockCLIBitmap(e, []uint32{63})
	case 50:
		if p.hints.Load() != 1 || d.word() != 0 || d.word() != 3 || d.word() != 2 || !bytes.Equal(d.take(8), make([]byte, 8)) || !bytes.Equal(d.take(8), bytes.Repeat([]byte{255}, 8)) || !bytes.Equal(d.take(8), blockCLIQuad(nil, 1)) || !bytes.Equal(d.take(16), lockSID) || d.word() != 32768 {
			return nil, 0, errors.New("bad writable grant request"), true
		}
		p.layouts.Add(1)
		e = missingV4Words(e, 1)
		e = append(e, layoutSID...)
		e = missingV4Words(e, 1)
		length := uint64(1536)
		if p.upload {
			length = ((p.length + 511) / 512) * 512
		}
		if p.growth {
			length = 4096
		}
		e = blockCLIQuad(blockCLIQuad(e, 0), length)
		e = missingV4Words(e, 2, 3)
		extents := []struct {
			storage uint64
			state   uint32
		}{{1024, 1}, {4096, 2}}
		if p.growth {
			extents[1].storage = 8192
		}
		if p.upload {
			extents = extents[1:]
		}
		body := missingV4Words(nil, uint32(len(extents)))
		for _, x := range extents {
			body = append(body, bytes.Repeat([]byte{0x45}, 16)...)
			body = blockCLIQuad(blockCLIQuad(blockCLIQuad(body, 0), length), x.storage)
			body = missingV4Words(body, x.state)
		}
		e = missingV4Opaque(e, body)
	case 49:
		logical := uint64(p.committed.Add(1)-1) * 512
		end := uint64(1101)
		if p.upload {
			end = p.length
		}
		if p.growth {
			logical += 512
			end = 3726
		}
		stop := min(logical+512, end)
		if !bytes.Equal(d.take(8), blockCLIQuad(nil, logical)) || !bytes.Equal(d.take(8), blockCLIQuad(nil, 512)) || d.word() != 0 || !bytes.Equal(d.take(16), layoutSID) || d.word() != 1 || !bytes.Equal(d.take(8), blockCLIQuad(nil, stop-1)) || d.word() != 0 || d.word() != 3 {
			return nil, 0, errors.New("incorrect block commit header"), true
		}
		update := &missingV4Decoder{b: d.opaque()}
		if update.word() != 1 || !bytes.Equal(update.take(16), bytes.Repeat([]byte{0x45}, 16)) || !bytes.Equal(update.take(8), blockCLIQuad(nil, logical)) || !bytes.Equal(update.take(8), blockCLIQuad(nil, 512)) || !bytes.Equal(update.take(8), make([]byte, 8)) || update.word() != 0 || update.err != nil || len(update.b) != 0 {
			return nil, 0, errors.New("incorrect COW commit list"), true
		}
		if err := p.commitCheck(logical); err != nil {
			return nil, 0, err, true
		}
		if p.mode == "commit-error" {
			return nil, 5, nil, true
		}
		if p.upload || p.growth {
			size := max(p.size.Load(), stop)
			p.size.Store(size)
			e = missingV4Words(e, 1)
			if p.mode == "commit-size" {
				size++
			}
			e = blockCLIQuad(e, size)
		} else {
			e = missingV4Words(e, 0)
		}
	default:
		return nil, 0, nil, false
	}
	return e, 0, nil, true
}

func TestBlockRangeUpload(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli", "initial-identity", "identity", "eof-identity", "cwd", "source-change", "source-alias", "cancel", "commit-error", "return-failure"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "volume")
				source := filepath.Join(dir, "patch")
				image := make([]byte, 8192)
				for i := range image {
					image[i] = byte(i*23 + 11)
				}
				signature := bytes.Clone(image[:8])
				want := bytes.Clone(image)
				patch := bytes.Repeat([]byte("COWpatch"), 125)
				for name, data := range map[string][]byte{path: image, source: patch} {
					if err := os.WriteFile(name, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				p := &blockCLIPeer{minor: minor, mode: mode, write: true, signature: signature, length: 1201}
				p.commitCheck = func(logical uint64) error {
					block := bytes.Clone(image[1024+logical : 1024+logical+512])
					if logical+512 > 1201 {
						clear(block[1201-logical:])
					}
					start, stop := max(logical, uint64(101)), min(logical+512, uint64(1101))
					copy(block[start-logical:stop-logical], patch[start-101:stop-101])
					copy(want[4096+logical:4096+logical+512], block)
					b, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(b, want) {
						return fmt.Errorf("physical COW verification failed: %v", err)
					}
					return nil
				}
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- p.serve(listener) }()
				t.Cleanup(func() {
					listener.Close()
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if mode == "cli" {
					args := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "--pnfs", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never", "-c", "lock target write", "-c", "putrangepnfs " + strconv.Quote(source) + " target 101 --layout block --block-write --block-volume " + strconv.Quote(path), "-c", "unlock 1"}
					output, err := runKerberosCLI(t, args)
					if err != nil {
						t.Fatal(err, output)
					}
				} else {
					c, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: fmt.Sprintf("4.%d", minor), Transport: "tcp", NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: 2 * time.Second, PNFS: true})
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					s := session.New(c, "127.0.0.1", false, false, io.Discard)
					if err := s.Use(ctx, "/"); err != nil {
						t.Fatal(err)
					}
					if _, err := s.Lock(ctx, "target", true); err != nil {
						t.Fatal(err)
					}
					local := source
					if mode == "source-alias" {
						local = path
					}
					progress := func(n, total uint64) {
						if mode == "initial-identity" && n == 0 {
							s.BaseAuth.UID++
						}
						if n == 0 {
							return
						}
						switch mode {
						case "identity":
							s.BaseAuth.GID++
						case "eof-identity":
							if n == total {
								s.BaseAuth.GID++
							}
						case "cwd":
							s.CWD = "/changed"
						case "source-change":
							if err := os.Truncate(source, 100); err != nil {
								t.Fatal(err)
							}
						case "cancel":
							cancel()
						}
					}
					n, err := s.PutPNFSRange(ctx, local, "target", 101, nfs.PNFSOptions{Layout: "block", BlockWrite: true, BlockVolumes: []string{path}}, progress)
					if mode == "api" {
						if err != nil || n != 1000 {
							t.Fatal(n, err)
						}
					} else if err == nil {
						t.Fatal("unsafe success", mode, n)
					}
				}
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatal("unrelated storage changed", err)
				}
				if (mode == "api" || mode == "cli") && (p.committed.Load() != 3 || p.returned.Load() != 1) {
					t.Fatal("missing durable commits/return", p.committed.Load(), p.returned.Load())
				}
				if (mode == "initial-identity" || mode == "source-alias") && p.layouts.Load() != 0 {
					t.Fatal("invalid initial profile acquired writable grant")
				}
				t.Logf("BLOCK_UPLOAD platform=%s minor=%d mode=%s commits=%d binary=%t verified", runtime.GOOS, minor, mode, p.committed.Load(), os.Getenv("NFS_VIEWER_TEST_BINARY") != "")
			})
		}
	}
}
