package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
	"nfs-viewer/internal/testiscsi"
)

// This peer supplies metadata only and rejects every MDS READ/WRITE. Local
// images contain independently constructed bytes; the client must translate
// the wire layout and withhold publication on source, cleanup or identity loss.
type blockCLIPeer struct {
	beforeReply                               func(net.Conn) error
	operationHook                             func(uint32, *missingV4Decoder, *string) ([]byte, uint32, error, bool)
	upload, growth                            bool
	created                                   atomic.Int32
	size                                      atomic.Uint64
	write                                     bool
	commitCheck                               func(uint64) error
	committed                                 atomic.Int32
	minor                                     uint32
	mode                                      string
	signature                                 []byte
	length                                    uint64
	hints, layouts, devices, returned, closed atomic.Int32
}

func blockCLIQuad(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }
func blockCLIBitmap(b []byte, bits []uint32) []byte {
	var words [3]uint32
	n := 0
	for _, bit := range bits {
		words[bit/32] |= 1 << (bit % 32)
		n = max(n, int(bit/32)+1)
	}
	b = missingV4Words(b, uint32(n))
	return missingV4Words(b, words[:n]...)
}

func (p *blockCLIPeer) serve(l net.Listener) error {
	conn, err := l.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	for {
		call, _, err := readObservedRPC(conn)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		d := &missingV4Decoder{b: call}
		xid := d.word()
		if d.word() != 0 || d.word() != 2 || d.word() != 100003 || d.word() != 4 || d.word() != 1 {
			return errors.New("expected block NFSv4 COMPOUND")
		}
		if d.word() != 1 {
			return errors.New("expected explicit AUTH_SYS")
		}
		d.opaque()
		d.word()
		d.opaque()
		d.opaque()
		if d.word() != p.minor {
			return errors.New("incorrect block minor version")
		}
		count := d.word()
		if count > 16 {
			return errors.New("excessive block fixture request")
		}
		var body []byte
		var status, completed uint32
		current := ""
		for completed < count {
			code := d.word()
			value, s, err := p.operation(code, d, &current)
			if err != nil {
				return err
			}
			body = missingV4Words(body, code, s)
			body = append(body, value...)
			completed++
			status = s
			if s != 0 {
				break
			}
		}
		if d.err != nil || status == 0 && len(d.b) != 0 {
			return fmt.Errorf("block request malformed or trailing: %v (%d)", d.err, len(d.b))
		}
		reply := missingV4Words(nil, xid, 1, 0, 0, 0, 0, status, 0, completed)
		if p.beforeReply != nil {
			if err := p.beforeReply(conn); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
		reply = append(reply, body...)
		wire := missingV4Words(nil, uint32(len(reply))|0x80000000)
		wire = append(wire, reply...)
		if _, err := io.Copy(conn, bytes.NewReader(wire)); err != nil {
			return err
		}
	}
}

func (p *blockCLIPeer) operation(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error) {
	if p.operationHook != nil {
		if e, s, err, handled := p.operationHook(code, d, current); handled {
			return e, s, err
		}
	}
	if p.write {
		if e, s, err, handled := p.writeOperation(code, d, current); handled {
			return e, s, err
		}
	}
	return p.readOperation(code, d, current)
}

func (p *blockCLIPeer) readOperation(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error) {
	var e []byte
	openSID, layoutSID := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
	binary.BigEndian.PutUint32(layoutSID, 1)
	switch code {
	case 42:
		d.take(8)
		d.opaque()
		d.word()
		d.word()
		d.word()
		e = blockCLIQuad(e, 123)
		e = missingV4Words(e, 1, 0x20000, 0)
		e = blockCLIQuad(e, 1)
		e = missingV4Opaque(e, []byte("block-mds"))
		e = missingV4Opaque(e, []byte("scope"))
		e = missingV4Words(e, 0)
	case 43:
		d.take(8)
		sequence := d.word()
		d.word()
		fore, back := d.take(28), d.take(28)
		d.word()
		if d.word() != 1 || d.word() != 0 {
			return nil, 0, errors.New("unexpected block backchannel credentials")
		}
		e = append(e, bytes.Repeat([]byte{9}, 16)...)
		e = missingV4Words(e, sequence, 2)
		e = append(e, fore...)
		e = append(e, back...)
	case 53:
		e = append(e, d.take(16)...)
		e = missingV4Words(e, d.word())
		d.take(12)
		e = missingV4Words(e, 0, 0, 0, 0)
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
		e = missingV4Opaque(e, []byte(*current))
	case 15:
		if string(d.opaque()) != "target" || *current != "root" {
			return nil, 0, errors.New("unexpected block lookup")
		}
		*current = "target"
	case 9:
		bits := d.bitmap()
		var values []byte
		for _, bit := range bits {
			switch bit {
			case 1:
				kind := uint32(1)
				if *current == "root" {
					kind = 2
				}
				values = missingV4Words(values, kind)
			case 3:
				change := uint64(7)
				if *current == "target" && (p.mode == "source-change" && p.layouts.Load() > 0 || p.mode == "post-return-change" && p.returned.Load() > 0) {
					change++
				}
				values = blockCLIQuad(values, change)
			case 4:
				size := p.length
				if p.upload || p.growth {
					size = p.size.Load()
				}
				values = blockCLIQuad(values, size)
			case 8:
				values = blockCLIQuad(blockCLIQuad(values, 1), 0)
			case 10:
				values = missingV4Words(values, 60)
			case 20:
				id := uint64(2)
				if *current == "root" {
					id = 1
				}
				values = blockCLIQuad(values, id)
			case 30, 31:
				values = blockCLIQuad(values, 32768)
			case 33:
				values = missingV4Words(values, 0644)
			case 36, 37:
				values = missingV4Opaque(values, []byte("fixture"))
			case 52, 53:
				values = missingV4Words(values, 0, 1, 0)
			case 65:
				values = missingV4Words(values, 512)
			default:
				return nil, 0, fmt.Errorf("unexpected block attribute %d", bit)
			}
		}
		e = blockCLIBitmap(e, bits)
		e = missingV4Opaque(e, values)
	case 26:
		d.take(8)
		d.take(8)
		d.word()
		d.word()
		d.bitmap()
		e = missingV4Words(e, 0, 1, 0, 1)
	case 18:
		d.word()
		share, deny := d.word(), d.word()
		d.take(8)
		d.opaque()
		if share != 1 || deny != 0 || d.word() != 0 || d.word() != 0 || string(d.opaque()) != "target" {
			return nil, 0, errors.New("block download changed OPEN profile")
		}
		*current = "target"
		e = append(e, openSID...)
		e = missingV4Words(e, 1, 0, 1, 0, 1, 0, 0, 0)
	case 34:
		p.hints.Add(1)
		if !bytes.Equal(d.take(16), openSID) || !reflect.DeepEqual(d.bitmap(), []uint32{63}) {
			return nil, 0, errors.New("invalid block hint identity/attribute")
		}
		value := &missingV4Decoder{b: d.opaque()}
		if value.word() != 3 {
			return nil, 0, errors.New("invalid block hint type")
		}
		hint := value.opaque()
		if !bytes.Equal(hint, bytes.Repeat([]byte{255}, 8)) || value.err != nil || len(value.b) != 0 {
			return nil, 0, errors.New("block client hid an unbounded I/O deadline")
		}
		if p.mode == "hint-denied" {
			return missingV4Words(nil, 0), 22, nil
		}
		e = blockCLIBitmap(e, []uint32{63})
	case 50:
		p.layouts.Add(1)
		if p.hints.Load() != 1 || d.word() != 0 || d.word() != 3 || d.word() != 1 {
			return nil, 0, errors.New("incorrect block layout type or unaccepted hint")
		}
		if !bytes.Equal(d.take(8), make([]byte, 8)) || !bytes.Equal(d.take(8), bytes.Repeat([]byte{255}, 8)) || !bytes.Equal(d.take(8), blockCLIQuad(nil, 1)) || !bytes.Equal(d.take(16), openSID) || d.word() != 32768 {
			return nil, 0, errors.New("invalid block layout request")
		}
		e = missingV4Words(e, 1)
		e = append(e, layoutSID...)
		e = missingV4Words(e, 1)
		e = blockCLIQuad(e, 0)
		e = blockCLIQuad(e, 1536)
		e = missingV4Words(e, 1, 3)
		body := missingV4Words(nil, 3)
		for i := uint64(0); i < 3; i++ {
			body = append(body, bytes.Repeat([]byte{0x45}, 16)...)
			body = blockCLIQuad(body, i*512)
			body = blockCLIQuad(body, 512)
			body = blockCLIQuad(body, i*512)
			state := uint32(1)
			if i == 1 {
				state = 3
			}
			body = missingV4Words(body, state)
		}
		e = missingV4Opaque(e, body)
	case 47:
		p.devices.Add(1)
		d.take(16)
		if d.word() != 3 || d.word() != 32768 || d.word() != 0 {
			return nil, 0, errors.New("invalid block device request")
		}
		signature := p.signature
		if p.mode == "signature" {
			signature = []byte("mismatch")
		}
		body := missingV4Words(nil, 1, 0, 1)
		body = blockCLIQuad(body, 0)
		body = missingV4Opaque(body, signature)
		e = missingV4Words(e, 3)
		e = missingV4Opaque(e, body)
		e = missingV4Words(e, 0)
	case 51:
		p.returned.Add(1)
		if d.word() != 0 || d.word() != 3 || d.word() != 3 || d.word() != 1 {
			return nil, 0, errors.New("incorrect block return type")
		}
		d.take(16)
		if !bytes.Equal(d.take(16), layoutSID) || len(d.opaque()) != 0 {
			return nil, 0, errors.New("incorrect block return state/body")
		}
		if p.mode == "return-failure" {
			return nil, 10025, nil
		}
		e = missingV4Words(e, 0)
	case 4:
		p.closed.Add(1)
		d.word()
		e = append(e, d.take(16)...)
		if p.mode == "close-failure" {
			return nil, 10025, nil
		}
	default:
		return nil, 0, fmt.Errorf("unexpected block operation %d; no MDS data fallback", code)
	}
	return e, 0, nil
}

func TestBlockDownloadPublication(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli", "empty", "signature", "hint-denied", "source-change", "post-return-change", "return-failure", "close-failure", "collision", "race-collision", "cancel", "base-identity", "cwd", "initial-identity"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				runBlockDownloadPublication(t, minor, mode)
			})
		}
	}
}

func runBlockDownloadPublication(t *testing.T, minor uint32, mode string) {
	t.Helper()
	secure := strings.HasPrefix(mode, "secure-")
	mode = strings.TrimPrefix(mode, "secure-")
	readRecovery := strings.HasPrefix(mode, "recovery-")
	mode = strings.TrimPrefix(mode, "recovery-")
	security, storageOptions, profile := secureStorageFixture(t, secure)
	transport := strings.HasPrefix(mode, "iscsi-")
	mode = strings.TrimPrefix(mode, "iscsi-")
	dir := t.TempDir()
	path := filepath.Join(dir, "volume")
	dest := filepath.Join(dir, "download")
	image := make([]byte, 8192)
	for i := range image {
		image[i] = byte(i*17 + 9)
	}
	signature := []byte{0x11, 0, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78}
	copy(image, signature)
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	want := append(append(append([]byte(nil), image[:512]...), make([]byte, 512)...), image[1024:1025]...)
	if mode == "empty" {
		want = nil
	}
	options := nfs.PNFSOptions{Layout: "block", BlockVolumes: []string{path}}
	var storage *testiscsi.Target
	if transport {
		if readRecovery {
			storageOptions.ReadDropAfter = 2
		}
		storage = testiscsi.Start(t, path, storageOptions)
		options.BlockVolumes = nil
		options.BlockTargets = []string{storage.URL()}
		options.BlockInitiator = testiscsi.Initiator
		if readRecovery {
			alternateOptions := storageOptions
			alternateOptions.ReadDropAfter = 0
			alternate := testiscsi.Start(t, path, alternateOptions)
			options.ReadFailover = true
			options.BlockReadAlternates = map[string][]string{storage.URL(): {alternate.URL()}}
		}
		if secure {
			options.BlockSecurity = storagePolicies(storage.URL(), security)
		}
	}
	p := &blockCLIPeer{minor: minor, mode: mode, signature: signature, length: uint64(len(want))}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.serve(listener) }()
	t.Cleanup(func() {
		listener.Close()
		if err := <-done; err != nil {
			t.Error("block peer", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if mode == "cli" {
		args := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "--pnfs", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never", "-c", "getpnfs target " + strconv.Quote(dest) + " --layout block --block-volume " + strconv.Quote(path)}
		if storage != nil {
			args[len(args)-1] = strings.Replace(args[len(args)-1], "--block-volume "+strconv.Quote(path), "--block-target "+strconv.Quote(storage.URL())+" --block-initiator "+testiscsi.Initiator, 1)
		}
		if secure {
			args[len(args)-1] += " --block-security " + strconv.Quote(storage.URL()+"="+profile)
		}
		if readRecovery {
			args[len(args)-1] += " --read-failover --block-alternate " + strconv.Quote(storage.URL()+"="+options.BlockReadAlternates[storage.URL()][0])
		}
		out, err := runKerberosCLI(t, args)
		if err != nil {
			t.Fatal(err, out)
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
		if mode == "collision" {
			if err := os.WriteFile(dest, []byte("competitor"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		progress := func(done, total uint64) {
			if mode == "initial-identity" && done == 0 {
				s.BaseAuth.UID++
			}
			if done == 0 {
				return
			}
			switch mode {
			case "cancel":
				cancel()
			case "base-identity":
				s.BaseAuth.GID++
			case "cwd":
				s.CWD = "/changed"
			case "race-collision":
				if done == total {
					if err := os.WriteFile(dest, []byte("competitor"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		n, err := s.GetPNFS(ctx, "target", dest, options, progress)
		if mode == "api" || mode == "empty" {
			if err != nil || n != int64(len(want)) {
				t.Fatal(n, err)
			}
		} else if err == nil {
			t.Fatal("unsafe block download published")
		}
	}
	b, err := os.ReadFile(dest)
	if mode == "api" || mode == "cli" || mode == "empty" {
		if err != nil || !bytes.Equal(b, want) || p.closed.Load() != 1 || (mode != "empty" && p.returned.Load() != 1) {
			t.Fatal("published block bytes/cleanup", len(b), err, p.closed.Load(), p.returned.Load())
		}
	} else if mode == "collision" || mode == "race-collision" {
		if err != nil || string(b) != "competitor" {
			t.Fatal("competitor replaced", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed block download left published file", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".nfs-download-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatal("temporary output leaked", leftovers, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, image) {
		t.Fatal("volume image changed", err)
	}
	t.Logf("BLOCK_PUBLICATION transport=%t platform=%s minor=%d mode=%s bytes=%d binary=%t verified", transport, runtime.GOOS, minor, mode, len(want), os.Getenv("NFS_VIEWER_TEST_BINARY") != "")
}

func TestBlockCLIArguments(t *testing.T) {
	for _, command := range []string{
		"getpnfs a b --layout block", "getpnfs a b --block-volume image",
		"getpnfs a b --layout block --block-volume", "getpnfs a b --layout block --block-volume image --parallel 2",
		"getpnfs a b --layout block --block-volume image --read-failover", "getpnfs a b --layout block --block-volume image --mirror-failover",
		"getpnfs a b --layout block --block-volume image --refresh-devices", "getpnfs a b --layout block --block-volume image --session-trunking",
		"getpnfs a b --layout block --block-volume image x=y", "putpnfs a b --layout block x=y", "putrangepnfs a b 0 --layout block x=y",
		"putpnfs a b --block-volume image x=y", "getpnfs a b --layout block --block-volume --parallel",
	} {
		t.Run(command, func(t *testing.T) {
			if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil || !strings.Contains(err.Error(), "block") {
				t.Fatal("expected block parser refusal", err)
			}
		})
	}
	var help bytes.Buffer
	if _, err := (&Shell{Out: &help, Err: io.Discard}).Execute(context.Background(), "help"); err != nil || !strings.Contains(help.String(), "--block-volume") {
		t.Fatal("block help missing", err)
	}
}
