package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/testiscsi"
)

// Execute the real command parser in an independently killable process. The
// release validation substitutes the built application for this test helper.
func TestBlockRecoveryChild(t *testing.T) {
	encoded := os.Getenv("NFS_BLOCK_CRASH_ARGS")
	if encoded == "" {
		t.Skip("subprocess helper")
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatal(err)
	}
	if report := os.Getenv("NFS_BLOCK_MEMORY_REPORT"); report != "" {
		// This observer reports Go heap independently of the client implementation.
		go func() {
			file, err := os.OpenFile(report, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return
			}
			defer file.Close()
			var peak uint64
			for {
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				peak = max(peak, m.HeapAlloc)
				_, _ = file.WriteString(strconv.FormatUint(peak, 10) + "\n")
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	cmd := NewCommand(strings.NewReader(""), os.Stdout, os.Stderr)
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBlockProcessCrashRecovery(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, transport := range []string{"image", "iscsi"} {
			for _, phase := range []string{"precommit", "postcommit", "changed-source", "changed-destination", "changed-profile", "changed-eof", "normal-replay", "missing-lock"} {
				t.Run(fmt.Sprintf("4.%d/%s/%s", minor, transport, phase), func(t *testing.T) {
					runBlockProcessCrash(t, minor, transport, phase)
				})
			}
		}
		t.Run(fmt.Sprintf("4.%d/iscsi/write-issued", minor), func(t *testing.T) {
			runBlockProcessCrash(t, minor, "iscsi", "write-issued")
		})
	}
}

func TestBlockJournalUploadFlows(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, transport := range []string{"", "iscsi-"} {
			for _, mode := range []string{"api", "cli", "empty-cli", "commit-error"} {
				t.Run(fmt.Sprintf("new/4.%d/%s%s", minor, transport, mode), func(t *testing.T) { runBlockUploadFlow(t, minor, "journal-"+transport+mode, false) })
			}
			for _, mode := range []string{"api", "cli"} {
				t.Run(fmt.Sprintf("growth/4.%d/%s%s", minor, transport, mode), func(t *testing.T) { runBlockUploadFlow(t, minor, "journal-"+transport+mode, true) })
			}
		}
	}
}

// The metadata peer never stores payload bytes. Its COW mappings are published
// one block at a time, while the physical image has an independent byte oracle.
func TestBlockLargeProcessRecovery(t *testing.T) {
	for _, mode := range []string{"small-patch", "two-crashes", "changed-source", "changed-device"} {
		t.Run(mode, func(t *testing.T) { runBlockLargeProcessRecovery(t, mode) })
	}
}

func runBlockLargeProcessRecovery(t *testing.T, mode string) {
	const block uint64 = 1 << 20
	const fileSize uint64 = 36 << 20
	const oldBase uint64 = 1 << 20
	const newBase uint64 = 48 << 20
	const volumeSize uint64 = 96 << 20
	offset, length := block+101, uint64(20<<20)+203
	if mode == "small-patch" {
		offset = 32*block + 11
		length = 31
	}
	dir := t.TempDir()
	volume := filepath.Join(dir, "volume")
	source := filepath.Join(dir, "source")
	journal := filepath.Join(dir, "journal")
	original := func(pos uint64) byte { return byte(pos*17 + pos/251 + 39) }
	replacement := func(pos uint64) byte { return byte(pos*29 + pos/127 + 71) }
	writePattern := func(path string, size uint64, pattern func(uint64) byte) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		buf := make([]byte, block)
		for off := uint64(0); off < size; off += uint64(len(buf)) {
			part := buf[:min(uint64(len(buf)), size-off)]
			for i := range part {
				part[i] = pattern(off + uint64(i))
			}
			if _, err = f.Write(part); err != nil {
				t.Fatal(err)
			}
		}
	}
	writePattern(volume, volumeSize, original)
	writePattern(source, length, replacement)
	signature := make([]byte, 8)
	for i := range signature {
		signature[i] = original(uint64(i))
	}
	p := &blockCLIPeer{minor: 2, write: true, length: fileSize, signature: signature}
	var published sync.Map
	var changedDevice atomic.Bool
	observed := make(chan uint64, 2)
	release := make(chan struct{}, 2)
	stop := make(chan struct{})
	var crashCount int
	checkBlock := func(logical uint64) error {
		f, err := os.Open(volume)
		if err != nil {
			return err
		}
		defer f.Close()
		actual := make([]byte, block)
		if _, err = f.ReadAt(actual, int64(newBase+logical)); err != nil {
			return err
		}
		for i, b := range actual {
			pos := logical + uint64(i)
			want := original(oldBase + pos)
			if pos >= offset && pos < offset+length {
				want = replacement(pos - offset)
			}
			if b != want {
				return fmt.Errorf("physical COW mismatch at %d", pos)
			}
		}
		return nil
	}
	p.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
		if code == 9 {
			probe := &missingV4Decoder{b: d.b}
			bits := probe.bitmap()
			if len(bits) == 1 && bits[0] == 65 {
				d.bitmap()
				return missingV4Opaque(blockCLIBitmap(nil, bits), missingV4Words(nil, uint32(block))), 0, nil, true
			}
		}
		if code == 18 && len(d.b) >= 8 && binary.BigEndian.Uint32(d.b[4:8]) == 1 {
			e, s, err := p.readOperation(code, d, current)
			return e, s, err, true
		}
		if code == 34 {
			p.hints.Store(0)
			if len(d.b) >= 16 && bytes.Equal(d.b[:16], bytes.Repeat([]byte{7}, 16)) {
				e, s, err := p.readOperation(code, d, current)
				return e, s, err, true
			}
		}
		if code == 47 && changedDevice.Load() {
			d.take(16)
			d.word()
			d.word()
			d.word()
			body := missingV4Words(nil, 1, 0, 1)
			body = blockCLIQuad(body, 0)
			body = missingV4Opaque(body, []byte("different-volume"))
			return missingV4Words(missingV4Opaque(missingV4Words(nil, 3), body), 0), 0, nil, true
		}
		if code == 50 {
			if p.hints.Load() != 1 || d.word() != 0 || d.word() != 3 {
				return nil, 0, errors.New("missing large block hint"), true
			}
			iomode := d.word()
			if iomode != 1 && iomode != 2 || !bytes.Equal(d.take(8), make([]byte, 8)) || !bytes.Equal(d.take(8), bytes.Repeat([]byte{255}, 8)) || !bytes.Equal(d.take(8), blockCLIQuad(nil, 1)) || !bytes.Equal(d.take(16), bytes.Repeat([]byte{6}, 16)) || d.word() != 32768 {
				return nil, 0, errors.New("large grant identity/range changed"), true
			}
			var body []byte
			extent := func(off, size, physical uint64, state uint32) {
				body = append(body, bytes.Repeat([]byte{0x45}, 16)...)
				body = blockCLIQuad(blockCLIQuad(blockCLIQuad(body, off), size), physical)
				body = missingV4Words(body, state)
			}
			if iomode == 2 {
				body = missingV4Words(nil, 2)
				extent(0, fileSize, oldBase, 1)
				extent(0, fileSize, newBase, 2)
			} else {
				body = missingV4Words(nil, uint32(fileSize/block))
				for off := uint64(0); off < fileSize; off += block {
					physical := oldBase + off
					if _, ok := published.Load(off); ok {
						physical = newBase + off
					}
					extent(off, block, physical, 1)
				}
			}
			e := missingV4Words(nil, 1, 1)
			e = append(e, bytes.Repeat([]byte{8}, 12)...)
			e = missingV4Words(e, 1)
			e = blockCLIQuad(blockCLIQuad(e, 0), fileSize)
			e = missingV4Words(e, iomode, 3)
			p.layouts.Add(1)
			return missingV4Opaque(e, body), 0, nil, true
		}
		if code != 49 {
			return nil, 0, nil, false
		}
		logical := binary.BigEndian.Uint64(d.take(8))
		last := min(logical+block, offset+length) - 1
		if logical%block != 0 || logical < offset/block*block || logical >= offset+length || !bytes.Equal(d.take(8), blockCLIQuad(nil, block)) || d.word() != 0 || !bytes.Equal(d.take(16), append(missingV4Words(nil, 1), bytes.Repeat([]byte{8}, 12)...)) || d.word() != 1 || !bytes.Equal(d.take(8), blockCLIQuad(nil, last)) || d.word() != 0 || d.word() != 3 {
			return nil, 0, errors.New("large commit identity/range changed"), true
		}
		update := &missingV4Decoder{b: d.opaque()}
		if update.word() != 1 || !bytes.Equal(update.take(16), bytes.Repeat([]byte{0x45}, 16)) || !bytes.Equal(update.take(8), blockCLIQuad(nil, logical)) || !bytes.Equal(update.take(8), blockCLIQuad(nil, block)) || !bytes.Equal(update.take(8), make([]byte, 8)) || update.word() != 0 || update.err != nil || len(update.b) != 0 {
			return nil, 0, errors.New("large commit extent changed"), true
		}
		if err := checkBlock(logical); err != nil {
			return nil, 0, err, true
		}
		if _, exists := published.Load(logical); exists {
			return nil, 0, errors.New("published block replayed"), true
		}
		crash := mode != "small-patch" && (crashCount == 0 && logical == 5*block || crashCount == 1 && logical == 11*block)
		// The first death precedes publication; the second follows publication but
		// loses its reply. Fresh READ grants distinguish those outcomes.
		post := crash && crashCount == 1
		if !crash || post {
			published.Store(logical, true)
			p.committed.Add(1)
		}
		if crash {
			crashCount++
			observed <- logical
			select {
			case <-release:
			case <-stop:
			}
			if !post {
				return nil, 10025, nil, true
			}
		}
		return missingV4Words(nil, 0), 0, nil, true
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	peerErrors := make(chan error, 8)
	go func() {
		defer close(done)
		for {
			if err := p.serve(listener); err != nil {
				peerErrors <- err
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("large metadata peer did not stop")
			return
		}
		close(peerErrors)
		for err := range peerErrors {
			if !strings.Contains(err.Error(), "reset by peer") && !strings.Contains(err.Error(), "forcibly closed") && !strings.Contains(err.Error(), "broken pipe") {
				t.Error(err)
			}
		}
	})
	command := "putrangepnfs " + strconv.Quote(source) + " target " + strconv.FormatUint(offset, 10) + " --layout block --block-write --block-volume " + strconv.Quote(volume) + " --block-journal " + strconv.Quote(journal)
	base := []string{"127.0.0.1", "--nfs-version", "4.2", "--nfs-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "--pnfs", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never", "-c", "lock target write"}
	runArgs := func(resume bool) []string {
		c := command
		if resume {
			c += " --block-resume"
		}
		return append(append([]string{}, base...), "-c", c, "-c", "unlock 1")
	}
	if mode != "small-patch" {
		for attempt := range 2 {
			args := runArgs(attempt > 0)
			var child *exec.Cmd
			memory := filepath.Join(dir, fmt.Sprintf("heap-%d", attempt))
			if app := os.Getenv("NFS_VIEWER_TEST_BINARY"); app != "" {
				child = exec.Command(app, args...)
			} else {
				encoded, _ := json.Marshal(args)
				child = exec.Command(os.Args[0], "-test.run=^TestBlockRecoveryChild$")
				child.Env = append(os.Environ(), "NFS_BLOCK_CRASH_ARGS="+string(encoded), "NFS_BLOCK_MEMORY_REPORT="+memory)
			}
			var output bytes.Buffer
			child.Stdout = &output
			child.Stderr = &output
			if err = child.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if child.ProcessState == nil {
					child.Process.Kill()
					child.Wait()
				}
			})
			select {
			case <-observed:
			case <-time.After(30 * time.Second):
				child.Process.Kill()
				child.Wait()
				t.Fatal("large child failed to reach crash", output.String())
			}
			if err = child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = child.Wait(); err == nil {
				t.Fatal("child survived kill")
			}
			release <- struct{}{}
			if os.Getenv("NFS_VIEWER_TEST_BINARY") == "" {
				raw, e := os.ReadFile(memory)
				var peak uint64
				lines := strings.Split(string(raw), "\n")
				// A killed write may leave the final record incomplete; only
				// complete prior samples are evidence, never a truncated file.
				for _, line := range lines[:len(lines)-1] {
					if sample, e := strconv.ParseUint(line, 10, 64); e == nil {
						peak = max(peak, sample)
					}
				}
				if e != nil || peak == 0 || peak > 64<<20 {
					t.Fatalf("bounded heap observer: %d %v", peak, e)
				}
				t.Logf("process %d peak sampled Go heap: %d bytes", attempt+1, peak)
			}
			info, e := nfs.InspectBlockJournal(journal)
			if e != nil || info.Phase != "commit-issued" {
				t.Fatal("lost durable crash boundary", info, e)
			}
		}
	}
	if mode == "changed-source" {
		f, e := os.OpenFile(source, os.O_RDWR, 0)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.WriteAt([]byte{0xff}, 0)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	if mode == "changed-device" {
		changedDevice.Store(true)
	}
	beforeCommits := p.committed.Load()
	out, err := runKerberosCLI(t, runArgs(mode != "small-patch"))
	if strings.HasPrefix(mode, "changed-") {
		if err == nil || p.committed.Load() != beforeCommits {
			t.Fatal("changed source/device permitted mutation", err, out)
		}
		return
	}
	if err != nil {
		t.Fatal("large recovery failed", err, out)
	}
	info, err := nfs.InspectBlockJournal(journal)
	if err != nil || info.Phase != "completed" || info.Progress != length {
		t.Fatal(info, err)
	}
	// Verify all 96 MiB, including source extents, unused COW blocks, signatures,
	// and bytes outside the patch within its two partial boundary blocks.
	f, err := os.Open(volume)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, block)
	for pos := uint64(0); pos < volumeSize; pos += block {
		if _, err = io.ReadFull(f, buf); err != nil {
			t.Fatal(err)
		}
		for i, b := range buf {
			physical := pos + uint64(i)
			want := original(physical)
			if physical >= newBase && physical < newBase+fileSize {
				logical := physical - newBase
				if _, ok := published.Load(logical / block * block); ok {
					want = original(oldBase + logical)
					if logical >= offset && logical < offset+length {
						want = replacement(logical - offset)
					}
				}
			}
			if b != want {
				t.Fatalf("unrelated/expected physical byte changed at %d", physical)
			}
		}
	}
}

func runBlockProcessCrash(t *testing.T, minor uint32, transport, phase string) {
	t.Helper()
	dir := t.TempDir()
	imagePath, source, journal := filepath.Join(dir, "volume"), filepath.Join(dir, "source"), filepath.Join(dir, "journal")
	image := make([]byte, 16384)
	for i := range image {
		image[i] = byte(i*13 + 5)
	}
	patch := bytes.Repeat([]byte("new-file!"), 114)[:1025]
	for name, b := range map[string][]byte{imagePath: image, source: patch} {
		if err := os.WriteFile(name, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := &blockCLIPeer{minor: minor, write: true, growth: true, signature: bytes.Clone(image[:8]), length: 700}
	p.size.Store(700)
	var committed sync.Map
	want := bytes.Clone(image)
	observed, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var gate sync.Once
	apply := func(logical uint64) error {
		block := make([]byte, 512)
		for i := range block {
			pos := logical + uint64(i)
			if pos < 700 {
				block[i] = image[1024+pos]
			}
			if pos >= 2701 && pos < 3726 {
				block[i] = patch[pos-2701]
			}
		}
		copy(want[8192+logical:8192+logical+512], block)
		actual, err := os.ReadFile(imagePath)
		if err != nil || !bytes.Equal(want, actual) {
			return fmt.Errorf("independent physical image mismatch at %d: %v", logical, err)
		}
		return nil
	}
	p.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
		// A recovery read must use a newly opened state and freshly constructed
		// READ extents reflecting only commits accepted by this metadata peer.
		if code == 18 && len(d.b) >= 8 && binary.BigEndian.Uint32(d.b[4:8]) == 1 {
			e, s, err := p.readOperation(code, d, current)
			return e, s, err, true
		}
		if code == 34 {
			p.hints.Store(0)
			if len(d.b) >= 16 && bytes.Equal(d.b[:16], bytes.Repeat([]byte{7}, 16)) {
				e, s, err := p.readOperation(code, d, current)
				return e, s, err, true
			}
		}
		if code == 50 && len(d.b) >= 12 && binary.BigEndian.Uint32(d.b[8:12]) == 1 {
			if p.hints.Load() != 1 || d.word() != 0 || d.word() != 3 || d.word() != 1 || !bytes.Equal(d.take(8), make([]byte, 8)) || !bytes.Equal(d.take(8), bytes.Repeat([]byte{255}, 8)) || !bytes.Equal(d.take(8), blockCLIQuad(nil, 1)) || !bytes.Equal(d.take(16), bytes.Repeat([]byte{6}, 16)) || d.word() != 32768 {
				return nil, 0, errors.New("invalid fresh read grant"), true
			}
			length := (p.size.Load() + 511) / 512 * 512
			body := missingV4Words(nil, uint32(length/512))
			for off := uint64(0); off < length; off += 512 {
				physical, state := uint64(1024)+off, uint32(1)
				if _, ok := committed.Load(off); ok {
					physical = 8192 + off
				} else if off >= 700 {
					physical = 0
					state = 3
				}
				body = append(body, bytes.Repeat([]byte{0x45}, 16)...)
				body = blockCLIQuad(blockCLIQuad(blockCLIQuad(body, off), 512), physical)
				body = missingV4Words(body, state)
			}
			e := missingV4Words(nil, 1, 1)
			e = append(e, bytes.Repeat([]byte{8}, 12)...)
			e = missingV4Words(e, 1)
			e = blockCLIQuad(blockCLIQuad(e, 0), length)
			e = missingV4Words(e, 1, 3)
			p.layouts.Add(1)
			return missingV4Opaque(e, body), 0, nil, true
		}
		if code != 49 {
			return nil, 0, nil, false
		}
		logical := binary.BigEndian.Uint64(d.take(8))
		stop := min(logical+512, uint64(3726))
		if logical < 512 || logical > 3584 || logical%512 != 0 || !bytes.Equal(d.take(8), blockCLIQuad(nil, 512)) || d.word() != 0 || !bytes.Equal(d.take(16), append(missingV4Words(nil, 1), bytes.Repeat([]byte{8}, 12)...)) || d.word() != 1 || !bytes.Equal(d.take(8), blockCLIQuad(nil, stop-1)) || d.word() != 0 || d.word() != 3 {
			return nil, 0, errors.New("invalid recovery commit header"), true
		}
		u := &missingV4Decoder{b: d.opaque()}
		if u.word() != 1 || !bytes.Equal(u.take(16), bytes.Repeat([]byte{0x45}, 16)) || !bytes.Equal(u.take(8), blockCLIQuad(nil, logical)) || !bytes.Equal(u.take(8), blockCLIQuad(nil, 512)) || !bytes.Equal(u.take(8), make([]byte, 8)) || u.word() != 0 || u.err != nil || len(u.b) != 0 {
			return nil, 0, errors.New("invalid recovery commit list"), true
		}
		if err := apply(logical); err != nil {
			return nil, 0, err, true
		}
		blocked := false
		if logical == 3072 && phase != "write-issued" {
			gate.Do(func() { blocked = true })
		}
		if !blocked || phase == "postcommit" || phase == "changed-destination" {
			committed.Store(logical, true)
			p.size.Store(max(p.size.Load(), stop))
			p.committed.Add(1)
		}
		if blocked {
			observed <- struct{}{}
			<-release
			if phase != "postcommit" && phase != "changed-destination" {
				return nil, 10025, nil, true
			}
		}
		return blockCLIQuad(missingV4Words(nil, 1), p.size.Load()), 0, nil, true
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peerErrors := make(chan error, 8)
	peerDone := make(chan struct{})
	stopPeer := make(chan struct{})
	go func() {
		defer close(peerDone)
		for {
			if err := p.serve(l); err != nil {
				peerErrors <- err
			}
			select {
			case <-stopPeer:
				return
			default:
			}
		}
	}()
	// Closing a listener is the only exit condition; the loop below is stopped
	// explicitly after all command processes have closed their connections.
	t.Cleanup(func() {
		unblock()
		close(stopPeer)
		l.Close()
		select {
		case <-peerDone:
		case <-time.After(3 * time.Second):
			t.Error("metadata peer did not stop")
			return
		}
		close(peerErrors)
		for err := range peerErrors {
			if !strings.Contains(err.Error(), "reset by peer") && !strings.Contains(err.Error(), "forcibly closed") && !strings.Contains(err.Error(), "broken pipe") {
				t.Error(err)
			}
		}
	})
	storageArgs := "--block-volume " + strconv.Quote(imagePath)
	var storage *testiscsi.Target
	if transport == "iscsi" {
		o := testiscsi.Options{InvalidStart: 8192, InvalidEnd: 12288, AllowProcessKill: true, ReadAllowed: func(start, length uint64) bool {
			if start < 8192 || start+length > 12288 {
				return false
			}
			for off := (start - 8192) / 512 * 512; off < start+length-8192; off += 512 {
				if _, ok := committed.Load(off); !ok {
					return false
				}
			}
			return true
		}}
		if phase == "write-issued" {
			o.WriteObserved = observed
			o.ContinueWrite = release
		}
		storage = testiscsi.Start(t, imagePath, o)
		t.Cleanup(unblock)
		storageArgs = "--block-target " + strconv.Quote(storage.URL()) + " --block-initiator " + testiscsi.Initiator
	}
	command := "putrangepnfs " + strconv.Quote(source) + " target 2701 --layout block --block-write --extend " + storageArgs + " --block-journal " + strconv.Quote(journal)
	base := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(l.Addr().(*net.TCPAddr).Port), "--pnfs", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never", "-c", "lock target write"}
	args := append(append([]string{}, base...), "-c", command)
	var child *exec.Cmd
	if app := os.Getenv("NFS_VIEWER_TEST_BINARY"); app != "" {
		child = exec.Command(app, args...)
	} else {
		encoded, _ := json.Marshal(args)
		child = exec.Command(os.Args[0], "-test.run=^TestBlockRecoveryChild$")
		child.Env = append(os.Environ(), "NFS_BLOCK_CRASH_ARGS="+string(encoded))
	}
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	})
	select {
	case <-observed:
	case <-time.After(15 * time.Second):
		child.Process.Kill()
		child.Wait()
		t.Fatal("child failed to reach crash boundary", output.String())
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err == nil {
		t.Fatal("process was not terminated")
	}
	unblock()
	info, err := nfs.InspectBlockJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if phase == "write-issued" {
		if info.Phase != "write-issued" {
			t.Fatal(info)
		}
	} else if info.Phase != "commit-issued" || info.Progress != 371 || info.ConfirmedBlocks != 5 {
		t.Fatal("durable boundary lost", info)
	}
	if phase == "changed-source" {
		patch[0] ^= 1
		if err := os.WriteFile(source, patch, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if phase == "changed-destination" {
		f, e := os.OpenFile(imagePath, os.O_RDWR, 0)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.WriteAt([]byte{0xff}, 8192+512)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	if phase == "changed-eof" {
		p.size.Add(1)
	}
	beforeCommits := p.committed.Load()
	beforeWrites := 0
	if storage != nil {
		beforeWrites = bytes.Count(storage.Events(), []byte{0x8a})
	}
	args = append(append([]string{}, base...), "-c", command+" --block-resume", "-c", "unlock 1")
	if phase == "changed-profile" {
		args = append(args, "--uid", "45")
	}
	if phase == "normal-replay" {
		args = append(append([]string{}, base...), "-c", command)
	}
	if phase == "missing-lock" {
		args = append(append([]string{}, base[:len(base)-2]...), "-c", command+" --block-resume")
	}
	out, err := runKerberosCLI(t, args)
	refused := phase != "precommit" && phase != "postcommit"
	if refused {
		if err == nil {
			t.Fatal("unsafe recovery accepted", out)
		}
		if p.committed.Load() != beforeCommits || storage != nil && bytes.Count(storage.Events(), []byte{0x8a}) != beforeWrites {
			t.Fatal("unsafe recovery issued a mutation")
		}
		if phase == "write-issued" {
			out, e := runKerberosCLI(t, []string{"block-state", "inspect", journal})
			if e != nil || !strings.Contains(out, "write-issued") || strings.Contains(out, "Data") {
				t.Fatal("offline inspection failed", e, out)
			}
			if out, e = runKerberosCLI(t, []string{"block-state", "ack", journal, info.ID}); e == nil {
				t.Fatal("ack skipped external verification flags", out)
			}
			if out, e = runKerberosCLI(t, []string{"block-state", "ack", journal, info.ID, "--storage-quiesced", "--destination-verified"}); e != nil {
				t.Fatal("offline acknowledgement failed", e, out)
			}
			final, e := nfs.InspectBlockJournal(journal)
			if e != nil || final.Phase != "acknowledged-unknown" || final.Progress != 0 {
				t.Fatal(final, e)
			}
			if p.committed.Load() != beforeCommits || bytes.Count(storage.Events(), []byte{0x8a}) != beforeWrites {
				t.Fatal("offline command sent storage mutation")
			}
		}
		return
	}
	if err != nil {
		t.Fatal("fresh recovery failed", err, out)
	}
	info, err = nfs.InspectBlockJournal(journal)
	if err != nil || info.Phase != "completed" || info.Progress != 1025 || info.CurrentSize != 3726 || info.ConfirmedBlocks != 7 {
		t.Fatal("incomplete recovery", info, err)
	}
	if p.committed.Load() != 7 {
		t.Fatal("acknowledged block replayed", p.committed.Load())
	}
	beforeWrites = 0
	if storage != nil {
		beforeWrites = bytes.Count(storage.Events(), []byte{0x8a})
	}
	if out, err = runKerberosCLI(t, args); err != nil {
		t.Fatal("completed verification failed", err, out)
	}
	if p.committed.Load() != 7 || storage != nil && bytes.Count(storage.Events(), []byte{0x8a}) != beforeWrites {
		t.Fatal("completed journal replayed storage")
	}
}
