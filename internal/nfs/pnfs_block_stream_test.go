package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBlockRecoverySmallPatchLargeDestination(t *testing.T) {
	c := &Client{version: "4.1", config: &Config{}, v4: &v4Client{clientNonce: bytes.Repeat([]byte{1}, 16), clientID: 123}}
	o := PNFSOptions{BlockJournal: filepath.Join(t.TempDir(), "wal")}
	data := []byte("preserve unrelated bytes")
	j, r, err := c.beginBlockRecovery(o, []byte("file"), 32<<20, uint64(len(data)), bytes.NewReader(data), Attr{Size: 64 << 20}, 512)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal(got, err)
	}
}

func TestBlockSpoolProcessDeath(t *testing.T) {
	if ready := os.Getenv("NFS_BLOCK_SPOOL_READY"); ready != "" {
		f, err := newBlockSpool()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err = f.Write(make([]byte, 1<<20)); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(ready, []byte(f.Name()), 0600); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestBlockSpoolProcessDeath$")
	cmd.Env = append(os.Environ(), "NFS_BLOCK_SPOOL_READY="+ready)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	var name []byte
	for {
		var err error
		name, err = os.ReadFile(ready)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("spool child not ready", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("spool child was not killed")
	}
	if _, err := os.Stat(string(name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private spool survived process death", err)
	}
}

type blockPatternReader struct {
	remaining uint64
	largest   int
}

type cancelBlockSource struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancelBlockSource) Read(p []byte) (int, error) {
	r.reads++
	clear(p)
	r.cancel()
	return len(p), nil
}

func TestBlockSourcePreparationGuard(t *testing.T) {
	for _, mode := range []string{"cancel", "profile-or-lock"} {
		t.Run(mode, func(t *testing.T) {
			c := &Client{version: "4.1", config: &Config{}, v4: &v4Client{clientNonce: bytes.Repeat([]byte{1}, 16)}}
			o := PNFSOptions{BlockJournal: filepath.Join(t.TempDir(), "wal")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := &cancelBlockSource{cancel: cancel}
			guard := ctx.Err
			if mode == "profile-or-lock" {
				guard = func() error {
					if source.reads > 0 {
						return errors.New("fixed profile or lock lost")
					}
					return nil
				}
			}
			if j, r, err := c.beginBlockRecovery(o, []byte("file"), 0, 80<<20, source, Attr{Size: 80 << 20}, 1<<20, guard); err == nil {
				r.Close()
				j.file.Close()
				t.Fatal("lost preparation guard accepted")
			}
			if source.reads != 1 {
				t.Fatal("read continued after guard loss", source.reads)
			}
			state, err := InspectBlockJournal(o.BlockJournal)
			if err != nil || state.Phase != "" {
				t.Fatal("failed preparation published intent", state, err)
			}
		})
	}
}

func (r *blockPatternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	r.largest = max(r.largest, len(p))
	p = p[:min(uint64(len(p)), r.remaining)]
	for i := range p {
		p[i] = byte(r.remaining - uint64(i))
	}
	r.remaining -= uint64(len(p))
	return len(p), nil
}

func TestBlockSourceSnapshotBoundedMemory(t *testing.T) {
	c := &Client{version: "4.1", config: &Config{}, v4: &v4Client{clientNonce: bytes.Repeat([]byte{1}, 16)}}
	o := PNFSOptions{BlockJournal: filepath.Join(t.TempDir(), "wal")}
	input := &blockPatternReader{remaining: 80 << 20}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	j, r, err := c.beginBlockRecovery(o, []byte("file"), 0, 80<<20, input, Attr{Size: 80 << 20}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	runtime.ReadMemStats(&after)
	if input.largest > 64<<10 || after.TotalAlloc-before.TotalAlloc > 16<<20 {
		t.Fatalf("source buffering scales with range: max read %d, allocated %d", input.largest, after.TotalAlloc-before.TotalAlloc)
	}
	name := r.reader.Name()
	if n, err := io.Copy(io.Discard, r); err != nil || n != 80<<20 {
		t.Fatal(n, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source spool survived close", err)
	}
}

func TestBlockCheckpointBoundedLongTransfer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal")
	j, err := loadBlockJournal(path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	e := blockTestBegin()
	e.Length = 50 << 20
	e.OriginalSize = e.Length
	e.BlockSize = 1 << 20
	if err = j.append(e); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{29}, 1<<20)
	pre := sha256.Sum256(make([]byte, len(data)))
	for block := uint64(0); block < 50; block++ {
		if err = j.prepare(block<<20, pre[:], data, 1<<20, e.Length); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"write-issued", "storage-synced", "commit-issued", "confirmed"} {
			if err = j.append(blockJournalEvent{Kind: kind}); err != nil {
				t.Fatal(block, kind, err)
			}
		}
		if len(j.state.Confirmed) != 0 {
			t.Fatal("per-block history retained")
		}
	}
	if err = j.append(blockJournalEvent{Kind: "completed"}); err != nil {
		t.Fatal(err)
	}
	j.file.Close()
	j, err = loadBlockJournal(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	info, err := j.file.Stat()
	if err != nil || info.Size() != int64(blockCheckpointSize) || j.state.Progress != 50<<20 || j.state.ConfirmedCount != 50 {
		t.Fatal(info, j.state.Progress, err)
	}
}

func TestBlockCheckpointInterruptedWrites(t *testing.T) {
	for _, stage := range []string{"before-write", "invalidated", "partial-body", "body-synced", "committed"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wal")
			j, err := loadBlockJournal(path, true, true)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.append(blockTestBegin()); err != nil {
				t.Fatal(err)
			}
			pre := sha256.Sum256(make([]byte, 512))
			if err = j.prepare(0, pre[:], make([]byte, 512), 512, 512); err != nil {
				t.Fatal(err)
			}
			j.checkpointFault = func(at string) error {
				if at == stage {
					return errors.New("injected crash")
				}
				return nil
			}
			if err = j.append(blockJournalEvent{Kind: "write-issued"}); err == nil {
				t.Fatal("fault missed")
			}
			j.file.Close()
			j, err = loadBlockJournal(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer j.file.Close()
			want := "prepared"
			if stage == "committed" {
				want = "write-issued"
			}
			if j.state.Phase != want {
				t.Fatal(j.state.Phase, want)
			}
		})
	}
}

func TestBlockCheckpointCommittedCorruptionRefused(t *testing.T) {
	for _, footer := range []bool{false, true} {
		t.Run(map[bool]string{false: "body", true: "partial-footer"}[footer], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wal")
			j, err := loadBlockJournal(path, true, true)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.append(blockTestBegin()); err != nil {
				t.Fatal(err)
			}
			pos := int64(len(blockCheckpointMagic) + 4)
			if footer {
				pos += blockCheckpointPayload
			}
			if _, err = j.file.WriteAt([]byte{0xff}, pos); err != nil {
				t.Fatal(err)
			}
			j.file.Close()
			if j, err = loadBlockJournal(path, false); err == nil {
				j.file.Close()
				t.Fatal("committed corruption accepted")
			}
		})
	}
}

func TestBlockStreamingVerification(t *testing.T) {
	// Construct the source oracle independently, including a partial final block.
	data := make([]byte, 4*512+71)
	for i := range data {
		data[i] = byte(i*13 + 9)
	}
	var previous [32]byte
	for off := uint64(512); off < 2048; off += 512 {
		h := sha256.New()
		h.Write([]byte("NFS-BLOCK-CONFIRMED-2"))
		h.Write(previous[:])
		var pos [8]byte
		binary.BigEndian.PutUint64(pos[:], off)
		h.Write(pos[:])
		sum := sha256.Sum256(data[off : off+512])
		h.Write(sum[:])
		copy(previous[:], h.Sum(nil))
	}
	s := blockJournalState{Version: 2, Intent: blockJournalEvent{Offset: 599, OriginalSize: uint64(len(data)), BlockSize: 512}, NextBlock: 2048, ConfirmedCount: 3, ConfirmedDigest: hex.EncodeToString(previous[:]), Prepared: &blockJournalEvent{Offset: 2048}}
	for _, changed := range []bool{false, true} {
		visible := bytes.Clone(data)
		if changed {
			visible[1029] ^= 1
		}
		w := newBlockRecoveryVerifier(s)
		for off := 0; off < len(visible); off += 113 {
			if _, err := w.Write(visible[off:min(off+113, len(visible))]); err != nil {
				t.Fatal(err)
			}
		}
		err := w.finish(uint64(len(visible)))
		if changed {
			if err == nil {
				t.Fatal("changed confirmed bytes accepted")
			}
			continue
		}
		want := make([]byte, 512)
		copy(want, data[2048:])
		if err != nil || !bytes.Equal(w.pending, want) {
			t.Fatal("streaming postimage mismatch", err)
		}
	}
}

func TestBlockLegacyJournalPreciseRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal")
	j, err := loadBlockJournal(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.append(blockTestBegin()); err != nil {
		t.Fatal(err)
	}
	j.file.Close()
	c := &Client{version: "4.1", config: &Config{}, v4: &v4Client{clientNonce: bytes.Repeat([]byte{1}, 16)}}
	if _, _, err = c.beginBlockRecovery(PNFSOptions{BlockJournal: path, BlockResume: true}, []byte("file"), 0, 512, bytes.NewReader(make([]byte, 512)), Attr{Size: 512}, 512); err == nil {
		t.Fatal("legacy intent resumed")
	}
	if _, err = InspectBlockJournal(path); err != nil {
		t.Fatal("legacy inspection lost", err)
	}
}
