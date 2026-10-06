package nfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBlockJournalTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	j, err := loadBlockJournal(path, true)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{19}, 512)
	pre := sha256.Sum256(make([]byte, 512))
	begin := blockJournalEvent{Kind: "begin", ID: "00112233445566778899aabbccddeeff", Profile: "profile", Epoch: "old", Handle: []byte("file"), Offset: 101, Length: 1000, SourceHash: blockHash([]byte("input")), OriginalSize: 1201, BlockSize: 512}
	if err = j.append(begin); err != nil {
		t.Fatal(err)
	}
	if err = j.prepare(0, pre[:], data, 411, 1201); err != nil {
		t.Fatal(err)
	}
	if err = j.append(blockJournalEvent{Kind: "confirmed"}); err == nil {
		t.Fatal("commit skipped storage sync")
	}
	for _, kind := range []string{"write-issued", "storage-synced", "commit-issued", "confirmed"} {
		if err = j.append(blockJournalEvent{Kind: kind}); err != nil {
			t.Fatal(kind, err)
		}
	}
	if j.state.Progress != 411 || j.state.NextBlock != 512 || j.state.Phase != "ready" {
		t.Fatal(j.state)
	}
	j.file.Close()
	j, err = loadBlockJournal(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	if j.state.Progress != 411 || len(j.state.Confirmed) != 1 {
		t.Fatal("progress lost", j.state)
	}
	if _, err = loadBlockJournal(path, false); err == nil {
		t.Fatal("second process acquired live journal")
	}
}

func blockTestBegin() blockJournalEvent {
	return blockJournalEvent{Kind: "begin", ID: "00112233445566778899aabbccddeeff", Profile: "profile", Epoch: "first", Handle: []byte("file"), Offset: 0, Length: 512, OriginalSize: 512, BlockSize: 512, SourceHash: blockHash([]byte("source"))}
}

func TestBlockJournalCrashChild(t *testing.T) {
	path, phase := os.Getenv("NFS_BLOCK_WAL_PATH"), os.Getenv("NFS_BLOCK_WAL_PHASE")
	if path == "" {
		t.Skip("subprocess helper")
	}
	j, err := loadBlockJournal(path, true)
	if err != nil {
		t.Fatal(err)
	}
	// Retain the open file until process termination; os.File has a finalizer.
	defer j.file.Close()
	if err = j.append(blockTestBegin()); err != nil {
		t.Fatal(err)
	}
	pre := sha256.Sum256(make([]byte, 512))
	if err = j.prepare(0, pre[:], bytes.Repeat([]byte{19}, 512), 512, 512); err != nil {
		t.Fatal(err)
	}
	if phase != "prepared" {
		for _, kind := range []string{"write-issued", "storage-synced", "commit-issued", "confirmed", "completed"} {
			if err = j.append(blockJournalEvent{Kind: kind}); err != nil {
				t.Fatal(err)
			}
			if kind == phase {
				break
			}
		}
	}
	// Exercise ownership across collection while the child waits to be killed.
	runtime.GC()
	runtime.Gosched()
	if err = os.WriteFile(path+".ready", []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestBlockJournalProcessDeath(t *testing.T) {
	for _, phase := range []string{"prepared", "write-issued", "storage-synced", "commit-issued", "confirmed", "completed"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wal")
			cmd := exec.Command(os.Args[0], "-test.run=^TestBlockJournalCrashChild$")
			cmd.Env = append(os.Environ(), "NFS_BLOCK_WAL_PATH="+path, "NFS_BLOCK_WAL_PHASE="+phase)
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
			for {
				if _, err := os.Stat(path + ".ready"); err == nil {
					break
				}
				if time.Now().After(deadline) {
					cmd.Process.Kill()
					cmd.Wait()
					t.Fatal("child not ready", output.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := InspectBlockJournal(path); err == nil {
				t.Fatal("live process lock bypassed")
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil {
				t.Fatal("child was not killed")
			}
			info, err := InspectBlockJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			want := phase
			if phase == "confirmed" {
				want = "ready"
			}
			if info.Phase != want {
				t.Fatal(info)
			}
			if phase == "confirmed" || phase == "completed" {
				if info.Progress != 512 || info.ConfirmedBlocks != 1 {
					t.Fatal(info)
				}
			} else if info.Progress != 0 || info.PendingOffset == nil {
				t.Fatal(info)
			}
		})
	}
}

func TestBlockJournalCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal")
	j, err := loadBlockJournal(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.append(blockTestBegin()); err != nil {
		t.Fatal(err)
	}
	j.file.Close()
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(payload []byte) []byte {
		h := sha256.Sum256(payload)
		b := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
		b = append(b, payload...)
		return append(b, h[:]...)
	}
	e := blockTestBegin()
	e.Sequence = 2
	sequence, _ := json.Marshal(e)
	for name, b := range map[string][]byte{
		"empty": {}, "magic": []byte("garbage"), "header": append(bytes.Clone(valid), 1),
		"tail": valid[:len(valid)-1], "checksum": append(bytes.Clone(valid[:len(valid)-1]), valid[len(valid)-1]^1),
		"oversize":      append(bytes.Clone(valid), binary.BigEndian.AppendUint32(nil, maxBlockFrame+1)...),
		"unknown-field": append([]byte(blockJournalMagic), frame([]byte(`{"Sequence":1,"Kind":"begin","Secret":1}`))...),
		"trailing-json": append([]byte(blockJournalMagic), frame(append(sequence, []byte(` {}`)...))...),
		"sequence":      append([]byte(blockJournalMagic), frame(sequence)...),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad")
			if err := os.WriteFile(p, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBlockJournal(p, false); err == nil {
				t.Fatal("corrupt WAL accepted")
			}
			after, _ := os.ReadFile(p)
			if !bytes.Equal(after, b) {
				t.Fatal("corruption was silently truncated")
			}
		})
	}
}

func TestBlockJournalRefusalAndAck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal")
	j, err := loadBlockJournal(path, true)
	if err != nil {
		t.Fatal(err)
	}
	e := blockTestBegin()
	if err = j.append(e); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"confirmed", "write-issued", "storage-synced", "commit-issued", "completed", "unknown"} {
		if err = j.append(blockJournalEvent{Kind: kind}); err == nil {
			t.Fatal("skipped phase", kind)
		}
	}
	if err = j.append(blockJournalEvent{Kind: "resumed", Epoch: "second"}); err != nil {
		t.Fatal(err)
	}
	if err = j.append(blockJournalEvent{Kind: "resumed", Epoch: "second"}); err == nil {
		t.Fatal("same incarnation resumed")
	}
	if j.state.Intent.Epoch != "second" {
		t.Fatal("incarnation not persisted")
	}
	j.file.Close()
	if err = validateBlockJournalGate(PNFSOptions{BlockJournal: path}); err == nil {
		t.Fatal("pending operation overwritten")
	}
	if err = AcknowledgeBlockJournal(path, "different-id"); err == nil {
		t.Fatal("wrong ID acknowledged")
	}
	if err = AcknowledgeBlockJournal(path, e.ID); err != nil {
		t.Fatal(err)
	}
	info, err := InspectBlockJournal(path)
	if err != nil || info.Phase != "acknowledged-unknown" || info.Progress != 0 {
		t.Fatal(info, err)
	}
	if err = validateBlockJournalGate(PNFSOptions{BlockJournal: path, BlockResume: true}); err == nil {
		t.Fatal("acknowledgement claimed resumability")
	}
	if err = validateBlockJournalGate(PNFSOptions{BlockJournal: path}); err != nil {
		t.Fatal(err)
	}
	if err = checkBlockJournalAliases(PNFSOptions{BlockJournal: path, BlockVolumes: []string{path}}, nil); err == nil {
		t.Fatal("volume/journal alias accepted")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = checkBlockJournalAliases(PNFSOptions{BlockJournal: path}, f); err == nil {
		t.Fatal("source/journal alias accepted")
	}
	if _, err = loadBlockJournal("relative", true); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestBlockJournalIntentBounds(t *testing.T) {
	for _, mode := range []string{"overflow", "size", "block-size", "source-hash", "id", "handle", "range"} {
		t.Run(mode, func(t *testing.T) {
			e := blockTestBegin()
			switch mode {
			case "overflow":
				e.Offset = ^uint64(0)
			case "size":
				e.OriginalSize = maxBlockRecoveryFile + 1
			case "block-size":
				e.BlockSize = 513
			case "source-hash":
				e.SourceHash = "bad"
			case "id":
				e.ID = strings.Repeat("a", 33)
			case "handle":
				e.Handle = make([]byte, 129)
			case "range":
				e.Length = 513
			}
			if _, err := applyBlockEvent(blockJournalState{}, e); err == nil {
				t.Fatal("invalid intent accepted")
			}
		})
	}
}

func TestMITBlockJournalWrites(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_GSS") != "1" {
		t.Skip("MIT fixture not enabled")
	}
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"cow", "rw", "commit-drop", "write-drop", "sync-drop"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%t/%s", minor, security, secure, mode), func(t *testing.T) { runBlockWriteWire(t, minor, "journal-iscsi-"+mode, security, secure) })
				}
			}
		}
	}
}

func TestBlockRecoveryIntentPinning(t *testing.T) {
	for _, mode := range []string{"same-client", "changed-profile", "changed-handle", "changed-range", "changed-source", "changed-block-size", "changed-growth", "out-of-int64", "missing-incarnation"} {
		t.Run(mode, func(t *testing.T) {
			c := &Client{version: "4.1", config: &Config{}, v4: &v4Client{clientNonce: bytes.Repeat([]byte{1}, 16), clientID: 123}}
			o := PNFSOptions{BlockJournal: filepath.Join(t.TempDir(), "wal"), Extend: true}
			data := bytes.Repeat([]byte{4}, 512)
			j, buffered, err := c.beginBlockRecovery(o, []byte("file"), 0, 512, bytes.NewReader(data), Attr{Size: 512}, 512)
			if err != nil {
				t.Fatal(err)
			}
			buffered.Close()
			j.file.Close()
			o.BlockResume = true
			c.v4.clientNonce = bytes.Repeat([]byte{2}, 16)
			fh, offset, length, bs, size := []byte("file"), uint64(0), uint64(512), uint64(512), uint64(512)
			switch mode {
			case "same-client":
				c.v4.clientNonce = bytes.Repeat([]byte{1}, 16)
			case "changed-profile":
				c.Auth.UID = 45
			case "changed-handle":
				fh = []byte("other")
			case "changed-range":
				offset = 1
				length = 511
			case "changed-source":
				data[0] ^= 1
			case "changed-block-size":
				bs = 1024
			case "changed-growth":
				o.Extend = false
			case "out-of-int64":
				size = ^uint64(0)
			case "missing-incarnation":
				c.v4.clientNonce = nil
			}
			if j, _, err = c.beginBlockRecovery(o, fh, offset, length, bytes.NewReader(data), Attr{Size: size}, bs); err == nil {
				j.file.Close()
				t.Fatal("changed recovery authorization accepted")
			}
			info, err := InspectBlockJournal(o.BlockJournal)
			if err != nil || info.Phase != "ready" || info.Progress != 0 {
				t.Fatal("refusal damaged WAL", info, err)
			}
		})
	}
}
