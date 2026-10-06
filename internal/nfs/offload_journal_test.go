package nfs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOffloadJournalRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offload-state")
	intent := offloadIntent{Operation: "copyasync", Destination: []byte("destination"), Length: 6}
	j, err := openOffloadJournal(path, "profile", intent)
	if err != nil {
		t.Fatal(err)
	}
	j.file.Close() // Process crash before a data/authorization request.
	j, err = openOffloadJournal(path, "profile", intent)
	if err != nil {
		t.Fatal("prepared recovery", err)
	}
	if err = j.issue(); err != nil {
		t.Fatal(err)
	}
	id := j.record.ID
	j.file.Close() // Process crash after intent was synced, without a reply.
	if _, err = openOffloadJournal(path, "profile", intent); !errors.Is(err, ErrOffloadPending) {
		t.Fatal("unknown operation replay allowed", err)
	}
	r, err := InspectOffloadJournal(path)
	if err != nil || !r.Pending || r.ID != id || r.Phase != "issued" {
		t.Fatal(r, err)
	}
	if err = AcknowledgeOffloadJournal(path, "wrong"); err == nil {
		t.Fatal("wrong operation acknowledged")
	}
	if err = AcknowledgeOffloadJournal(path, id); err != nil {
		t.Fatal(err)
	}
	r, err = InspectOffloadJournal(path)
	if err != nil || r.Pending || r.Outcome != "acknowledged-unknown" {
		t.Fatal(r, err)
	}
	j, err = openOffloadJournal(path, "profile", intent)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.issue(); err != nil {
		t.Fatal(err)
	}
	if err = j.finish(nil); err != nil {
		t.Fatal(err)
	}
	r, err = InspectOffloadJournal(path)
	if err != nil || r.Pending || r.Outcome != "completed" {
		t.Fatal(r, err)
	}
}

func journalCopyClient(t *testing.T, path string, reply operationReply4) *Client {
	c := copyPeer(t, reply)
	c.config = &Config{Host: "fixture.test", Version: "4.2", Offload: true, OffloadJournal: path}
	c.v4.recall = &layoutRecall{offloadEnabled: true, minor: 2, session: bytes.Repeat([]byte{9}, 16)}
	return c
}

func TestOffloadJournalProcessCrash(t *testing.T) {
	if path := os.Getenv("NFS_VIEWER_OFFLOAD_CRASH_PATH"); path != "" {
		mode := os.Getenv("NFS_VIEWER_OFFLOAD_CRASH_MODE")
		c := journalCopyClient(t, path, func(code uint32, d *decoder) (encoder, Status, error) {
			if code == 32 {
				return nil, 0, nil
			}
			if mode == "issued" && code == 60 || mode == "callback-id" && code == 67 {
				fmt.Println("CRASH-BOUNDARY")
				select {}
			}
			if code == 60 {
				d.take(len(d.b))
				var e encoder
				e.u32(1)
				e = append(e, bytes.Repeat([]byte{8}, 16)...)
				e.u64(0)
				e.u32(2)
				e = append(e, []byte("verifier")...)
				e.u32(1)
				e.u32(0)
				return e, 0, nil
			}
			return nil, 0, fmt.Errorf("unexpected operation %d", code)
		})
		if mode == "prepared" {
			j, err := openOffloadJournal(path, c.offloadProfile(), offloadIntent{Operation: "copyasync", Source: []byte("source"), Destination: []byte("destination"), Length: 6})
			if err != nil {
				t.Fatal(err)
			}
			defer j.file.Close()
			fmt.Println("CRASH-BOUNDARY")
			select {}
		}
		_, err := c.CopyRangeAsync(context.Background(), []byte("source"), []byte("destination"), 0, 0, 6, 20*time.Second)
		t.Fatal("child reached end instead of crash boundary", err)
	}
	for _, mode := range []string{"prepared", "issued", "callback-id"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestOffloadJournalProcessCrash$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "NFS_VIEWER_OFFLOAD_CRASH_PATH="+path, "NFS_VIEWER_OFFLOAD_CRASH_MODE="+mode)
			var diagnostic bytes.Buffer
			cmd.Stderr = &diagnostic
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewScanner(stdout)
			found := false
			for reader.Scan() {
				if reader.Text() == "CRASH-BOUNDARY" {
					found = true
					break
				}
				diagnostic.WriteString(reader.Text() + "\n")
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if !found {
				t.Fatal("child missed crash boundary", diagnostic.String())
			}
			r, err := InspectOffloadJournal(path)
			if err != nil || !r.Pending || (mode == "callback-id" && len(r.CallbackID) != 16) {
				t.Fatal(r, err)
			}
			var copies atomic.Int32
			c := journalCopyClient(t, path, func(code uint32, d *decoder) (encoder, Status, error) {
				if code == 32 {
					return nil, 0, nil
				}
				copies.Add(1)
				d.take(len(d.b))
				var e encoder
				e.u32(0)
				e.u64(6)
				e.u32(2)
				e = append(e, []byte("verifier")...)
				e.u32(1)
				e.u32(1)
				return e, 0, nil
			})
			n, err := c.CopyRangeAsync(context.Background(), []byte("source"), []byte("destination"), 0, 0, 6, time.Second)
			if mode == "prepared" {
				if err != nil || n != 6 || copies.Load() != 1 {
					t.Fatal("safe prepared recovery", n, err, copies.Load())
				}
			} else if !errors.Is(err, ErrOffloadPending) || copies.Load() != 0 {
				t.Fatal("replayed crashed operation", err, copies.Load())
			}
		})
	}
}

func TestOffloadJournalMutationGate(t *testing.T) {
	for _, kind := range []string{"success", "lost", "closed-journal", "full", "bad-destination", "cancelled-before-issue"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			var calls atomic.Int32
			var c *Client
			c = journalCopyClient(t, path, func(code uint32, d *decoder) (encoder, Status, error) {
				if code == 32 {
					return nil, 0, nil
				}
				calls.Add(1)
				journal := c.v4.recall.offload.journal
				data := make([]byte, journal.size)
				_, err := journal.file.ReadAt(data, 0)
				if err != nil || !bytes.Contains(data, []byte(`"Phase":"issued"`)) {
					t.Error("mutation preceded durable issue marker", err)
				}
				d.take(len(d.b))
				if kind == "lost" {
					return []byte{0}, 0, nil
				}
				var e encoder
				e.u32(0)
				e.u64(6)
				e.u32(2)
				e = append(e, []byte("verifier")...)
				e.u32(1)
				e.u32(1)
				return e, 0, nil
			})
			if kind == "full" {
				if err := os.WriteFile(path, make([]byte, maxOffloadJournal+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "closed-journal" {
				end, err := c.v4.beginOffload(offloadIntent{Operation: "copyasync", Source: []byte("source"), Destination: []byte("destination"), Length: 6})
				if err != nil {
					t.Fatal(err)
				}
				c.v4.recall.offload.journal.file.Close()
				err = c.v4.issueOffload()
				if err == nil {
					t.Fatal("closed journal issued")
				}
				end(&err)
				return
			}
			fh := []byte("destination")
			if kind == "bad-destination" {
				fh = []byte("other")
			}
			ctx, cancel := context.WithCancel(context.Background())
			if kind == "cancelled-before-issue" {
				cancel()
			}
			defer cancel()
			n, err := c.CopyRangeAsync(ctx, []byte("source"), fh, 0, 0, 6, time.Second)
			good := kind == "success"
			if (err == nil) != good || good && n != 6 {
				t.Fatal(n, err)
			}
			if kind != "success" && kind != "lost" && calls.Load() != 0 {
				t.Fatal("data request passed failed preflight", calls.Load())
			}
			if kind == "full" {
				return
			}
			r, readErr := InspectOffloadJournal(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if r.Pending != (kind == "lost") {
				t.Fatal("incorrect quarantine", r)
			}
			if kind == "lost" {
				var sideEffects atomic.Int32
				fresh := journalCopyClient(t, path, func(code uint32, d *decoder) (encoder, Status, error) {
					sideEffects.Add(1)
					return nil, 0, errors.New("unexpected retry")
				})
				_, err = fresh.CopyRangeAsync(context.Background(), []byte("source"), []byte("destination"), 0, 0, 6, time.Second)
				if !errors.Is(err, ErrOffloadPending) || sideEffects.Load() != 0 {
					t.Fatal("unknown request retried", err)
				}
			}
		})
	}
}

func TestOffloadStateIDNonzeroSequence(t *testing.T) {
	var e encoder
	e.u32(1)
	id := bytes.Repeat([]byte{7}, 16)
	clear(id[:4])
	e = append(e, id...)
	e.u64(0)
	e.u32(2)
	e = append(e, []byte("verifier")...)
	d := &decoder{b: e}
	decodeOffloadReply(d)
	if d.err == nil {
		t.Fatal("zero sequence accepted")
	}
	binary.BigEndian.PutUint32(e[4:8], 1)
	d = &decoder{b: e}
	decodeOffloadReply(d)
	if d.err != nil {
		t.Fatal(d.err)
	}
}

func TestOffloadJournalConfig(t *testing.T) {
	for _, cfg := range []Config{{Version: "4.2", OffloadJournal: filepath.Join(t.TempDir(), "state")}, {Version: "4.2", Offload: true, OffloadJournal: "relative-state"}} {
		if _, err := Connect(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "offload journal requires") {
			t.Fatal(err)
		}
	}
}

func TestOffloadJournalTransitions(t *testing.T) {
	prepared := OffloadRecord{Version: 1, Sequence: 1, ID: strings.Repeat("a", 32), Profile: "profile", Operation: "copyasync", Destination: []byte("file"), Length: 6, Phase: "prepared", Pending: true}
	if err := validateOffloadRecord(prepared, OffloadRecord{}); err != nil {
		t.Fatal(err)
	}
	issued := prepared
	issued.Sequence++
	issued.Phase = "issued"
	for _, kind := range []string{"intent-change", "target-change", "sequence-gap", "phase-regression", "different-id", "different-profile", "false-completion", "completed-with-error", "bad-length", "unknown-operation", "old-callback"} {
		t.Run(kind, func(t *testing.T) {
			r := issued
			r.Sequence++
			previous := issued
			switch kind {
			case "intent-change":
				r.Offset = 1
			case "target-change":
				r.Target = "other-target"
			case "sequence-gap":
				r.Sequence++
			case "phase-regression":
				r.Phase = "prepared"
			case "different-id":
				r.ID = strings.Repeat("b", 32)
			case "different-profile":
				r.Profile = "other"
			case "false-completion":
				r.Outcome = "completed"
			case "completed-with-error":
				r.Pending = false
				r.Outcome = "completed"
				r.Error = "failed cleanup"
			case "bad-length":
				r.Length = 0
			case "unknown-operation":
				r.Operation = "write"
			case "old-callback":
				previous.CallbackID = bytes.Repeat([]byte{1}, 16)
				r.CallbackID = bytes.Repeat([]byte{2}, 16)
			}
			if err := validateOffloadRecord(r, previous); err == nil {
				t.Fatal("invalid transition accepted")
			}
		})
	}
}

func TestOffloadJournalSourceConnectionGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	j, err := openOffloadJournal(path, "profile", offloadIntent{Operation: "copyfrom", Source: []byte("source"), Destination: []byte("file"), Length: 6})
	if err != nil {
		t.Fatal(err)
	}
	if err = j.issue(); err != nil {
		t.Fatal(err)
	}
	j.file.Close()
	c := &Client{config: &Config{OffloadJournal: path}}
	_, err = c.ConnectCopySourceOptions(context.Background(), "127.0.0.1:1", CopyFromOptions{})
	if !errors.Is(err, ErrOffloadPending) {
		t.Fatal("source connection was not gated", err)
	}
}

func TestOffloadJournalGSS(t *testing.T) { runCopyFromGSS(t, false, false, true) }
func TestOffloadJournalMIT(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	runCopyFromGSS(t, true, false, true)
}
func TestOffloadJournalMITTLS(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	runCopyFromGSS(t, true, true, true)
}

func TestOffloadJournalIntegrity(t *testing.T) {
	for _, mode := range []string{"empty", "truncated", "checksum", "profile", "concurrent", "renamed", "failure"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			j, err := openOffloadJournal(path, "profile", offloadIntent{Operation: "writesame", Destination: []byte("file"), Length: 6})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "concurrent" {
				if _, err := InspectOffloadJournal(path); err == nil {
					t.Fatal("process lock ignored")
				}
				j.file.Close()
				return
			}
			if mode == "renamed" {
				// Replace the path after closing to work on Windows as well.
				j.file.Close()
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := j.issue(); err == nil {
					t.Fatal("closed/replaced file accepted")
				}
				return
			}
			if mode == "failure" {
				if err := j.issue(); err != nil {
					t.Fatal(err)
				}
				if err := j.finish(errors.New("reply lost")); err != nil {
					t.Fatal(err)
				}
				r, err := InspectOffloadJournal(path)
				if err != nil || !r.Pending || r.Outcome != "unverified" {
					t.Fatal(r, err)
				}
				return
			}
			if err := j.finish(nil); err != nil {
				t.Fatal(err)
			}
			if mode == "profile" {
				if _, err := openOffloadJournal(path, "another-profile", offloadIntent{Operation: "copyasync", Destination: []byte("file"), Length: 6}); err == nil {
					t.Fatal("profile mismatch accepted")
				}
				return
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "empty":
				data = nil
			case "truncated":
				data = data[:len(data)-1]
			case "checksum":
				data[8] ^= 1
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectOffloadJournal(path); err == nil {
				t.Fatal("corrupt journal accepted")
			}
		})
	}
}
