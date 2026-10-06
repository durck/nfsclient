package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgressCompletionFailureAndThrottling(t *testing.T) {
	for _, fail := range []bool{false, true} {
		var out bytes.Buffer
		now := time.Unix(0, 0)
		p := &transferProgress{w: &out, operation: "GET", enabled: true, live: true, now: func() time.Time { return now }, width: func() int { return 100 }, started: now}
		p.Update(0, 1024)
		first := out.Len()
		p.Update(512, 1024)
		if out.Len() != first {
			t.Fatal("progress update was not throttled")
		}
		now = now.Add(time.Second)
		p.Update(512, 1024)
		if !strings.Contains(out.String(), "50%") || !strings.Contains(out.String(), "512 B/s") || !strings.Contains(out.String(), "ETA 1s") {
			t.Fatal(out.String())
		}
		now = now.Add(time.Second)
		p.Update(1024, 1024)
		if strings.Contains(out.String(), "100%") || !strings.Contains(out.String(), "saving") {
			t.Fatal("reported success before finalization")
		}
		var err error
		if fail {
			err = errors.New("publish failed")
		}
		p.Finish(1024, err)
		if fail {
			if strings.Contains(out.String(), "100%") || strings.Contains(out.String(), "DONE") || !strings.Contains(out.String(), "FAILED") {
				t.Fatal("false success on failure")
			}
		} else if !strings.Contains(out.String(), "100%") || !strings.Contains(out.String(), "DONE") {
			t.Fatal("missing successful completion")
		}
		last := out.Len()
		p.Update(2048, 1024)
		p.Finish(1024, nil)
		if out.Len() != last {
			t.Fatal("output after completion")
		}
	}
}

func TestProgressZeroAndGrowingFiles(t *testing.T) {
	for _, total := range []uint64{0, 1} {
		var out bytes.Buffer
		now := time.Unix(0, 0)
		p := &transferProgress{w: &out, operation: "PUT", enabled: true, now: func() time.Time { return now }, width: func() int { return 40 }, started: now}
		p.Update(0, total)
		now = now.Add(time.Second)
		p.Update(2, total)
		if strings.Contains(out.String(), "100%") || strings.Contains(out.String(), "Inf") {
			t.Fatal(out.String())
		}
		p.Finish(2, nil)
		if !strings.Contains(out.String(), "100%") {
			t.Fatal(out.String())
		}
	}
}

func TestProgressOutputPolicy(t *testing.T) {
	t.Setenv("TERM", "xterm")
	for _, tc := range []struct {
		mode      string
		tty, live bool
	}{{"auto", false, false}, {"auto", true, true}, {"never", true, false}, {"always", false, false}} {
		var out bytes.Buffer
		p := newProgress(&out, "get", "file\x1b(0", "local", tc.mode, tc.tty, false)
		p.Update(0, 100)
		p.Finish(100, nil)
		if strings.Contains(out.String(), "\r") != tc.live {
			t.Fatalf("policy %+v: %q", tc, out.String())
		}
		if strings.Contains(out.String(), "\x1b(0") {
			t.Fatal("unsafe filename printed")
		}
		if !tc.live && strings.Contains(out.String(), "\x1b[") {
			t.Fatal("ANSI emitted into log")
		}
	}
}

func TestProgressFitsNarrowTerminal(t *testing.T) {
	for _, width := range []int{1, 10, 20, 40, 60, 79, 80, 100} {
		now := time.Unix(100, 0)
		p := &transferProgress{done: 1 << 48, total: 1 << 60, started: now.Add(-time.Second), width: func() int { return width }}
		if line := p.line(now, "", false); len(line) >= width {
			t.Fatalf("width %d: %q", width, line)
		}
	}
}

func TestGetPutProgressReportsActualBytes(t *testing.T) {
	sh, root, _ := testShell(t)
	data := bytes.Repeat([]byte("roundtrip"), 10000)
	if err := os.WriteFile(filepath.Join(sh.LocalDir, "source"), data, 0600); err != nil {
		t.Fatal(err)
	}
	var previous uint64
	updates := 0
	observe := func(done, total uint64) {
		if total != uint64(len(data)) || done < previous || done > total {
			t.Fatalf("bad progress %d/%d after %d", done, total, previous)
		}
		previous = done
		updates++
	}
	n, err := sh.Session.PutProgress(context.Background(), filepath.Join(sh.LocalDir, "source"), "target", observe)
	if err != nil || n != int64(len(data)) || previous != uint64(len(data)) || updates < 3 {
		t.Fatalf("put progress: %d %d %v", n, updates, err)
	}
	previous, updates = 0, 0
	n, err = sh.Session.GetProgress(context.Background(), "target", filepath.Join(sh.LocalDir, "copy"), observe)
	if err != nil || n != int64(len(data)) || previous != uint64(len(data)) || updates < 3 {
		t.Fatalf("get progress: %d %d %v", n, updates, err)
	}
	for _, name := range []string{filepath.Join(root, "target"), filepath.Join(sh.LocalDir, "copy")} {
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	sh.ProgressMode = "always"
	if _, err := sh.Execute(context.Background(), "get target copy2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sh.Err.(*bytes.Buffer).String(), "100%") {
		t.Fatal("shell did not connect progress")
	}
	if err := os.WriteFile(filepath.Join(sh.LocalDir, "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	emptyUpdates := 0
	emptyProgress := func(done, total uint64) {
		if done != 0 || total != 0 {
			t.Fatalf("empty transfer %d/%d", done, total)
		}
		emptyUpdates++
	}
	if n, err := sh.Session.PutProgress(context.Background(), filepath.Join(sh.LocalDir, "empty"), "empty", emptyProgress); err != nil || n != 0 {
		t.Fatalf("empty put: %d %v", n, err)
	}
	if n, err := sh.Session.GetProgress(context.Background(), "empty", filepath.Join(sh.LocalDir, "empty-copy"), emptyProgress); err != nil || n != 0 {
		t.Fatalf("empty get: %d %v", n, err)
	}
	if emptyUpdates < 2 {
		t.Fatal("empty progress missing")
	}
}
