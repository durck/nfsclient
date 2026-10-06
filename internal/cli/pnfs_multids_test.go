package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// LizardFS uses 64 MiB file-layout stripes. Three chunks exercise real storage
// placement without changing the server's layout or device-info implementation.
const pnfsMultiSize = (128 << 20) + 17

type pnfsMultiConfig struct {
	host, export string
	port         int
	advertised   []string
	targets      []string
}

func pnfsMultiFixture(t *testing.T) pnfsMultiConfig {
	t.Helper()
	c := pnfsMultiConfig{host: os.Getenv("NFS_VIEWER_PNFS_MULTI_HOST"), export: os.Getenv("NFS_VIEWER_PNFS_MULTI_EXPORT")}
	if c.host == "" {
		t.Skip("disposable multi-DS fixture not selected")
	}
	var err error
	c.port, err = strconv.Atoi(os.Getenv("NFS_VIEWER_PNFS_MULTI_PORT"))
	if err != nil || c.port < 1 || c.port > 65535 || c.export == "" {
		t.Fatal("explicit multi-DS port and export required")
	}
	seen, targets := map[string]bool{}, map[string]bool{}
	for _, mapping := range strings.Split(os.Getenv("NFS_VIEWER_PNFS_MULTI_DS"), ",") {
		a, b, ok := strings.Cut(mapping, "=")
		if !ok || seen[a] || targets[b] {
			t.Fatal("two distinct explicit multi-DS mappings required")
		}
		for _, endpoint := range []string{a, b} {
			host, port, err := net.SplitHostPort(endpoint)
			p, parseErr := strconv.Atoi(port)
			if err != nil || parseErr != nil || host == "" || p < 1 || p > 65535 {
				t.Fatal("invalid multi-DS endpoint", endpoint)
			}
		}
		seen[a], targets[b] = true, true
		c.advertised, c.targets = append(c.advertised, a), append(c.targets, b)
	}
	if len(c.targets) != 2 {
		t.Fatal("this fixture requires exactly two physical data servers")
	}
	return c
}

func (c pnfsMultiConfig) connect(t *testing.T, ctx context.Context, version string) *session.Session {
	t.Helper()
	client, err := nfs.Connect(ctx, nfs.Config{Host: c.host, NFSPort: c.port, Version: version, PNFS: true, Timeout: 10 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}})
	if err != nil {
		t.Fatal(err)
	}
	s := session.New(client, c.host, false, false, nil)
	t.Cleanup(func() { s.Client.Close() })
	if err := s.Use(ctx, c.export); err != nil {
		t.Fatal(err)
	}
	return s
}

func (c pnfsMultiConfig) observeMDS(t *testing.T) (pnfsMultiConfig, *pnfsMultiObserver) {
	t.Helper()
	o := &pnfsMultiObserver{}
	endpoint, _ := newPNFSMultiRelay(t, net.JoinHostPort(c.host, strconv.Itoa(c.port)), -1, o)
	var port string
	c.host, port, _ = net.SplitHostPort(endpoint)
	c.port, _ = strconv.Atoi(port)
	return c, o
}

func pnfsMultiNoMDSRead(t *testing.T, name string, observer *pnfsMultiObserver) {
	t.Helper()
	s := observer.snapshot()
	if len(s.Reads) != 0 || len(s.Errors) != 0 {
		t.Fatalf("MDS READ fallback or observer error: reads=%d errors=%v", len(s.Reads), s.Errors)
	}
	pnfsMultiEvidence(t, name, "mds-no-read", 0, s)
}

func pnfsMultiSource(t *testing.T, path string) string {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	w := io.MultiWriter(f, h)
	buf := make([]byte, 1<<20)
	for offset := 0; offset < pnfsMultiSize; {
		n := min(len(buf), pnfsMultiSize-offset)
		for i := range buf[:n] {
			p := offset + i
			buf[i] = byte((uint64(p)*31 + uint64(p)/251) % 256)
		}
		if _, err := w.Write(buf[:n]); err != nil {
			f.Close()
			t.Fatal(err)
		}
		offset += n
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func pnfsMultiVerifyFile(t *testing.T, path, want string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil || n != pnfsMultiSize || hex.EncodeToString(h.Sum(nil)) != want {
		t.Fatalf("multi-DS content mismatch: size=%d err=%v sha256=%x want=%s", n, err, h.Sum(nil), want)
	}
}

func pnfsMultiClean(t *testing.T, path string, failed bool) {
	t.Helper()
	if failed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed download published destination", err)
		}
	}
	left, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".nfs-download-*"))
	if err != nil || len(left) != 0 {
		t.Fatal("download temporary leak", left, err)
	}
}

// Check every actual wire READ and find a boundary at which the server-selected
// destination changes. The concurrency check never assumes chunk placement.
func pnfsMultiReads(t *testing.T, s pnfsMultiSnapshot) uint64 {
	t.Helper()
	if len(s.Errors) != 0 {
		t.Fatal("RPC observer errors", s.Errors)
	}
	sort.Slice(s.Reads, func(i, j int) bool { return s.Reads[i].Offset < s.Reads[j].Offset })
	var offset, boundary uint64
	servers := map[int]bool{}
	for i, r := range s.Reads {
		if r.Offset != offset || r.Count == 0 || r.ReturnedBytes != r.Count || r.WireStatus != 0 || r.RepliedAt.IsZero() || r.ForwardedAt.Before(r.RequestedAt) {
			t.Fatalf("incomplete, repeated or invalid wire READ at %d: %+v", offset, r)
		}
		if i > 0 && r.ServerID != s.Reads[i-1].ServerID && boundary == 0 {
			boundary = r.Offset
		}
		servers[r.ServerID] = true
		offset += uint64(r.ReturnedBytes)
	}
	if offset != pnfsMultiSize || len(servers) != 2 || boundary == 0 {
		t.Fatalf("real multi-DS coverage missing: bytes=%d servers=%v boundary=%d", offset, servers, boundary)
	}
	return boundary
}

func pnfsMultiEvidence(t *testing.T, name, phase string, elapsed time.Duration, snapshot pnfsMultiSnapshot) {
	t.Helper()
	var received uint64
	for _, r := range snapshot.Reads {
		received += uint64(r.ReturnedBytes)
	}
	var rate float64
	if elapsed > 0 {
		rate = float64(received) / (1 << 20) / elapsed.Seconds()
	}
	t.Logf("PNFS_MULTI_READ remote=%s phase=%s wire_bytes=%d seconds=%.6f MiB_per_second=%.3f requests=%d", name, phase, received, elapsed.Seconds(), rate, len(snapshot.Reads))
	if dir := os.Getenv("NFS_VIEWER_PNFS_MULTI_EVIDENCE_DIR"); dir != "" {
		b, err := json.MarshalIndent(struct {
			Remote, Phase string
			ElapsedNS     int64
			Snapshot      pnfsMultiSnapshot
		}{name, phase, int64(elapsed), snapshot}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+"-"+phase+".json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLizardPNFSMultiDS(t *testing.T) {
	c := pnfsMultiFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			c, mdsObserver := c.observeMDS(t)
			s, other := c.connect(t, ctx, version), c.connect(t, ctx, version)
			name := fmt.Sprintf("pnfs-multi-api-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			t.Logf("PNFS_MULTI_FILE remote=%s", name)
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			want := pnfsMultiSource(t, source)
			if _, err := s.Put(ctx, source, name); err != nil {
				t.Fatal(err)
			}
			o := &pnfsMultiObserver{}
			options := nfs.PNFSOptions{DataServers: map[string]string{}, Parallelism: 1}
			var cuts []func()
			for i, target := range c.targets {
				endpoint, cut := newPNFSMultiRelay(t, target, i, o)
				options.DataServers[c.advertised[i]] = endpoint
				cuts = append(cuts, cut)
			}
			get := func(phase string) pnfsMultiSnapshot {
				t.Helper()
				path := filepath.Join(dir, phase)
				start := time.Now()
				n, err := s.GetPNFS(ctx, name, path, options, nil)
				elapsed := time.Since(start)
				snapshot := o.snapshot()
				pnfsMultiEvidence(t, name, phase, elapsed, snapshot)
				if err != nil || n != pnfsMultiSize {
					t.Fatal(phase, n, err)
				}
				pnfsMultiVerifyFile(t, path, want)
				pnfsMultiClean(t, path, false)
				pnfsMultiReads(t, snapshot)
				return snapshot
			}
			boundary := pnfsMultiReads(t, get("sequential"))
			o.reset()
			options.Parallelism = 8
			get("parallel") // Unimpeded timing, separate from the barrier proof.
			o.reset()
			o.armBoundary(boundary)
			id, err := s.Lock(ctx, name, false)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := get("parallel-barrier-held-lock")
			if !snapshot.BarrierMatched || snapshot.BarrierTimedOut {
				t.Fatal("distinct DS requests did not overlap at a real stripe boundary", snapshot.BarrierMatched, snapshot.BarrierTimedOut)
			}
			if len(s.Client.Locks()) != 1 || s.Client.Locks()[0].Uncertain {
				t.Fatal("DS cleanup damaged retained MDS lock")
			}
			if _, err := other.Lock(ctx, name, true); !errors.Is(err, nfs.Status(10010)) {
				t.Fatal("lock contention lost", err)
			}
			if err := s.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			o.reset()
			cutDone := false
			var beforeCut map[int]int
			path := filepath.Join(dir, "cut")
			cutStart := time.Now()
			n, err := s.GetPNFS(ctx, name, path, options, func(done, total uint64) {
				if !cutDone && done > min(boundary, uint64(64<<20)) {
					cutDone = true
					beforeCut = o.snapshot().Connections
					for _, cut := range cuts {
						cut()
					}
				}
			})
			if !cutDone || err == nil || n <= 0 || n >= pnfsMultiSize {
				t.Fatal("DS cut did not fail incomplete transfer", cutDone, n, err)
			}
			pnfsMultiClean(t, path, true)
			cutSnapshot := o.snapshot()
			for server, count := range cutSnapshot.Connections {
				if count != 1 || count != beforeCut[server] {
					t.Fatal("DS connection replay after cut", cutSnapshot.Connections)
				}
			}
			if len(cutSnapshot.Connections) == 0 {
				t.Fatal("cut did not reach a DS")
			}
			if len(cutSnapshot.Connections) != len(beforeCut) {
				t.Fatal("DS connection set changed after cut")
			}
			pnfsMultiEvidence(t, name, "cut", time.Since(cutStart), cutSnapshot)
			if err := s.Reconnect(ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.Use(ctx, c.export); err != nil {
				t.Fatal(err)
			}
			pnfsMultiNoMDSRead(t, name, mdsObserver)
			t.Logf("PNFS_MULTI_API platform=%s version=%s remote=%s bytes=%d sha256=%s two_DS sequential parallel barrier held_lock contention DS_cut no_replay no_MDS_read reconnect verified", runtime.GOOS, version, name, pnfsMultiSize, want)
		})
	}
}

func TestLizardPNFSMultiDSCLI(t *testing.T) {
	c := pnfsMultiFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			name := fmt.Sprintf("pnfs-multi-cli-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			t.Logf("PNFS_MULTI_FILE remote=%s", name)
			c, mdsObserver := c.observeMDS(t)
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			want := pnfsMultiSource(t, source)
			o := &pnfsMultiObserver{}
			var mappings []string
			for i, target := range c.targets {
				endpoint, _ := newPNFSMultiRelay(t, target, i, o)
				mappings = append(mappings, c.advertised[i]+"="+endpoint)
			}
			run := func(commands ...string) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				args := []string{c.host, "--nfs-version", version, "--nfs-port", strconv.Itoa(c.port), "--pnfs", "--export", c.export, "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--no-banner", "--progress", "never", "--color", "never"}
				for _, command := range commands {
					args = append(args, "-c", command)
				}
				var output string
				var err error
				if binary := os.Getenv("NFS_VIEWER_TEST_BINARY"); binary != "" {
					var b []byte
					b, err = exec.CommandContext(ctx, binary, args...).CombinedOutput()
					output = string(b)
				} else {
					var b bytes.Buffer
					cmd := NewCommand(strings.NewReader(""), &b, &b)
					cmd.SetArgs(args)
					err = cmd.ExecuteContext(ctx)
					output = b.String()
				}
				if err != nil {
					t.Fatal(err, output)
				}
			}
			run("put " + strconv.Quote(source) + " " + name)
			var boundary uint64
			for index, parallel := range []int{1, 8, 8} {
				o.reset()
				phase := fmt.Sprintf("cli-parallel-%d", parallel)
				if index == 2 {
					phase += "-barrier"
					o.armBoundary(boundary)
				}
				path := filepath.Join(dir, phase)
				start := time.Now()
				run("lock "+name+" read", "getpnfs "+name+" "+strconv.Quote(path)+" --parallel "+strconv.Itoa(parallel)+" "+strings.Join(mappings, " "), "unlock 1", "reconnect")
				elapsed := time.Since(start)
				pnfsMultiVerifyFile(t, path, want)
				pnfsMultiClean(t, path, false)
				snapshot := o.snapshot()
				pnfsMultiEvidence(t, name, phase, elapsed, snapshot)
				boundary = pnfsMultiReads(t, snapshot)
				if index == 2 && (!snapshot.BarrierMatched || snapshot.BarrierTimedOut) {
					t.Fatal("CLI --parallel 8 did not overlap distinct DS requests")
				}
			}
			pnfsMultiNoMDSRead(t, name, mdsObserver)
			t.Logf("PNFS_MULTI_CLI platform=%s version=%s remote=%s bytes=%d sha256=%s binary=%t two_DS held_lock no_MDS_read reconnect verified", runtime.GOOS, version, name, pnfsMultiSize, want, os.Getenv("NFS_VIEWER_TEST_BINARY") != "")
		})
	}
}
