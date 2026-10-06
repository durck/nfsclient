package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

type pnfsNaturalConfig struct {
	host, export, advertised, target string
	port                             int
}

func pnfsNaturalFixture(t *testing.T) pnfsNaturalConfig {
	t.Helper()
	c := pnfsNaturalConfig{host: os.Getenv("NFS_VIEWER_PNFS_NATURAL_HOST"), export: os.Getenv("NFS_VIEWER_PNFS_NATURAL_EXPORT"), advertised: os.Getenv("NFS_VIEWER_PNFS_NATURAL_ADVERTISED"), target: os.Getenv("NFS_VIEWER_PNFS_NATURAL_TARGET")}
	if c.host == "" {
		t.Skip("disposable natural pNFS recall fixture not selected")
	}
	var err error
	c.port, err = strconv.Atoi(os.Getenv("NFS_VIEWER_PNFS_NATURAL_PORT"))
	if err != nil || c.port < 1 || c.port > 65535 || c.export == "" {
		t.Fatal("explicit natural recall port/export required")
	}
	for _, endpoint := range []string{c.advertised, c.target} {
		h, p, err := net.SplitHostPort(endpoint)
		port, pe := strconv.Atoi(p)
		if err != nil || pe != nil || h == "" || port < 1 || port > 65535 {
			t.Fatal("invalid natural recall DS endpoint", endpoint)
		}
	}
	return c
}

func (c pnfsNaturalConfig) connect(t *testing.T, ctx context.Context, version, role string, o *pnfsNaturalObserver) *session.Session {
	t.Helper()
	endpoint := newPNFSNaturalRelay(t, net.JoinHostPort(c.host, strconv.Itoa(c.port)), role, o)
	h, p, _ := net.SplitHostPort(endpoint)
	port, _ := strconv.Atoi(p)
	client, err := nfs.Connect(ctx, nfs.Config{Host: h, NFSPort: port, Version: version, PNFS: true, Timeout: 5 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}})
	if err != nil {
		t.Fatal(err)
	}
	s := session.New(client, h, false, false, nil)
	t.Cleanup(func() { client.Close() })
	if err := s.Use(ctx, c.export); err != nil {
		t.Fatal(err)
	}
	return s
}

type pnfsNaturalResult struct {
	n   int64
	err error
}
type pnfsNaturalTransfer struct {
	ready    chan struct{}
	release  chan struct{}
	result   chan pnfsNaturalResult
	once     sync.Once
	gateNS   int64
	gateDone uint64
}

func (g *pnfsNaturalTransfer) unblock() { g.once.Do(func() { close(g.release) }) }

func startPNFSNatural(ctx context.Context, s *session.Session, name, path string, options nfs.PNFSOptions, wg *sync.WaitGroup) *pnfsNaturalTransfer {
	g := &pnfsNaturalTransfer{ready: make(chan struct{}), release: make(chan struct{}), result: make(chan pnfsNaturalResult, 1)}
	wg.Add(1)
	go func() {
		defer wg.Done()
		paused := false
		n, err := s.GetPNFS(ctx, name, path, options, func(done, total uint64) {
			if done == 0 || paused {
				return
			}
			paused = true
			_, g.gateNS = pnfsMultiTimestamp()
			g.gateDone = done
			close(g.ready)
			select {
			case <-g.release:
			case <-ctx.Done():
			}
		})
		g.result <- pnfsNaturalResult{n, err}
	}()
	return g
}

func naturalRecallAcknowledged(snapshot pnfsNaturalSnapshot, fh []byte) *pnfsNaturalEvent {
	for _, e := range snapshot.Events {
		if e.Role == "A" && e.Kind == "recall" && bytes.Equal(e.FH, fh) && e.ReplyNS > 0 && e.Status == 0 {
			return &e
		}
	}
	return nil
}

func naturalRecallStateAdvanced(before, after []byte) bool {
	if len(before) != 16 || len(after) != 16 || !bytes.Equal(before[4:], after[4:]) {
		return false
	}
	// FreeBSD 14.4 nfsrv_recalloldlayout increments seqid and skips zero.
	want := binary.BigEndian.Uint32(before) + 1
	if want == 0 {
		want = 1
	}
	return binary.BigEndian.Uint32(after) == want
}

// A uses DS relay id 0; all bounded B attempts use a separate relay with id 1.
// Parallelism one and the first-progress gate require exactly one complete A
// READ. This also rejects any additional A I/O after callback acknowledgement.
func validatePNFSNaturalDS(s pnfsMultiSnapshot, gateNS, ackNS, releasedNS int64, prefix uint64, transferred int64) error {
	if len(s.Errors) != 0 {
		return fmt.Errorf("DS observer errors: %v", s.Errors)
	}
	if prefix == 0 || transferred < 0 || uint64(transferred) != prefix || s.Connections[0] != 1 {
		return fmt.Errorf("A transferred prefix or connection differs: prefix=%d transferred=%d connections=%v", prefix, transferred, s.Connections)
	}
	count := 0
	for _, r := range s.Reads {
		if r.ServerID != 0 {
			continue
		}
		count++
		if r.Offset != 0 || r.Count == 0 || r.ReturnedBytes != r.Count || uint64(r.ReturnedBytes) != prefix || r.WireStatus != 0 || r.RequestedNS <= 0 || r.ForwardedNS < r.RequestedNS || r.RepliedNS < r.ForwardedNS || r.RepliedNS > gateNS || (ackNS > 0 && r.RequestedNS >= ackNS) || (releasedNS > 0 && r.RequestedNS >= releasedNS) {
			return fmt.Errorf("A READ does not precede its gate and recall: %+v", r)
		}
	}
	if count != 1 {
		return fmt.Errorf("expected exactly one gated A DS READ, observed %d", count)
	}
	return nil
}

func TestPNFSNaturalDSProof(t *testing.T) {
	read := pnfsMultiReadEvent{ServerID: 0, Offset: 0, Count: 32768, ReturnedBytes: 32768, RequestedNS: 10, ForwardedNS: 20, RepliedNS: 30}
	valid := func() pnfsMultiSnapshot {
		return pnfsMultiSnapshot{Connections: map[int]int{0: 1, 1: 1}, Reads: []pnfsMultiReadEvent{read}}
	}
	check := func(s pnfsMultiSnapshot, n int64) error { return validatePNFSNaturalDS(s, 40, 50, 60, 32768, n) }
	if err := check(valid(), 32768); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"A READ after ACK", "unattributed A READ", "failed READ", "partial READ", "observer error", "extra transferred bytes", "reply after gate"} {
		t.Run(scenario, func(t *testing.T) {
			s := valid()
			n := int64(32768)
			switch scenario {
			case "A READ after ACK":
				extra := read
				extra.RequestedNS, extra.ForwardedNS, extra.RepliedNS = 51, 52, 53
				s.Reads = append(s.Reads, extra)
			case "unattributed A READ":
				s.Reads[0].ServerID = 1
			case "failed READ":
				s.Reads[0].WireStatus = 10025
			case "partial READ":
				s.Reads[0].ReturnedBytes--
			case "observer error":
				s.Errors = []string{"malformed reply"}
			case "extra transferred bytes":
				n++
			case "reply after gate":
				s.Reads[0].RepliedNS = 41
			}
			if err := check(s, n); err == nil {
				t.Fatal("accepted invalid DS recall evidence")
			}
		})
	}
}

func TestPNFSNaturalRecallState(t *testing.T) {
	for _, seq := range []uint32{1, 42, ^uint32(0)} {
		before := make([]byte, 16)
		binary.BigEndian.PutUint32(before, seq)
		after := append([]byte(nil), before...)
		next := seq + 1
		if next == 0 {
			next = 1
		}
		binary.BigEndian.PutUint32(after, next)
		if !naturalRecallStateAdvanced(before, after) {
			t.Fatal("valid state transition rejected", seq)
		}
		if naturalRecallStateAdvanced(before, before) {
			t.Fatal("unchanged state sequence accepted", seq)
		}
		after[15]++
		if naturalRecallStateAdvanced(before, after) {
			t.Fatal("changed state identity accepted", seq)
		}
	}
	if naturalRecallStateAdvanced(nil, make([]byte, 16)) {
		t.Fatal("missing initial state accepted")
	}
}

// FreeBSD's stock layout-cache pressure policy chooses an existing layout to
// recall. The fixture sets its boot-time high-water mark to one; this test only
// creates two layouts and sends ordinary GETATTR requests to drive that policy.
func TestFreeBSDPNFSNaturalRecall(t *testing.T) {
	c := pnfsNaturalFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		for _, held := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/held=%t", version, held), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				o := &pnfsNaturalObserver{}
				name := fmt.Sprintf("pnfs-natural-%s-%s-%t-%d", runtime.GOOS, version, held, time.Now().UnixNano())
				nameA, nameB := name+"-a", name+"-b"
				dir := t.TempDir()
				source := filepath.Join(dir, "source")
				payload := pnfsPayload()
				if err := os.WriteFile(source, payload, 0600); err != nil {
					t.Fatal(err)
				}
				sA, sC := c.connect(t, ctx, version, "A", o), c.connect(t, ctx, version, "C", o)
				for _, remote := range []string{nameA, nameB} {
					if _, err := sC.Put(ctx, source, remote); err != nil {
						t.Fatal(err)
					}
				}
				nodeA, _, err := sA.Resolve(ctx, nameA, true)
				if err != nil {
					t.Fatal(err)
				}
				var lock uint64
				if held {
					lock, err = sA.Lock(ctx, nameA, false)
					if err != nil {
						t.Fatal(err)
					}
				}
				dsObserver := &pnfsMultiObserver{}
				dsEndpointA, _ := newPNFSMultiRelay(t, c.target, 0, dsObserver)
				dsEndpointB, _ := newPNFSMultiRelay(t, c.target, 1, dsObserver)
				optionsA := nfs.PNFSOptions{DataServers: map[string]string{c.advertised: dsEndpointA}, Parallelism: 1}
				optionsB := nfs.PNFSOptions{DataServers: map[string]string{c.advertised: dsEndpointB}, Parallelism: 1}
				var wg sync.WaitGroup
				var transfers []*pnfsNaturalTransfer
				// Cancel, unblock, and join all transfer workers before test cleanup
				// closes sessions or listeners, including every failure path.
				attempts, probes := 0, 0
				var gateANS, releasedNS, finishedNS int64
				var gatedPrefix uint64
				var result pnfsNaturalResult
				defer func() {
					cancel()
					for _, g := range transfers {
						g.unblock()
					}
					wg.Wait()
					snapshot, _ := o.snapshot()
					evidence := struct {
						Platform, Version, RemoteA, RemoteB        string
						Held                                       bool
						Attempts, Probes                           int
						GateANS, ReleasedNS, FinishedNS, StoppedAt int64
						GatedPrefix                                uint64
						TransferError, PayloadSHA256               string
						Snapshot                                   pnfsNaturalSnapshot
						DS                                         pnfsMultiSnapshot
					}{runtime.GOOS, version, nameA, nameB, held, attempts, probes, gateANS, releasedNS, finishedNS, result.n, gatedPrefix, fmt.Sprint(result.err), fmt.Sprintf("%x", sha256.Sum256(payload)), snapshot, dsObserver.snapshot()}
					if out := os.Getenv("NFS_VIEWER_PNFS_NATURAL_EVIDENCE_DIR"); out != "" {
						b, err := json.MarshalIndent(evidence, "", "  ")
						if err == nil {
							err = os.WriteFile(filepath.Join(out, name+".json"), b, 0600)
						}
						if err != nil {
							t.Error("write natural recall evidence", err)
						}
					}
				}()
				destA := filepath.Join(dir, "target-a")
				gA := startPNFSNatural(ctx, sA, nameA, destA, optionsA, &wg)
				transfers = append(transfers, gA)
				select {
				case <-gA.ready:
				case r := <-gA.result:
					t.Fatalf("A stopped before first READ: %d %v", r.n, r.err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				gateANS = gA.gateNS
				gatedPrefix = gA.gateDone
				if err := validatePNFSNaturalDS(dsObserver.snapshot(), gateANS, 0, 0, gatedPrefix, int64(gatedPrefix)); err != nil {
					t.Fatal(err)
				}
				var recall *pnfsNaturalEvent
				var gB *pnfsNaturalTransfer
				for attempts < 8 && recall == nil {
					attempts++
					sB := c.connect(t, ctx, version, fmt.Sprintf("B-%d", attempts), o)
					gB = startPNFSNatural(ctx, sB, nameB, filepath.Join(dir, fmt.Sprintf("target-b-%d", attempts)), optionsB, &wg)
					transfers = append(transfers, gB)
					startup := true
					for startup && recall == nil {
						snap, changed := o.snapshot()
						if len(snap.Errors) > 0 {
							t.Fatal(snap.Errors)
						}
						recall = naturalRecallAcknowledged(snap, nodeA.Handle)
						if recall != nil {
							break
						}
						select {
						case <-gB.ready:
							startup = false
						case r := <-gB.result:
							if r.n != 0 || r.err == nil || r.err.Error() != "pNFS layout recalled; transfer stopped" {
								t.Fatalf("B startup failed: n=%d err=%v", r.n, r.err)
							}
							// Preserve this failed attempt and its wire observations.
							t.Logf("PNFS_NATURAL_B_RETRY attempt=%d n=%d err=%v", attempts, r.n, r.err)
							sB.Client.Close()
							gB = nil
							startup = false
						case <-changed:
						case <-ctx.Done():
							t.Fatal("B startup", ctx.Err())
						}
					}
					if gB != nil {
						break
					}
				}
				if gB == nil && recall == nil {
					t.Fatal("eight B layouts recalled before the first READ; A was never recalled")
				}
				for recall == nil && probes < 4096 {
					snap, _ := o.snapshot()
					if len(snap.Errors) > 0 {
						t.Fatal(snap.Errors)
					}
					recall = naturalRecallAcknowledged(snap, nodeA.Handle)
					if recall != nil {
						break
					}
					if _, err := sC.Client.GetAttr(ctx, nodeA.Handle); err != nil {
						t.Fatal("ordinary pressure-driving GETATTR", err)
					}
					probes++
				}
				if recall == nil {
					snap, _ := o.snapshot()
					recall = naturalRecallAcknowledged(snap, nodeA.Handle)
				}
				if recall == nil {
					t.Fatal("no natural A FILE recall after bounded GETATTR requests")
				}
				snap, _ := o.snapshot()
				var layoutA, layoutB *pnfsNaturalEvent
				for _, e := range snap.Events {
					if e.Kind == "layoutget" && e.ReplyNS > 0 && e.Status == 0 && e.ReceivedNS < recall.ReceivedNS {
						if e.Role == "A" {
							layoutA = &e
						}
						if strings.HasPrefix(e.Role, "B-") {
							active := true
							for _, returned := range snap.Events {
								if returned.Role == e.Role && returned.Kind == "layoutreturn" && returned.ReceivedNS < recall.ReceivedNS {
									active = false
								}
							}
							if active {
								layoutB = &e
							}
						}
					}
				}
				if layoutA == nil || layoutB == nil || recall.LayoutType != 1 || recall.RecallKind != 1 || !bytes.Equal(recall.Session, layoutA.Session) || !naturalRecallStateAdvanced(layoutA.State, recall.State) || recall.ReceivedNS < gA.gateNS {
					t.Fatalf("recall does not match held A and two successful FILE layouts: A=%+v B=%+v recall=%+v", layoutA, layoutB, recall)
				}
				_, releasedNS = pnfsMultiTimestamp()
				gA.unblock()
				select {
				case result = <-gA.result:
				case <-ctx.Done():
					t.Fatal("A recall completion", ctx.Err())
				}
				_, finishedNS = pnfsMultiTimestamp()
				if result.err == nil || result.err.Error() != "pNFS layout recalled; transfer stopped" || result.n <= 0 || result.n >= int64(len(payload)) {
					t.Fatalf("A did not stop partially for recall: %d %v", result.n, result.err)
				}
				if _, err := os.Lstat(destA); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recalled A published", err)
				}
				// B intentionally still has a temporary file. Inspect A's directory
				// after joining B below to assert that neither transfer leaks one.
				// The client can finish processing a forwarded reply before the
				// relay publishes its observation. Wait for that publication.
				for {
					observed, changed := o.snapshot()
					if len(observed.Errors) != 0 {
						t.Fatal(observed.Errors)
					}
					returned := false
					for _, e := range observed.Events {
						if e.Role == "A" && e.Kind == "read" {
							t.Fatal("unexpected MDS READ fallback before reuse")
						}
						if e.Role == "A" && e.Kind == "layoutreturn" && e.ReplyNS > releasedNS && bytes.Equal(e.FH, nodeA.Handle) && bytes.Equal(e.State, recall.State) {
							if e.Status != 0 {
								t.Fatal("LAYOUTRETURN rejected", e.Status)
							}
							returned = true
						}
					}
					if returned {
						break
					}
					select {
					case <-changed:
					case <-ctx.Done():
						t.Fatal("matching completed LAYOUTRETURN missing", ctx.Err())
					}
				}
				if held {
					locks := sA.Client.Locks()
					if len(locks) != 1 || locks[0].Uncertain {
						t.Fatal("recall damaged retained lock", locks)
					}
					if _, err := sC.Lock(ctx, nameA, true); !errors.Is(err, nfs.Status(10010)) {
						t.Fatal("retained lock lost server contention", err)
					}
				}
				mds := filepath.Join(dir, "mds-reuse")
				if _, err := sA.Get(ctx, nameA, mds); err != nil {
					t.Fatal("same-session MDS reuse", err)
				}
				if b, err := os.ReadFile(mds); err != nil || !bytes.Equal(b, payload) {
					t.Fatal("MDS reuse content", err)
				}
				if held {
					if err := sA.Client.Unlock(ctx, lock); err != nil {
						t.Fatal("unlock after recall", err)
					}
				}
				cancel()
				for _, g := range transfers {
					g.unblock()
				}
				wg.Wait()
				if err := validatePNFSNaturalDS(dsObserver.snapshot(), gateANS, recall.ReplyNS, releasedNS, gatedPrefix, result.n); err != nil {
					t.Fatal(err)
				}
				for attempt := 1; attempt <= attempts; attempt++ {
					if _, err := os.Lstat(filepath.Join(dir, fmt.Sprintf("target-b-%d", attempt))); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("pressure transfer unexpectedly published", attempt, err)
					}
				}
				if files, err := filepath.Glob(filepath.Join(dir, ".nfs-download-*")); err != nil || len(files) > 0 {
					t.Fatal("download temporary leak", files, err)
				}
				snap, _ = o.snapshot()
				if len(snap.Errors) > 0 {
					t.Fatal(snap.Errors)
				}
				t.Logf("PNFS_NATURAL platform=%s version=%s held=%t remote_a=%s remote_b=%s attempts=%d probes=%d stopped_at=%d callback_ack FILE_type_1 layoutreturn no_publication no_temp MDS_reuse retained_lock verified", runtime.GOOS, version, held, nameA, nameB, attempts, probes, result.n)
			})
		}
	}
}
