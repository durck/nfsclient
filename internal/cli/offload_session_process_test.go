package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
)

// The normal CLI prepares/hashes/issues COPY. A killed process leaves an exact
// pending CLOSE; a second CLI invocation must BIND, not replace the session.
func TestOffloadSessionProcessRecovery(t *testing.T) {
	for _, secondCrash := range []bool{false, true} {
		t.Run(fmt.Sprintf("second-crash=%t", secondCrash), func(t *testing.T) { testOffloadSessionProcessRecovery(t, secondCrash) })
	}
}

func testOffloadSessionProcessRecovery(t *testing.T, secondCrash bool) {
	policy, serverTLS := referralTLSPolicy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsListener := &referralTLSListener{Listener: listener, config: serverTLS}
	p := &reconcileWirePeer{tag: 1, mode: "valid", next: 1, source: bytes.Repeat([]byte("source-range"), 1000), boundary: make(chan struct{}, 1), release: make(chan struct{})}
	p.destination = bytes.Repeat([]byte{42}, len(p.source))
	p.base.minor = 2
	p.base.operationHook = p.operation
	done := make(chan error, 1)
	go func() { done <- p.base.serve(tlsListener) }()
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(p.release) }) })
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	journal := filepath.Join(t.TempDir(), "offload.state")
	common := []string{"127.0.0.1", "--nfs-version", "4.2", "--nfs-port", port, "--auto-uid=false", "--auto-escape=false", "--tls", "--tls-ca", policy.CAFile, "--tls-server-name", policy.ServerName}
	args := append(append([]string{}, common...), "--export", "/", "--offload", "--offload-journal", journal, "--offload-session-recovery", "--batch")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child, in, diagnostics := startReconcileChild(t, ctx, args)
	fmt.Fprintf(in, "copyrange source destination 0 0 %d\n", len(p.source))
	select {
	case <-p.boundary:
	case err := <-done:
		child.Process.Kill()
		child.Wait()
		t.Fatal("no crash boundary", err, diagnostics.String())
	case <-ctx.Done():
		child.Process.Kill()
		child.Wait()
		t.Fatal("origin timeout", diagnostics.String())
	}
	child.Process.Kill()
	child.Wait()
	release.Do(func() { close(p.release) })
	if err := <-done; !errors.Is(err, io.EOF) {
		t.Fatal("origin peer", err)
	}
	record, err := nfs.InspectOffloadJournal(journal)
	if err != nil || record.Recovery == nil || record.Recovery.Request == nil || !record.Recovery.Committed || record.Expectation == nil || p.issued != 1 {
		t.Fatal("missing exact CLI crash evidence", err)
	}
	pending := record.Recovery.Request
	binds, closes, creates := 0, 0, 0
	cleanupBoundary, cleanupRelease := make(chan struct{}), make(chan struct{})
	var releaseCleanup sync.Once
	t.Cleanup(func() { releaseCleanup.Do(func() { close(cleanupRelease) }) })
	var sourceClose []byte
	p.base.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
		switch code {
		case 42:
			e, status, err, ok := p.operation(code, d, current)
			// EXCHANGE_ID response flags are after client ID and sequence.
			e[12] |= 0x80
			return e, status, err, ok
		case 43:
			creates++
			return nil, 0, errors.New("replacement session before original CLOSE recovery"), true
		case 41:
			if !bytes.Equal(d.take(16), bytes.Repeat([]byte{1}, 16)) || d.word() != 1 || d.word() != 0 {
				return nil, 0, errors.New("wrong original BIND"), true
			}
			binds++
			return missingV4Words(bytes.Repeat([]byte{1}, 16), 1, 0), 0, nil, true
		case 53:
			sid := d.take(16)
			seq := d.word()
			slot, highest, cache := d.word(), d.word(), d.word()
			if !bytes.Equal(sid, pending.Session) || seq != pending.Sequence+uint32(min(closes, 1)) || slot != 0 || highest != 0 || cache != 1 {
				return nil, 0, errors.New("changed pending CLOSE sequence"), true
			}
			return missingV4Words(bytes.Clone(sid), seq, 0, 0, 0, 0), 0, nil, true
		case 4:
			seq := d.word()
			sid := d.take(16)
			want := pending.Operations[len(pending.Operations)-1]
			args := missingV4Words(nil, seq)
			args = append(args, sid...)
			if want.Code != 4 || closes == 0 && !bytes.Equal(want.Args, args) || p.opens[string(sid)] != *current || closes > 0 && *current != "source" {
				return nil, 0, errors.New("changed replayed CLOSE"), true
			}
			closes++
			if secondCrash && closes == 2 {
				sourceClose = bytes.Clone(args)
				close(cleanupBoundary)
				<-cleanupRelease
				return nil, 0, io.EOF, true
			}
			if closes == 3 && !bytes.Equal(args, sourceClose) {
				return nil, 0, errors.New("second restart changed source CLOSE"), true
			}
			return bytes.Clone(sid), 0, nil, true
		}
		return p.operation(code, d, current)
	}
	go func() { done <- p.base.serve(tlsListener) }()
	recovery := append(append([]string{}, common...), "--recover-offload", journal, "--offload-operation", record.ID)
	if secondCrash {
		child, _, diagnostics := startReconcileChild(t, ctx, recovery)
		select {
		case <-cleanupBoundary:
		case err := <-done:
			t.Fatal("no cleanup crash boundary", err)
		case <-ctx.Done():
			child.Process.Kill()
			child.Wait()
			t.Fatal("cleanup timeout", diagnostics.String())
		}
		child.Process.Kill()
		child.Wait()
		releaseCleanup.Do(func() { close(cleanupRelease) })
		if err := <-done; !errors.Is(err, io.EOF) {
			t.Fatal("cleanup peer", err)
		}
		second, err := nfs.InspectOffloadJournal(journal)
		if err != nil || second.Recovery.Request == nil || !bytes.Equal(second.Recovery.Request.Operations[1].Args, sourceClose) || !second.Pending {
			t.Fatal("missing second-crash evidence", err)
		}
		go func() { done <- p.base.serve(tlsListener) }()
	}
	output, err := runKerberosCLI(t, recovery)
	if err != nil {
		t.Fatal("standalone CLI recovery", err, output)
	}
	if err := <-done; err != nil {
		t.Fatal("recovery peer", err)
	}
	var result nfs.OffloadRecord
	if err := json.Unmarshal([]byte(output), &result); err != nil || result.Pending || result.Recovery == nil || !result.Recovery.Committed || result.Recovery.StateCleanup != "confirmed" || result.Outcome != "completed" {
		t.Fatal("CLI JSON receipt", err, output)
	}
	wantBinds, wantCloses := 1, 2
	if secondCrash {
		wantBinds, wantCloses = 2, 3
	}
	if binds != wantBinds || closes != wantCloses || creates != 0 || p.issued != 1 {
		t.Fatal("unsafe restart", binds, closes, creates, p.issued)
	}
	t.Log("OFFLOAD_SESSION_CLI protected original bind and exact CLOSE recovery", "release="+strconv.FormatBool(os.Getenv("NFS_VIEWER_TEST_BINARY") != ""))
}
