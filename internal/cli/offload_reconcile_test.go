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
	"strconv"
	"sync"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
)

// Each connection has independent session, client and state IDs. The restarted
// client must verify bytes through newly acquired state, never old offload IDs.
type reconcileWirePeer struct {
	base                   blockCLIPeer
	tag                    byte
	mode                   string
	source, destination    []byte
	next                   uint32
	opens                  map[string]string
	lock, saved            string
	issued, reads, unlocks int
	boundary               chan struct{}
	release                chan struct{}
}

func (p *reconcileWirePeer) sid(index byte) []byte {
	b := make([]byte, 16)
	b[3] = 1
	b[4] = p.tag
	b[5] = index
	return b
}
func reconcileQuad(d *missingV4Decoder) uint64 { return uint64(d.word())<<32 | uint64(d.word()) }

func (p *reconcileWirePeer) operation(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
	var e []byte
	fail := func(s string) ([]byte, uint32, error, bool) { return nil, 0, errors.New(s), true }
	switch code {
	case 42:
		d.take(8)
		d.opaque()
		d.word()
		d.word()
		d.word()
		e = blockCLIQuad(e, 100+uint64(p.tag))
		e = missingV4Words(e, 1, 0x10000, 0)
		e = blockCLIQuad(e, 1)
		e = missingV4Opaque(e, []byte("receipt-server"))
		e = missingV4Opaque(e, []byte("receipt-scope"))
		e = missingV4Words(e, 0)
	case 43:
		if reconcileQuad(d) != 100+uint64(p.tag) {
			return fail("wrong client ID")
		}
		seq := d.word()
		d.word()
		fore, back := d.take(28), d.take(28)
		d.word()
		callbacks := d.word()
		want := uint32(0)
		if p.tag == 1 {
			want = 1
		}
		if callbacks != want {
			return fail("wrong callback profile")
		}
		if callbacks == 1 && d.word() != 0 {
			return fail("wrong callback credentials")
		}
		e = append(e, bytes.Repeat([]byte{p.tag}, 16)...)
		e = missingV4Words(e, seq, 2*callbacks)
		e = append(e, fore...)
		e = append(e, back...)
	case 53:
		sid := d.take(16)
		seq := d.word()
		slot, highest, cache := d.word(), d.word(), d.word()
		if !bytes.Equal(sid, bytes.Repeat([]byte{p.tag}, 16)) || seq != p.next || slot != 0 || highest != 0 || cache > 1 {
			return fail(fmt.Sprintf("wrong fresh SEQUENCE %d want %d", seq, p.next))
		}
		p.next++
		e = append(e, sid...)
		e = missingV4Words(e, seq, 0, 0, 0, 0)
	case 24:
		*current = "root"
	case 22:
		*current = string(d.opaque())
	case 10:
		e = missingV4Opaque(e, []byte(*current))
	case 15:
		name := string(d.opaque())
		if *current != "root" || (name != "source" && name != "destination") {
			return fail("unexpected reconciliation path")
		}
		*current = name
		if p.tag != 1 && p.mode == "path" && name == "destination" {
			*current = "different"
		}
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
				if p.tag != 1 && p.mode == "changed" && p.reads > 0 {
					change++
				}
				values = blockCLIQuad(values, change)
			case 4:
				size := len(p.source)
				if *current == "destination" {
					size = len(p.destination)
				}
				values = blockCLIQuad(values, uint64(size))
			case 8:
				values = blockCLIQuad(blockCLIQuad(values, 1), 0)
			case 10:
				values = missingV4Words(values, 60)
			case 20:
				id := uint64(3)
				if *current == "root" {
					id = 1
				} else if *current == "source" {
					id = 2
				}
				if p.tag != 1 && p.mode == "file-id" && *current == "destination" {
					id = 4
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
			default:
				return fail(fmt.Sprintf("unexpected receipt attribute %d", bit))
			}
		}
		e = missingV4Opaque(blockCLIBitmap(e, bits), values)
	case 18:
		seq, share, deny := d.word(), d.word(), d.word()
		client := reconcileQuad(d)
		d.opaque()
		if seq != 0 || deny != 0 || client != 100+uint64(p.tag) || d.word() != 0 || d.word() != 0 {
			return fail("wrong fresh OPEN")
		}
		name := string(d.opaque())
		if name != "source" && name != "destination" {
			return fail("wrong OPEN filename")
		}
		if p.tag != 1 && (name != "destination" || share != 1) {
			return fail("recovery requested write OPEN")
		}
		if p.opens == nil {
			p.opens = map[string]string{}
		}
		sid := p.sid(byte(len(p.opens) + 1))
		p.opens[string(sid)] = name
		*current = name
		e = append(e, sid...)
		e = missingV4Words(e, 1, 0, 1, 0, 1, 0, 0, 0)
	case 4:
		seq := d.word()
		sid := d.take(16)
		name, ok := p.opens[string(sid)]
		if !ok || name != *current || (p.tag != 1 && seq != 2) {
			return fail("old or foreign CLOSE state")
		}
		if p.tag == 1 && p.issued > 0 {
			p.boundary <- struct{}{}
			<-p.release
			return nil, 0, io.EOF, true
		}
		e = append(e, sid...)
	case 25:
		sid := d.take(16)
		offset := reconcileQuad(d)
		size := d.word()
		data := p.source
		if p.tag == 1 {
			if p.opens[string(sid)] != "source" || *current != "source" {
				return fail("wrong source hashing state")
			}
		} else {
			if string(sid) != p.lock || *current != "destination" {
				return fail("recovery reused old state or unprotected READ")
			}
			data = p.destination
			p.reads++
			if p.mode == "retry-read" && p.tag == 2 {
				p.boundary <- struct{}{}
				<-p.release
				return nil, 0, io.EOF, true
			}
		}
		if offset > uint64(len(data)) {
			return fail("READ beyond file")
		}
		end := min(int(offset)+int(size), len(data))
		eof := uint32(0)
		if end == len(data) {
			eof = 1
		}
		e = missingV4Opaque(missingV4Words(e, eof), data[int(offset):end])
	case 32:
		p.saved = *current
	case 60, 71:
		if p.tag != 1 {
			return fail("recovery replayed a data operation")
		}
		src, dst := d.take(16), d.take(16)
		if p.opens[string(src)] != "source" || p.opens[string(dst)] != "destination" || p.saved != "source" || *current != "destination" || reconcileQuad(d) != 0 || reconcileQuad(d) != 0 || reconcileQuad(d) != uint64(len(p.source)) {
			return fail("COPY/CLONE intent changed")
		}
		//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
		if code == 60 && (d.word() != 1 || d.word() != 1 || d.word() != 0) {
			return fail("COPY must be synchronous intra-server")
		}
		p.issued++
		p.destination = bytes.Clone(p.source)
		if p.mode == "no-receipt" {
			p.boundary <- struct{}{}
			<-p.release
			return nil, 0, io.EOF, true
		}
		if code == 60 {
			e = missingV4Words(e, 0)
			e = blockCLIQuad(e, uint64(len(p.source)))
			e = missingV4Words(e, 2)
			e = append(e, []byte("receipt!")...)
			e = missingV4Words(e, 1, 1)
		}
	case 12:
		kind, reclaim := d.word(), d.word()
		offset, length := reconcileQuad(d), reconcileQuad(d)
		newOwner, seq := d.word(), d.word()
		sid := d.take(16)
		lockseq := d.word()
		client := reconcileQuad(d)
		d.opaque()
		if p.tag == 1 || kind != 1 || reclaim != 0 || offset != 0 || length != ^uint64(0) || newOwner != 1 || seq != 1 || p.opens[string(sid)] != "destination" || lockseq != 0 || client != 100+uint64(p.tag) {
			return fail("wrong fresh read LOCK")
		}
		if p.mode == "lock-denied" {
			return nil, 13, nil, true
		}
		p.lock = string(p.sid(100))
		e = []byte(p.lock)
	case 14:
		kind, seq := d.word(), d.word()
		sid := d.take(16)
		offset, length := reconcileQuad(d), reconcileQuad(d)
		if kind != 1 || seq != 1 || string(sid) != p.lock || offset != 0 || length != ^uint64(0) {
			return fail("recovery LOCKU replay or old state")
		}
		p.unlocks++
		if p.mode == "unlock-failed" {
			return nil, 5, nil, true
		}
		e = bytes.Clone(sid)
		e[3] = 2
	case 45:
		d.take(16)
	case 5:
		if reconcileQuad(d) != 0 || d.word() != 0 {
			return fail("wrong verification COMMIT")
		}
		if p.mode == "commit-failed" {
			return nil, 5, nil, true
		}
		e = []byte("receipt!")
	default:
		return nil, 0, nil, false
	}
	return e, 0, nil, true
}

func TestOffloadProcessReconciliation(t *testing.T) {
	for _, operation := range []string{"copyrange", "clonerange"} {
		for _, mode := range []string{"valid", "bytes", "size", "file-id", "path", "changed", "lock-denied", "commit-failed", "unlock-failed", "wrong-id", "profile", "no-receipt", "corrupt", "retry-read", "retry-bytes"} {
			t.Run(operation+"/"+mode, func(t *testing.T) { runOffloadReconciliation(t, operation, mode) })
		}
	}
}

func runOffloadReconciliation(t *testing.T, operation, mode string) {
	t.Helper()
	dir := t.TempDir()
	journal := filepath.Join(dir, "offload.journal")
	source := bytes.Repeat([]byte{0, 1, 255, 31, 72, 9, 99}, 10000)
	policy, serverTLS := referralTLSPolicy(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := &referralTLSListener{Listener: listener, config: serverTLS}
	original := &reconcileWirePeer{tag: 1, mode: mode, next: 1, source: source, destination: bytes.Repeat([]byte{42}, len(source)), boundary: make(chan struct{}, 1), release: make(chan struct{})}
	fresh := &reconcileWirePeer{tag: 2, mode: mode, next: 1, source: source, boundary: make(chan struct{}, 1), release: make(chan struct{})}
	original.base.minor = 2
	fresh.base.minor = 2
	original.base.operationHook = original.operation
	fresh.base.operationHook = fresh.operation
	originalDone, freshDone := make(chan error, 1), make(chan error, 1)
	startFresh := make(chan struct{})
	go func() {
		originalDone <- original.base.serve(tlsListener)
		<-startFresh
		freshDone <- fresh.base.serve(tlsListener)
	}()
	var releaseOnce, startOnce sync.Once
	t.Cleanup(func() {
		listener.Close()
		releaseOnce.Do(func() { close(original.release) })
		startOnce.Do(func() { close(startFresh) })
	})
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	common := []string{"127.0.0.1", "--nfs-version", "4.2", "--nfs-port", port, "--auto-uid=false", "--auto-escape=false", "--tls", "--tls-ca", policy.CAFile, "--tls-server-name", policy.ServerName, "--export", "/"}
	args := append(append([]string{}, common...), "--offload", "--offload-journal", journal, "--offload-reconcile", "--batch")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	binary := os.Getenv("NFS_VIEWER_TEST_BINARY")
	var child *exec.Cmd
	if binary != "" {
		child = exec.CommandContext(ctx, binary, args...)
	} else {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child = exec.CommandContext(ctx, executable, "-test.run=^TestLockRecoveryChild$", "-test.timeout=30s")
		encoded, _ := json.Marshal(args)
		child.Env = append(os.Environ(), "NFS_LOCK_RECOVERY_ARGS="+string(encoded))
	}
	var diagnostic bytes.Buffer
	child.Stderr = &diagnostic
	child.Stdout = io.Discard
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	fmt.Fprintf(stdin, "%s source destination 0 0 %d\n", operation, len(source))
	select {
	case <-original.boundary:
	case err := <-originalDone:
		child.Process.Kill()
		child.Wait()
		t.Fatal("missed durable receipt boundary", err, diagnostic.String())
	case <-ctx.Done():
		child.Process.Kill()
		child.Wait()
		t.Fatal("receipt child timeout", diagnostic.String())
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.Wait()
	releaseOnce.Do(func() { close(original.release) })
	if err = <-originalDone; !errors.Is(err, io.EOF) {
		t.Fatal("original peer", err)
	}
	record, err := nfs.InspectOffloadJournal(journal)
	sum := sha256.Sum256(source)
	if err != nil || !record.Pending || record.Phase != "issued" || record.Reconcile == nil || record.Reconcile.ExpectedSHA256 != hex.EncodeToString(sum[:]) || record.Reconcile.Receipt != (mode != "no-receipt") || original.issued != 1 {
		t.Fatal("persisted crash record", record, err)
	}
	fresh.destination = bytes.Clone(original.destination)
	if mode == "bytes" || mode == "retry-bytes" {
		fresh.destination[len(fresh.destination)/2] ^= 1
	}
	if mode == "size" {
		fresh.destination = fresh.destination[:len(fresh.destination)-1]
	}
	if mode == "corrupt" {
		f, err := os.OpenFile(journal, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte{1})
		f.Close()
	}
	id := record.ID
	if mode == "wrong-id" {
		id = "00000000000000000000000000000000"
	}
	recoveryArgs := append(append([]string{}, common...), "--command", "offload-reconcile "+strconv.Quote(journal)+" "+id+" destination")
	if mode == "profile" {
		recoveryArgs = append(recoveryArgs, "--uid", "99")
	}
	startOnce.Do(func() { close(startFresh) })
	var output string
	var runErr error
	if mode == "retry-read" {
		var unblock sync.Once
		t.Cleanup(func() { unblock.Do(func() { close(fresh.release) }) })
		second, in, diagnostics := startReconcileChild(t, ctx, append(append([]string{}, common...), "--batch"))
		fmt.Fprintf(in, "offload-reconcile %s %s destination\n", strconv.Quote(journal), id)
		select {
		case <-fresh.boundary:
		case <-ctx.Done():
			second.Process.Kill()
			second.Wait()
			t.Fatal("verification child missed READ boundary", diagnostics.String())
		}
		second.Process.Kill()
		second.Wait()
		unblock.Do(func() { close(fresh.release) })
		runErr = io.EOF
	} else {
		output, runErr = runKerberosCLI(t, recoveryArgs)
	}
	if mode == "valid" && runErr != nil || mode != "valid" && runErr == nil {
		t.Fatal("reconciliation outcome", runErr, output)
	}
	select {
	case err = <-freshDone:
		if err != nil && !(mode == "retry-read" && errors.Is(err, io.EOF)) {
			t.Fatal("fresh peer", err, output)
		}
	case <-ctx.Done():
		t.Fatal("fresh peer timeout", output)
	}
	after, inspectErr := nfs.InspectOffloadJournal(journal)
	if mode == "corrupt" {
		if inspectErr == nil {
			t.Fatal("accepted torn record")
		}
	} else if inspectErr != nil || after.Pending != (mode != "valid") || mode == "valid" && after.Outcome != "reconciled-verified" {
		t.Fatal("journal retirement", after, inspectErr)
	}
	if fresh.issued != 0 || mode == "valid" && (fresh.reads < 3 || fresh.unlocks != 1) {
		t.Fatal("replay or incomplete verification", fresh.issued, fresh.reads, fresh.unlocks)
	}
	if mode == "retry-read" || mode == "retry-bytes" {
		// A failed/killed verifier leaves the receipt intact. A later fresh
		// process may verify again; it still never replays the original operation.
		third := &reconcileWirePeer{tag: 3, mode: "valid", next: 1, source: source, destination: bytes.Clone(original.destination)}
		third.base.minor = 2
		third.base.operationHook = third.operation
		thirdDone := make(chan error, 1)
		go func() { thirdDone <- third.base.serve(tlsListener) }()
		if out, err := runKerberosCLI(t, recoveryArgs); err != nil {
			t.Fatal("fresh verification retry", err, out)
		}
		if err := <-thirdDone; err != nil {
			t.Fatal("third peer", err)
		}
		r, err := nfs.InspectOffloadJournal(journal)
		if err != nil || r.Pending || r.Outcome != "reconciled-verified" || third.issued != 0 || third.reads < 3 || third.unlocks != 1 {
			t.Fatal("verification retry did not retire safely", r, err)
		}
	}
	t.Logf("OFFLOAD_RECONCILE operation=%s mode=%s release=%t copies=1 fresh_mutations=0", operation, mode, binary != "")
}

func startReconcileChild(t *testing.T, ctx context.Context, args []string) (*exec.Cmd, io.WriteCloser, *bytes.Buffer) {
	t.Helper()
	var child *exec.Cmd
	if binary := os.Getenv("NFS_VIEWER_TEST_BINARY"); binary != "" {
		child = exec.CommandContext(ctx, binary, args...)
	} else {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child = exec.CommandContext(ctx, executable, "-test.run=^TestLockRecoveryChild$", "-test.timeout=30s")
		encoded, _ := json.Marshal(args)
		child.Env = append(os.Environ(), "NFS_LOCK_RECOVERY_ARGS="+string(encoded))
	}
	diagnostics := &bytes.Buffer{}
	child.Stderr = diagnostics
	child.Stdout = io.Discard
	in, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	return child, in, diagnostics
}
