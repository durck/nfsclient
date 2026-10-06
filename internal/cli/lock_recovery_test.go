package cli

import (
	"bufio"
	"bytes"
	"context"
	wirebinary "encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"nfs-viewer/internal/nfs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLockRecoveryChild(t *testing.T) {
	encoded := os.Getenv("NFS_LOCK_RECOVERY_ARGS")
	if encoded == "" {
		t.Skip("subprocess helper")
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		t.Fatal(err)
	}
	c := NewCommand(os.Stdin, os.Stdout, os.Stderr)
	c.SetArgs(args)
	if err := c.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLockProcessCrashRecovery(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"valid-read", "valid-write", "valid-multi", "valid-lease-renewal", "completed-read", "completed-write", "replayed-write", "replayed-open", "replayed-lock", "pending-read", "pending-write", "pending-unlock", "pending-recovery", "lost-open", "lost-lock", "scope", "unconfirmed", "client-id", "no-session", "path", "revoked-final", "sequence", "changed-profile", "corrupt"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runLockProcessCrash(t, minor, mode) })
		}
	}
}

func runLockProcessCrash(t *testing.T, minor uint32, mode string) {
	t.Helper()
	dir := t.TempDir()
	journal := filepath.Join(dir, "locks.journal")
	local := filepath.Join(dir, "output")
	patchFile := filepath.Join(dir, "patch")
	patch := []byte("fresh explicit write after checkpoint")
	if err := os.WriteFile(patchFile, patch, 0600); err != nil {
		t.Fatal(err)
	}
	policy, tlsServer := referralTLSPolicy(t)
	x := &migrationEvidence{}
	payload := bytes.Repeat([]byte("retained-state-data!"), 200)
	origin := &migrationWirePeer{origin: true, recovery: true, mode: "not-moved", evidence: x, metadata: referralWirePeer{data: bytes.Clone(payload)}}
	lifecycle := mode == "replayed-open" || mode == "replayed-lock"
	lostCode := uint32(12)
	if mode == "replayed-open" {
		lostCode = 18
	}
	targetMode := mode
	if mode == "completed-read" || mode == "completed-write" || mode == "replayed-write" || lifecycle {
		targetMode = "valid-read"
	}
	target := &migrationWirePeer{recovery: true, mode: targetMode, evidence: x, metadata: referralWirePeer{data: bytes.Clone(payload)}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &referralTLSListener{Listener: l, config: tlsServer}
	originalDone, recoveryDone := make(chan error, 1), make(chan error, 1)
	issued, release := make(chan struct{}, 1), make(chan struct{})
	recoveryRelease := make(chan struct{})
	renewed := make(chan struct{}, 8)
	var cachedWriteArgs, cachedWriteReply []byte
	var cachedPhaseArgs, cachedPhaseReply []byte
	var cachedPhaseConsumed int
	var cachedPhaseCurrent string
	replayed := false
	origin.base.minor = minor
	target.base.minor = minor
	origin.base.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
		if lifecycle && code == 18 {
			// The fixture's older OPEN parser accepts plain READ/BOTH; check the
			// durable wire explicitly before passing an independent parsed copy.
			if wirebinary.BigEndian.Uint32(d.b[4:])&0x400 == 0 {
				return nil, 0, errors.New("durable OPEN did not refuse delegation"), true
			}
		}
		if lifecycle && (code == 18 || code == lostCode) {
			original := bytes.Clone(d.b)
			copyDecoder := &missingV4Decoder{b: bytes.Clone(d.b)}
			if code == 18 {
				wirebinary.BigEndian.PutUint32(copyDecoder.b[4:], wirebinary.BigEndian.Uint32(copyDecoder.b[4:])&^0x400)
			}
			body, status, operr, handled := origin.operation(code, copyDecoder, current)
			consumed := len(original) - len(copyDecoder.b)
			d.take(uint32(consumed))
			if code == lostCode && operr == nil && status == 0 {
				cachedPhaseArgs, cachedPhaseReply, cachedPhaseConsumed, cachedPhaseCurrent = original, bytes.Clone(body), consumed, *current
				issued <- struct{}{}
				<-release
				return nil, 0, io.EOF, true
			}
			return body, status, operr, handled
		}

		if mode == "replayed-write" && code == 38 {
			cachedWriteArgs = bytes.Clone(d.b)
			var status uint32
			var err error
			cachedWriteReply, status, err, _ = origin.operation(code, d, current)
			if err != nil || status != 0 {
				return nil, status, err, true
			}
			issued <- struct{}{}
			<-release
			return nil, 0, io.EOF, true
		}
		if mode == "valid-lease-renewal" && code == 9 {
			peek := &missingV4Decoder{b: d.b}
			if fmt.Sprint(peek.bitmap()) == "[10]" {
				d.bitmap()
				return missingV4Opaque(blockCLIBitmap(nil, []uint32{10}), missingV4Words(nil, 1)), 0, nil, true
			}
		}
		if mode == "valid-lease-renewal" && code == 53 && len(d.b) == 32 && origin.locks.Load() > 0 {
			select {
			case renewed <- struct{}{}:
			default:
			}
		}
		if mode == "pending-read" && code == 25 || mode == "pending-write" && code == 38 || mode == "pending-unlock" && code == 14 {
			issued <- struct{}{}
			<-release
			return nil, 0, io.EOF, true
		}
		return origin.operation(code, d, current)
	}
	target.base.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
		if code == 53 && (mode == "pending-write" || mode == "pending-unlock" || (mode == "replayed-write" || lifecycle) && !replayed) {
			id := bytes.Clone(d.take(16))
			seq := d.word()
			slot, highest, cache := d.word(), d.word(), d.word()
			if mode == "pending-write" || mode == "pending-unlock" {
				return nil, 10068, nil, true
			}
			x.mu.Lock()
			want := x.next - 1
			x.mu.Unlock()
			if seq != want || slot != 0 || highest != 0 || cache != 1 {
				return nil, 0, errors.New("crash retry changed cached slot"), true
			}
			return missingV4Words(id, seq, 0, 0, 0, 0), 0, nil, true
		}
		if lifecycle && code == lostCode && !replayed {
			if !bytes.Equal(d.b, cachedPhaseArgs) {
				return nil, 0, errors.New("crash retry changed lifecycle request"), true
			}
			d.take(uint32(cachedPhaseConsumed))
			*current = cachedPhaseCurrent
			replayed = true
			return bytes.Clone(cachedPhaseReply), 0, nil, true
		}
		if lifecycle && code == 12 && mode == "replayed-open" {
			// Complete the already planned first LOCK, never a replacement OPEN.
			target.origin = true
			body, status, operr, handled := target.operation(code, d, current)
			target.origin = false
			return body, status, operr, handled
		}

		if mode == "replayed-write" && code == 38 && !replayed {
			if !bytes.Equal(d.b, cachedWriteArgs) {
				return nil, 0, errors.New("crash retry changed original WRITE bytes"), true
			}
			d.take(uint32(len(d.b)))
			replayed = true
			return bytes.Clone(cachedWriteReply), 0, nil, true
		}
		if mode == "pending-recovery" && code == 55 {
			issued <- struct{}{}
			<-recoveryRelease
			return nil, 0, io.EOF, true
		}
		if mode == "valid-lease-renewal" && code == 9 {
			peek := &missingV4Decoder{b: d.b}
			if fmt.Sprint(peek.bitmap()) == "[10]" {
				d.bitmap()
				return missingV4Opaque(blockCLIBitmap(nil, []uint32{10}), missingV4Words(nil, 1)), 0, nil, true
			}
		}
		return target.operation(code, d, current)
	}
	go func() {
		err := origin.base.serve(listener)
		if mode == "completed-write" || mode == "replayed-write" {
			// Publish actual server bytes before this goroutine serves recovery.
			// A parent-side copy after originalDone has no ordering with reads.
			copy(target.metadata.data, origin.metadata.data)
		}
		originalDone <- err
		err = target.base.serve(listener)
		if err == nil && (mode == "replayed-write" || lifecycle) {
			err = target.base.serve(listener)
		}
		recoveryDone <- err
	}()
	var once sync.Once
	var releaseOnce sync.Once
	stop := func() { once.Do(func() { l.Close(); releaseOnce.Do(func() { close(release) }) }) }
	t.Cleanup(stop)
	_, port, _ := net.SplitHostPort(l.Addr().String())
	common := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", port, "--auto-uid=false", "--auto-escape=false", "--tls", "--tls-ca", policy.CAFile, "--tls-server-name", policy.ServerName}
	childArgs := append(append([]string{}, common...), "--export", "/data", "--batch")
	binary := os.Getenv("NFS_VIEWER_TEST_BINARY")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var child *exec.Cmd
	if binary != "" {
		child = exec.CommandContext(ctx, binary, childArgs...)
	} else {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child = exec.CommandContext(ctx, executable, "-test.run=^TestLockRecoveryChild$", "-test.timeout=30s")
		encoded, _ := json.Marshal(childArgs)
		child.Env = append(os.Environ(), "NFS_LOCK_RECOVERY_ARGS="+string(encoded))
	}
	child.Stdout = io.Discard
	stderr, err := child.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	ready := make(chan string, 4)
	go func() {
		scanner := bufio.NewScanner(stderr)
		var diagnostics strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			diagnostics.WriteString(line + "\n")
			if strings.Contains(line, "Confirmed lock state saved") {
				ready <- ""
			}
		}
		ready <- diagnostics.String()
	}()
	kind, ranges := "read", ""
	if strings.Contains(mode, "write") {
		kind = "write"
	}
	if mode == "valid-multi" {
		ranges = " 0 100"
	}
	if !lifecycle {
		fmt.Fprintf(stdin, "lock file %s%s\n", kind, ranges)
	}
	count := int32(1)
	if mode == "valid-multi" {
		fmt.Fprintln(stdin, "lock file read 200 100")
		count++
	}
	fmt.Fprintf(stdin, "lock-save %s\n", strconv.Quote(journal))
	waitReady := func() {
		select {
		case diagnostic := <-ready:
			if diagnostic != "" {
				t.Fatal("checkpoint child", diagnostic)
			}
		case <-ctx.Done():
			t.Fatal("checkpoint timeout")
		}
	}
	waitReady()
	if lifecycle {
		fmt.Fprintf(stdin, "lock file %s\n", kind)
	}
	if mode == "valid-lease-renewal" {
		select {
		case <-renewed:
		case <-ctx.Done():
			t.Fatal("lease renewal was not sent")
		}
		fmt.Fprintf(stdin, "lock-save %s\n", strconv.Quote(journal))
		waitReady()
	}
	if mode == "completed-read" || mode == "pending-read" {
		fmt.Fprintln(stdin, "cat file")
	}
	if mode == "completed-write" || mode == "pending-write" || mode == "replayed-write" {
		fmt.Fprintf(stdin, "putrange %s file 0\n", strconv.Quote(patchFile))
	}
	if mode == "pending-unlock" {
		fmt.Fprintln(stdin, "unlock 1")
	}
	if strings.HasPrefix(mode, "completed-") {
		fmt.Fprintf(stdin, "lock-save %s\n", strconv.Quote(journal))
		waitReady()
	}
	if mode == "pending-read" || mode == "pending-write" || mode == "pending-unlock" || mode == "replayed-write" || lifecycle {
		select {
		case <-issued:
		case <-ctx.Done():
			t.Fatal("request was not issued")
		}
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err == nil {
		t.Fatal("child did not terminate by force")
	}
	stdin.Close()
	releaseOnce.Do(func() { close(release) })
	if err = <-originalDone; err != nil && !strings.HasPrefix(mode, "pending-") && mode != "replayed-write" && !lifecycle {
		var closed *net.OpError
		if !errors.As(err, &closed) || closed.Op != "read" {
			t.Fatal("original wire", err)
		}
	}
	if mode == "completed-write" || mode == "replayed-write" {
		copy(payload, patch)
		if origin.writes.Load() != 1 || !bytes.Equal(origin.metadata.data, payload) {
			t.Fatal("completed write did not update original server bytes")
		}
	}
	if mode == "corrupt" {
		f, err := os.OpenFile(journal, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte{1})
		f.Close()
	}
	args := append(append([]string{}, common...), "--recover-locks", journal)
	recoveryJoined := false
	if mode == "pending-recovery" {
		secondArgs := append(append([]string{}, args...), "--batch")
		var second *exec.Cmd
		if binary != "" {
			second = exec.CommandContext(ctx, binary, secondArgs...)
		} else {
			executable, _ := os.Executable()
			second = exec.CommandContext(ctx, executable, "-test.run=^TestLockRecoveryChild$", "-test.timeout=30s")
			encoded, _ := json.Marshal(secondArgs)
			second.Env = append(os.Environ(), "NFS_LOCK_RECOVERY_ARGS="+string(encoded))
		}
		second.Stdin = strings.NewReader("")
		second.Stdout = io.Discard
		second.Stderr = io.Discard
		if err := second.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { second.Process.Kill(); second.Wait() })
		select {
		case <-issued:
		case <-ctx.Done():
			t.Fatal("recovery TEST_STATEID not issued")
		}
		if err := second.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if second.Wait() == nil {
			t.Fatal("recovery process not killed")
		}
		close(recoveryRelease)
		<-recoveryDone
		recoveryJoined = true
	}
	if mode == "changed-profile" {
		args = append(args, "--uid", "99")
	}
	if mode != "valid-multi" {
		args = append(args, "--command", "get file "+strconv.Quote(local))
	}
	args = append(args, "--command", "unlock 1")
	if count == 2 {
		args = append(args, "--command", "unlock 2")
	}
	out, recoveryErr := runKerberosCLI(t, args)
	valid := strings.HasPrefix(mode, "valid-") || strings.HasPrefix(mode, "completed-") || mode == "replayed-write" || lifecycle
	t.Logf("LOCK_RECOVERY mode=%s release=%t error=%v output=%s", mode, binary != "", recoveryErr, out)
	if (recoveryErr == nil) != valid {
		t.Fatal("wrong recovery outcome", recoveryErr)
	}
	if valid {
		if mode != "valid-multi" {
			got, err := os.ReadFile(local)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("recovered file bytes", err)
			}
		}
		binds := int32(1)
		if mode == "replayed-write" || lifecycle {
			binds = 2
		}
		if target.unlocks.Load() != count || target.tests.Load() != 1 || target.binds.Load() != binds {
			t.Fatal("retained state not validated/released")
		}
	} else if target.destroyed.Load() != 0 || target.unlocks.Load() != 0 {
		t.Fatal("failed recovery destroyed retained state")
	}
	stop()
	if !recoveryJoined {
		if err = <-recoveryDone; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal("recovery wire", err)
		}
	}
	if mode != "corrupt" {
		r, err := nfs.InspectLockJournal(journal)
		if err != nil {
			t.Fatal("final journal", err)
		}
		if valid && (r.Retired == lifecycle || r.Pending || r.Locks != 0) {
			t.Fatal("clean unlock did not retire journal", r)
		}
		if mode == "replayed-write" && (r.RecoveredRequest == nil || r.RecoveredRequest.Operation != 38 || r.RecoveredRequest.Status != 0 || r.RecoveredRequest.Count != uint32(len(patch)) || target.writes.Load() != 0 || wirebinary.BigEndian.Uint32(cachedWriteArgs[28:]) != uint32(len(patch))) {
			t.Fatal("cached write receipt or exactly-once evidence differs", r)
		}
		if !valid && mode != "changed-profile" && !r.Pending {
			t.Fatal("failed recovery lost quarantine", r)
		}
		if mode == "changed-profile" && r.Pending {
			t.Fatal("wrong profile altered original journal")
		}
	}
	wantOriginLocks, wantTargetLocks := count, int32(0)
	if mode == "replayed-open" {
		wantOriginLocks, wantTargetLocks = 0, 1
	}
	if origin.opens.Load() != count || origin.locks.Load() != wantOriginLocks || target.opens.Load() != 0 || target.locks.Load() != wantTargetLocks {
		t.Fatal("recovery reissued OPEN/LOCK")
	}
}
