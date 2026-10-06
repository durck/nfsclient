package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestOffloadRecoveryProcessChild(t *testing.T) {
	value := os.Getenv("NFS_OFFLOAD_PROCESS_CONFIG")
	if value == "" {
		t.Skip("subprocess helper")
	}
	var cfg Config
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if id := os.Getenv("NFS_OFFLOAD_PROCESS_ID"); id != "" {
		r, err := RecoverOffload(ctx, cfg, cfg.OffloadJournal, id)
		if os.Getenv("NFS_OFFLOAD_EXPECT_FAILURE") == "1" {
			if err == nil || !r.Pending || r.Recovery == nil || r.Recovery.Verified || r.Recovery.Committed {
				t.Fatal("verification failure was published", err)
			}
			return
		}
		if err != nil || r.Pending || r.Recovery == nil || !r.Recovery.Committed {
			t.Fatal("recovery", err)
		}
		return
	}
	rpc, err := dialRPC(ctx, cfg.Host, cfg.NFSPort, cfg.Timeout, false)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := cfg.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := rpc.startTLS(ctx, nfsProgram, 4, policy); err != nil {
		t.Fatal(err)
	}
	c := &Client{nfs: rpc, config: &cfg, Auth: cfg.Auth, version: "4.2", security: "sys", ReadSize: 128, WriteSize: 128}
	v := &v4Client{c: c, minor: 2, clientNonce: bytes.Repeat([]byte{6}, 16)}
	c.v4 = v
	if err := v.initializeSession(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	v.root = []byte("root")
	v.leaseSeconds = 90
	now := time.Now()
	v.lastLease.Store(&now)
	v.recall = &layoutRecall{offloadEnabled: true}
	_, err = v.beginOffload(offloadIntent{Operation: "writesame", Destination: []byte("file"), Offset: 7, Length: 6})
	if err != nil {
		t.Fatal(err)
	}
	// This transport crash oracle supplies a pre-existing caller-owned stateid;
	// acquisition/cleanup are exercised by the separate real CLI OPEN oracle.
	v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Write: true, Length: LockToEOF}, file: &v4Open{fh: []byte("file"), auth: c.Auth}, sid: bytes.Repeat([]byte{1}, 16)}}
	if _, _, err := v.offloadOpenIO(ctx, []byte("file"), 2); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NFS_OFFLOAD_PROCESS_ASYNC") == "1" {
		j := v.recall.offload.journal
		r := j.record
		r.Expectation = offloadExpectedFixture()
		if err := j.append(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.issueOffload(); err != nil {
		t.Fatal(err)
	}
	// The parent kills this process after server execution, before this reply.
	if err := v.compound(ctx, fh4([]byte("file")), op4(70, recoveryADBArgs(), func(d *decoder) { decodeOffloadReply(d) })); err != nil {
		t.Fatal(err)
	}
	t.Fatal("origin unexpectedly received a result")
}

func TestOffloadFreshProcessQuiescentRecovery(t *testing.T) {
	for _, mode := range []string{"ok", "mismatch", "renamed", "unlock"} {
		t.Run(mode, func(t *testing.T) {
			p := &offloadVerificationPeer{mode: mode}
			peer := peer4(t, 2, p.operation)
			policy, servers := pnfsTLSFixture(t, "data")
			endpoint := pnfsTLSPeerEndpoint(t, peer, servers(0), "")
			host, port, _ := net.SplitHostPort(endpoint)
			number, _ := strconv.Atoi(port)
			cfg := Config{Host: host, NFSPort: number, Version: "4.2", Transport: "tcp", Security: "sys", Timeout: 5 * time.Second, TLS: policy, Offload: true, OffloadSessionRecovery: true}
			cfg.TLS.ServerName = "127.0.0.1"
			v, j, closeFixture := sessionOffloadFixture(t, func([]byte) []byte { return nil }, true)
			defer closeFixture()
			cfg.OffloadJournal = j.file.Name()
			r := j.record
			r.Expectation = offloadExpectedFixture()
			if err := j.append(r); err != nil {
				t.Fatal(err)
			}
			if err := j.issue(); err != nil {
				t.Fatal(err)
			}
			saved, err := v.saveSession()
			if err != nil {
				t.Fatal(err)
			}
			saved.Confirmed = time.Now().Add(-10 * time.Minute)
			profile, err := offloadRecoveryProfile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			r = j.record
			r.Recovery = &OffloadSessionEvidence{Session: saved, Profile: profile, Quiescent: true, Result: &OffloadCompletion{ID: bytes.Repeat([]byte{1}, 16), Count: 6, Complete: true}}
			if err := j.append(r); err != nil {
				t.Fatal(err)
			}
			// The recovery process must open a completely new protected session.
			// Its name cache is empty; no original in-process maps are inherited.
			j.file.Close()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, executable, "-test.run=^TestOffloadRecoveryProcessChild$", "-test.timeout=12s")
			child.Env = append(os.Environ(), "NFS_OFFLOAD_PROCESS_CONFIG="+string(encoded), "NFS_OFFLOAD_PROCESS_ID="+r.ID)
			if mode != "ok" {
				child.Env = append(child.Env, "NFS_OFFLOAD_EXPECT_FAILURE=1")
			}
			output, err := child.CombinedOutput()
			if err != nil {
				t.Fatalf("fresh recovery child: %v %s", err, output)
			}
			after, err := InspectOffloadJournal(cfg.OffloadJournal)
			if err != nil || after.Recovery.Verified != (mode == "ok") || after.Pending != (mode != "ok") {
				t.Fatal("incorrect persisted verification", err)
			}
		})
	}
}

func TestOffloadProcessCrashExactProtectedRecovery(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run(fmt.Sprintf("async=%t", async), func(t *testing.T) { offloadCrashProtectedRecovery(t, async) })
	}
}

func offloadCrashProtectedRecovery(t *testing.T, async bool) {
	policy, servers := pnfsTLSFixture(t, "data")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	number, _ := strconv.Atoi(port)
	cfg := Config{Host: host, NFSPort: number, Version: "4.2", Transport: "tcp", Security: "sys", Timeout: 5 * time.Second, TLS: policy, Offload: true, OffloadSessionRecovery: true, OffloadJournal: filepath.Join(t.TempDir(), "offload.state")}
	cfg.TLS.ServerName = "127.0.0.1"
	state := &cachedWritePeer{role: 0x10000, data: func(code uint32, d *decoder) (encoder, error) {
		if code != 70 || !bytes.Equal(d.take(len(recoveryADBArgs())), recoveryADBArgs()) {
			return nil, errors.New("changed WRITE_SAME")
		}
		var e encoder
		if async {
			e.u32(1)
			e = append(e, bytes.Repeat([]byte{1}, 16)...)
		} else {
			e.u32(0)
		}
		e.u64(6)
		e.u32(2)
		e = append(e, make([]byte, 8)...)
		return e, nil
	}}
	state.other = func(code uint32, d *decoder) (encoder, error) {
		if code != 67 || !bytes.Equal(d.take(16), bytes.Repeat([]byte{1}, 16)) {
			return nil, errors.New("unexpected recovery status")
		}
		var e encoder
		e.u64(6)
		e.u32(1)
		e.u32(0)
		return e, nil
	}
	issued, release := make(chan struct{}), make(chan struct{})
	connections := 2
	if async {
		connections = 3
	}
	done := make(chan error, connections)
	go func() {
		for connection := 0; connection < connections; connection++ {
			conn, err := l.Accept()
			if err != nil {
				done <- err
				return
			}
			go func(connection int, conn net.Conn) {
				done <- func() error {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(15 * time.Second))
					raw, err := readRecord(conn)
					if err != nil {
						return err
					}
					d := &decoder{b: raw}
					xid := d.u32()
					for _, want := range []uint32{0, 2, nfsProgram, 4, 0, 7, 0, 0, 0} {
						if d.u32() != want {
							return errors.New("NFS before TLS")
						}
					}
					var reply encoder
					for _, n := range []uint32{xid, 1, 0, 0} {
						reply.u32(n)
					}
					reply.str("STARTTLS")
					reply.u32(0)
					if _, err := conn.Write(record(reply, true)); err != nil {
						return err
					}
					secure := tls.Server(conn, servers(connection))
					if err := secure.Handshake(); err != nil {
						return err
					}
					var up *Client
					if connection == 2 {
						up = peer4(t, 2, (&offloadVerificationPeer{}).operation).c
					} else {
						up = state.client(t, 2)
					}
					defer up.nfs.conn.Close()
					for {
						raw, err := readRecord(secure)
						if err != nil {
							return nil
						}
						if _, err := up.nfs.conn.Write(record(raw, true)); err != nil {
							return err
						}
						response, err := readRecord(up.nfs.conn)
						if err != nil {
							return err
						}
						state.mu.Lock()
						executed := state.writes > 0
						state.mu.Unlock()
						if connection == 0 && executed {
							close(issued)
							<-release
							return nil
						}
						if _, err := secure.Write(record(response, true)); err != nil {
							return err
						}
					}
				}()
			}(connection, conn)
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestOffloadRecoveryProcessChild$", "-test.timeout=15s")
	child.Env = append(os.Environ(), "NFS_OFFLOAD_PROCESS_CONFIG="+string(encoded))
	if async {
		child.Env = append(child.Env, "NFS_OFFLOAD_PROCESS_ASYNC=1")
	}
	var diagnostics bytes.Buffer
	child.Stdout = &diagnostics
	child.Stderr = &diagnostics
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	select {
	case <-issued:
	case <-ctx.Done():
		t.Fatal("origin timeout", diagnostics.String())
	}
	child.Process.Kill()
	child.Wait()
	close(release)
	r, err := InspectOffloadJournal(cfg.OffloadJournal)
	if err != nil || r.Recovery == nil || r.Recovery.Request == nil {
		t.Fatal("missing crash evidence", err)
	}
	if binary.BigEndian.Uint32(r.Recovery.Request.Inner[len(r.Recovery.Request.Inner)-len(recoveryADBArgs())-4:]) != 70 {
		t.Fatal("wrong durable operation")
	}
	recover := exec.CommandContext(ctx, executable, "-test.run=^TestOffloadRecoveryProcessChild$", "-test.timeout=15s")
	recover.Env = append(os.Environ(), "NFS_OFFLOAD_PROCESS_CONFIG="+string(encoded), "NFS_OFFLOAD_PROCESS_ID="+r.ID)
	output, err := recover.CombinedOutput()
	if err != nil {
		t.Fatalf("recovery child: %v %s", err, output)
	}
	for range connections {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.creates != 1 || state.writes != 1 || state.replays != 1 || state.binds != 1 {
		t.Fatal(fmt.Sprint(state.creates, state.writes, state.replays, state.binds))
	}
}
