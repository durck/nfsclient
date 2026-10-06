package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestOffloadVerifierReceiptFailureKeepsOriginalSession(t *testing.T) {
	policy, servers := pnfsTLSFixture(t, "data")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	number, _ := strconv.Atoi(port)
	cfg := Config{Host: host, NFSPort: number, Version: "4.2", Transport: "tcp", Security: "sys", Timeout: 3 * time.Second, TLS: policy}
	cfg.TLS.ServerName = "127.0.0.1"
	p := &offloadVerificationPeer{}
	creates, binds, destroys := 0, 0, 0
	done := make(chan error, 2)
	go func() {
		for connection := 0; connection < 2; connection++ {
			conn, err := l.Accept()
			if err != nil {
				done <- err
				return
			}
			peer := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
				switch code {
				case 41:
					if !bytes.Equal(d.take(16), bytes.Repeat([]byte{9}, 16)) || d.u32() != 1 || d.boolean() {
						return nil, 0, errors.New("wrong verification BIND")
					}
					binds++
					e := encoder(bytes.Repeat([]byte{9}, 16))
					e.u32(1)
					e.u32(0)
					return e, 0, nil
				case 43:
					creates++
				case 44:
					destroys++
				}
				e, status, err := p.operation(code, d)
				if code == 42 && connection == 1 {
					e[12] |= 0x80
				}
				return e, status, err
			})
			err = serveOffloadTLSProxy(conn, peer, servers(connection))
			peer.c.nfs.conn.Close()
			done <- err
		}
	}()
	v, j, closeFixture := sessionOffloadFixture(t, func([]byte) []byte { t.Error("unexpected original-session RPC"); return nil }, true)
	defer closeFixture()
	r := j.record
	r.Expectation = offloadExpectedFixture()
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	if err := j.issue(); err != nil {
		t.Fatal(err)
	}
	r = j.record
	saved, err := v.saveSession()
	if err != nil {
		t.Fatal(err)
	}
	r.Resources = &OffloadResources{Version: 1, Complete: true}
	r.Recovery = &OffloadSessionEvidence{Session: saved}
	r.Recovery.Profile, err = offloadRecoveryProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.Recovery.Result = &OffloadCompletion{Count: 6, Complete: true}
	r.Recovery.Quiescent, r.Recovery.DataIssued = true, true
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	_ = v
	failed := false
	j.checkpointFault = func(stage string) error {
		e, ok := j.record.Endpoints["verification"]
		if stage == "before-write" && ok && len(e.Resources.Entries) > 0 && offloadOwnResourcesReleased(endpointRecord(j.record, "verification")) && !failed {
			failed = true
			return errors.New("terminal receipt sync unavailable")
		}
		return nil
	}
	if _, err := finishVerifiedOffload(context.Background(), cfg, j); err == nil || !failed {
		t.Fatal("receipt failure not injected", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if destroys != 0 || !j.record.Pending || !offloadOwnResourcesReleased(endpointRecord(j.record, "verification")) {
		t.Fatal("pending verification destroyed its recovery session")
	}
	path, id := j.file.Name(), j.record.ID
	j.file.Close()
	recovered, err := RecoverOffload(context.Background(), cfg, path, id)
	if err != nil || recovered.Pending || recovered.Outcome != "completed" || recovered.Recovery.StateCleanup != "confirmed" {
		t.Fatal("second verification recovery", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if creates != 1 || binds != 1 || destroys != 1 || p.locks != 2 || p.unlocks != 2 {
		t.Fatal("wrong verifier lifetime", creates, binds, destroys, p.locks, p.unlocks)
	}
}

func serveOffloadTLSProxy(conn net.Conn, peer *v4Client, policy *tls.Config) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
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
	secure := tls.Server(conn, policy)
	if err := secure.Handshake(); err != nil {
		return err
	}
	for {
		raw, err := readRecord(secure)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := peer.c.nfs.conn.Write(record(raw, true)); err != nil {
			return err
		}
		body, err := readRecord(peer.c.nfs.conn)
		if err != nil {
			return err
		}
		if _, err := secure.Write(record(body, true)); err != nil {
			return err
		}
	}
}
