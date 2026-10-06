package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestPNFSFailoverIdentity(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"same", "minor-id", "owner", "scope", "client-id", "unconfirmed", "unknown-sequence", "uncertain-sequence"} {
			t.Run(fmt.Sprintf("%d/%s", minor, mode), func(t *testing.T) {
				s := &createSequenceServer{next: 22, clientID: 123, owner: "ds", scope: "scope"}
				original := s.peer(t, minor, nil, 0x40000)
				if err := original.initialize(context.Background()); err != nil {
					t.Fatal(err)
				}
				expected := *original.serverIdentity
				switch mode {
				case "minor-id":
					s.minorID++
				case "owner":
					s.owner = "other"
				case "scope":
					s.scope = "other"
				case "client-id":
					s.clientID++
				case "unconfirmed":
					s.confirmed = false
				case "unknown-sequence":
					delete(original.creates.entries, expected)
				case "uncertain-sequence":
					original.creates.entries[expected] = createSessionSequence{next: 23, uncertain: true}
				}
				alternate := s.peer(t, minor, original, 0x40000)
				err := alternate.initializeExpected(context.Background(), &expected)
				success := mode == "same" || mode == "minor-id"
				if (err == nil) != success {
					t.Fatalf("success=%v err=%v", success, err)
				}
				want := 1
				if success {
					want = 2
					if alternate.serverIdentity == nil || *alternate.serverIdentity != expected {
						t.Fatal("identity changed")
					}
				}
				if len(s.requests) != want {
					t.Fatal("unexpected CREATE_SESSION", s.requests)
				}
			})
		}
	}
}

func TestPNFSFailoverTransportClassification(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"record-eof", &rpcTransportFailure{&ConnectionLostError{Err: io.EOF}}, true},
		{"read-timeout", markRPCTransportFailure(&net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}), true},
		{"write-reset", markRPCTransportFailure(&net.OpError{Op: "write", Net: "tcp", Err: net.ErrClosed}), true},
		{"dial", markRPCTransportFailure(&net.OpError{Op: "dial", Net: "tcp", Err: net.ErrClosed}), false},
		{"decoded-xdr", io.ErrUnexpectedEOF, false},
		{"closed-before-call", ErrConnectionLost, false},
		{"status", Status(13), false},
		{"rpc-denied", RPCDenied(1), false},
		{"bad-mic", errors.New("GSS signature invalid"), false},
		{"tls-alert", errors.New("tls: bad record MAC"), false},
		{"cancel", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if retryablePNFSRead(tc.err) != tc.retry {
				t.Fatal(tc.err)
			}
		})
	}
}

func TestPNFSFailoverProfileRefusals(t *testing.T) {
	o := PNFSOptions{ReadFailover: true, DataServers: map[string]string{"192.0.2.1:2049": "127.0.0.1:2049"}}
	validated, err := validatePNFSOptions(o)
	if err != nil || !validated.ReadFailover {
		t.Fatal(validated, err)
	}
	for _, security := range []string{"", "sys", "krb5"} {
		c := &Client{config: &Config{Security: security}, nfs: &rpcClient{}}
		if _, err := c.pnfsKerberosConfigs(o); err == nil {
			t.Fatal("unprotected failover accepted", security)
		}
	}
	c := &Client{}
	if err := c.ValidatePNFSWriteOptions(o); err == nil {
		t.Fatal("write preflight accepted")
	}
	if _, err := c.WritePNFSRangeFromProgress(context.Background(), nil, 0, 1, bytes.NewReader([]byte{1}), o, nil); err == nil {
		t.Fatal("write accepted")
	}
}

func lostPNFSReadClient(t *testing.T) *Client {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); readRecord(server) }()
	t.Cleanup(func() { client.Close(); server.Close(); <-done })
	c := &Client{nfs: &rpcClient{conn: client, timeout: time.Second}}
	c.v4 = &v4Client{c: c, minor: 1}
	return c
}

func TestPNFSFailoverDoesNotRetryContextExchangeLoss(t *testing.T) {
	for _, control := range []uint32{0, 1, 2, 3} {
		t.Run(fmt.Sprint(control), func(t *testing.T) {
			c := lostPNFSReadClient(t)
			_, err := c.nfs.callLocked(context.Background(), nfsProgram, 4, 0, nil, nil, control)
			if !errors.Is(err, ErrConnectionLost) || retryablePNFSRead(err) != (control == 0) {
				t.Fatal("context exchange loss classified as an eligible READ", err)
			}
		})
	}
}

func TestPNFSFailoverBatch(t *testing.T) {
	for _, mode := range []string{"recover", "default", "second-loss", "bad-xdr", "denied", "cancel", "recall"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := lostPNFSReadClient(t)
			alternate := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 25 || d.u32() != 0 || !bytes.Equal(d.take(12), bytes.Repeat([]byte{7}, 12)) || d.u64() != 123 || d.u32() != 4 {
					return nil, 0, errors.New("READ changed")
				}
				var e encoder
				e.u32(1)
				e.opaque([]byte("good"))
				return e, 0, nil
			})
			healthy := peer4WithHandle(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				d.take(16)
				d.u64()
				d.u32()
				if mode == "denied" {
					return nil, Status(13), nil
				}
				if mode == "bad-xdr" {
					return nil, 0, nil
				}
				var e encoder
				e.u32(1)
				e.opaque([]byte("keep"))
				return e, 0, nil
			}, nil, true)
			batch := []*pnfsRead{{ds: original, handle: []byte("a"), offset: 123, limit: 4}, {ds: healthy.c, handle: []byte("b"), limit: 4}}
			recoveries := 0
			recovery := func(r *pnfsRead) error {
				recoveries++
				r.ds = alternate.c
				if mode == "second-loss" {
					r.ds = lostPNFSReadClient(t)
				}
				return nil
			}
			if mode == "default" {
				recovery = nil
			}
			if mode == "cancel" {
				cancel()
			}
			usable := func() error {
				if mode == "recall" {
					return errors.New("layout recalled")
				}
				return nil
			}
			err := readPNFSBatchRecover(ctx, batch, bytes.Repeat([]byte{7}, 16), usable, recovery)
			if mode == "recover" {
				if err != nil || string(batch[0].data) != "good" || string(batch[1].data) != "keep" || recoveries != 1 {
					t.Fatal(err, recoveries)
				}
			} else if err == nil {
				t.Fatal("failure lost")
			}
			if mode != "recover" && mode != "second-loss" && recoveries != 0 {
				t.Fatal("unsafe retry", recoveries)
			}
		})
	}
}
