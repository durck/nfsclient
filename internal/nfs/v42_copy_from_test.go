package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCopyFromGrantDecoding(t *testing.T) {
	var valid encoder
	valid.u64(60)
	valid.u32(0)
	valid = append(valid, bytes.Repeat([]byte{4}, 16)...)
	valid.u32(1)
	valid = append(valid, copyNetaddr("[2001:db8::1]:2049")...)
	started := time.Now()
	for i := 0; i < len(valid); i++ {
		d := &decoder{b: valid[:i]}
		decodeCopyGrant(d, started)
		if d.err == nil {
			t.Fatalf("accepted truncated grant at %d", i)
		}
	}
	for _, kind := range []string{"valid", "negative-seconds", "bad-nanos", "zero-id", "ones-id", "empty-list", "excess-list", "bad-kind", "huge-lease"} {
		t.Run(kind, func(t *testing.T) {
			b := bytes.Clone(valid)
			switch kind {
			case "negative-seconds":
				binary.BigEndian.PutUint64(b, 1<<63)
			case "bad-nanos":
				binary.BigEndian.PutUint32(b[8:], 1e9)
			case "zero-id":
				clear(b[12:28])
			case "ones-id":
				copy(b[12:28], bytes.Repeat([]byte{255}, 16))
			case "empty-list":
				binary.BigEndian.PutUint32(b[28:], 0)
			case "excess-list":
				binary.BigEndian.PutUint32(b[28:], 65)
			case "bad-kind":
				binary.BigEndian.PutUint32(b[32:], 4)
			case "huge-lease":
				binary.BigEndian.PutUint64(b, 1<<63-1)
			}
			d := &decoder{b: b}
			grant := decodeCopyGrant(d, started)
			ok := kind == "valid" || kind == "huge-lease"
			if (d.err == nil) != ok {
				t.Fatal(d.err)
			}
			if ok && (len(d.b) != 0 || len(grant.endpoints) != 1 || grant.endpoints[0] != "[2001:db8::1]:2049" || !bytes.Equal(grant.locations, valid[28:]) || !grant.expires.After(started)) {
				t.Fatal("incorrect grant", grant)
			}
		})
	}
}

func TestCopyFromOptions(t *testing.T) {
	for _, o := range []CopyFromOptions{
		{}, {Destination: "example.test:2049", SourceServers: []string{"192.0.2.1:2049"}},
		{Destination: "192.0.2.2:2049", SourceServers: []string{"192.0.2.1:0"}},
		{Destination: "192.0.2.2:2049", SourceServers: []string{"192.0.2.1:2049", "[::ffff:192.0.2.1]:2049"}},
	} {
		if err := ValidateCopyFromOptions(o); err == nil {
			t.Fatal("invalid endpoints accepted", o)
		}
	}
	if err := ValidateCopyFromOptions(CopyFromOptions{Destination: "[2001:db8::2]:2049", SourceServers: []string{"[2001:db8::1]:2049"}}); err != nil {
		t.Fatal(err)
	}
}

func TestCopyFromWire(t *testing.T) {
	for _, mode := range []string{"sync", "unstable", "short", "notify-denied", "unapproved", "hostname", "truncated-notify", "expired", "copy-denied", "truncated-copy", "cancel", "async", "revoke-failed", "lease-zero", "many-addresses", "excess-addresses"} {
		t.Run(mode, func(t *testing.T) {
			notifies, copies, revokes, cancels, commits := 0, 0, 0, 0, 0
			token, job := bytes.Repeat([]byte{4}, 16), bytes.Repeat([]byte{5}, 16)
			var locations encoder
			count := 1
			if mode == "many-addresses" {
				count = 64
			}
			if mode == "excess-addresses" {
				count = 65
			}
			locations.u32(uint32(count))
			for range count {
				if mode == "hostname" {
					locations.u32(1)
					locations.str("source.example.test")
					continue
				}
				locations.u32(3)
				locations.str("tcp")
				address := "192.0.2.1.8.1"
				if mode == "unapproved" {
					address = "192.0.2.99.8.1"
				}
				locations.str(address)
			}
			source := copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 61:
					notifies++
					if !bytes.Equal(d.take(16), bytes.Repeat([]byte{7}, 16)) || d.u32() != 3 || d.str() != "tcp" || d.str() != "192.0.2.2.8.1" {
						return nil, 0, errors.New("wrong COPY_NOTIFY identity or destination")
					}
					if mode == "notify-denied" {
						return nil, 13, nil
					}
					seconds, nanos := uint64(60), uint32(0)
					if mode == "lease-zero" {
						seconds = 0
					}
					if mode == "expired" {
						seconds = 0
						nanos = 1
						time.Sleep(2 * time.Millisecond) // Grant expires during the RPC round trip.
					}
					e.u64(seconds)
					e.u32(nanos)
					e = append(e, token...)
					e = append(e, locations...)
					if mode == "truncated-notify" {
						e = e[:len(e)-1]
					}
					return e, 0, nil
				case 66:
					revokes++
					if !bytes.Equal(d.take(16), token) {
						return nil, 0, errors.New("wrong revoked authorization")
					}
					if mode == "revoke-failed" {
						return nil, 5, nil
					}
					return nil, 0, nil
				}
				return nil, 0, fmt.Errorf("unexpected source operation %d", code)
			})
			var destination *Client
			destination = copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 32:
					return nil, 0, nil
				case 60:
					copies++
					if !bytes.Equal(d.take(16), token) || !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) || d.u64() != 17 || d.u64() != 23 || d.u64() != 8192 || !d.boolean() || d.boolean() || !bytes.Equal(d.take(len(locations)), locations) {
						return nil, 0, errors.New("COPY altered authorization, offsets or exact source list")
					}
					if mode == "copy-denied" {
						return nil, 13, nil
					}
					if mode == "async" || mode == "cancel" {
						e.u32(1)
						e = append(e, job...)
					} else {
						e.u32(0)
					}
					n := uint64(8192)
					if mode == "short" {
						n = 7
					}
					e.u64(n)
					if mode == "unstable" {
						e.u32(0)
					} else {
						e.u32(2)
					}
					e = append(e, []byte("verifier")...)
					e.u32(1)
					if mode == "async" || mode == "cancel" {
						e.u32(0)
					} else {
						e.u32(1)
					}
					if mode == "truncated-copy" {
						e = e[:len(e)-1]
					}
					return e, 0, nil
				case 67:
					if !bytes.Equal(d.take(16), job) {
						return nil, 0, errors.New("wrong status job")
					}
					if mode == "async" {
						_, err := destination.v4.recall.callback(offloadCallback(destination.v4.recall, 1, []byte("destination"), job, offloadReply{count: 8192, stable: 2, verifier: []byte("verifier")}))
						if err != nil {
							return nil, 0, err
						}
					}
					e.u64(8192)
					e.u32(1)
					e.u32(0)
					return e, 0, nil
				case 66:
					cancels++
					if !bytes.Equal(d.take(16), job) {
						return nil, 0, errors.New("wrong cancelled job")
					}
					return nil, 0, nil
				case 5:
					commits++
					if d.u64() != 23 || d.u32() != 0 {
						return nil, 0, errors.New("wrong COMMIT range")
					}
					return encoder("verifier"), 0, nil
				}
				return nil, 0, fmt.Errorf("unexpected destination operation %d", code)
			})
			destination.v4.recall = &layoutRecall{offloadEnabled: true, minor: 2, session: bytes.Repeat([]byte{9}, 16)}
			wait := 2 * time.Second
			if mode == "cancel" {
				wait = 50 * time.Millisecond
			}
			n, err := destination.CopyRangeFrom(context.Background(), source, []byte("source"), []byte("destination"), 17, 23, 8192, wait, CopyFromOptions{Destination: "192.0.2.2:2049", SourceServers: []string{"192.0.2.1:2049"}})
			success := mode == "sync" || mode == "unstable" || mode == "async" || mode == "lease-zero" || mode == "many-addresses"
			if (err == nil) != success || success && n != 8192 {
				t.Fatal(n, err)
			}
			wantCopies, wantRevokes := 1, 1
			switch mode {
			case "notify-denied", "truncated-notify", "excess-addresses":
				wantCopies = 0
				wantRevokes = 0
			case "unapproved", "hostname", "expired":
				wantCopies = 0
			}
			if notifies != 1 || copies != wantCopies || revokes != wantRevokes {
				t.Fatal("replayed request or lost revocation", notifies, copies, revokes, err)
			}
			if (cancels == 1) != (mode == "cancel") || (commits == 1) != (mode == "unstable") {
				t.Fatal("cancellation/durability", cancels, commits)
			}
			if mode == "short" && n != 7 {
				t.Fatal("lost short count", n)
			}
			if strings.HasPrefix(mode, "truncated-") && !strings.Contains(err.Error(), "unverified") {
				t.Fatal("lost uncertainty", err)
			}
			if mode == "revoke-failed" && !source.v4.stateLost.Load() {
				t.Fatal("failed revocation retained usable source state")
			}
		})
	}
}
