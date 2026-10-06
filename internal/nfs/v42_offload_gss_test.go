package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	bgss "nfsclient/internal/krbgss"
)

func TestOffloadGSSProfile(t *testing.T) {
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		// Missing credentials must reach normal Kerberos validation, never a
		// blanket AUTH_SYS-only refusal or network connection.
		_, err := Connect(context.Background(), Config{Version: "4.2", Offload: true, Security: security})
		if err == nil || strings.Contains(err.Error(), "offload requires") {
			t.Fatal(security, err)
		}
		_, err = Connect(context.Background(), Config{Version: "4.2", Offload: true, Security: security, TLS: TLSConfig{Enabled: true}})
		if err == nil || !strings.Contains(err.Error(), "kerberos requires") {
			t.Fatal(security, err)
		}
		for _, sourceProtected := range []bool{false, true} {
			destination := &Client{v4: &v4Client{minor: 2}, config: &Config{Transport: "tcp"}}
			source := &Client{v4: &v4Client{minor: 2}, config: &Config{Transport: "tcp"}}
			if sourceProtected {
				source.security = security
			} else {
				destination.security = security
			}
			if _, err := destination.CopyRangeFrom(context.Background(), source, []byte("s"), []byte("d"), 0, 0, 1, time.Second, CopyFromOptions{}); err == nil || !strings.Contains(err.Error(), "inter-server COPY currently requires AUTH_SYS") {
				t.Fatal("secure delegation silently enabled", sourceProtected, security, err)
			}
		}
	}
}

// The MIT acceptor fronts the same strict lifecycle oracle used without GSS.
// Its callbacks travel through the TCP duplex reader before the waiting fore
// request completes; both directions share real ticket-derived context keys.
func offloadMITCallbacks(t *testing.T, c *Client, security string) func(encoder) error {
	t.Helper()
	var tlsOptions []mitTLSOptions
	if strings.HasPrefix(security, "tls-") {
		security = strings.TrimPrefix(security, "tls-")
		policy, server := pnfsTLSFixture(t, "data")
		tlsOptions = []mitTLSOptions{{server: server(0), client: policy}}
	}
	var mu sync.Mutex
	var conn net.Conn
	var acceptor *bgss.Acceptor
	pnfsMITWrapClient(t, c, security, func(connection net.Conn, ctx *bgss.Acceptor) error {
		mu.Lock()
		conn, acceptor = connection, ctx
		mu.Unlock()
		return nil
	}, tlsOptions...)
	c.config.PNFS = false
	c.config.Offload = true
	r := c.v4.recall
	g, err := newGSSBackchannel(c.nfs.gss)
	if err != nil {
		t.Fatal(err)
	}
	r.gss = g
	c.nfs.pinnedBackchannelGSS = true
	c.nfs.duplex = startDuplex(c.nfs, func(raw []byte) ([]byte, error) { return g.callback(raw, r) })
	var rpcSequence uint32
	return func(plain encoder) error {
		mu.Lock()
		defer mu.Unlock()
		if conn == nil || acceptor == nil {
			return errors.New("callback before context establishment")
		}
		rpcSequence++
		server := &gssBackchannel{context: acceptor, handle: g.handle, service: g.service}
		raw := gssProtectCallback(t, server, plain, rpcSequence)
		if _, err := conn.Write(record(raw, true)); err != nil {
			return err
		}
		reply, err := readRecord(conn)
		if err != nil {
			return err
		}
		d := &decoder{b: reply}
		if d.u32() != binary.BigEndian.Uint32(plain) || d.u32() != 1 || d.u32() != 0 {
			return errors.New("wrong callback reply identity")
		}
		d.verifierFlavor = d.u32()
		d.verifier = d.opaque(400)
		if d.u32() != 0 {
			return errors.New("callback RPC rejection")
		}
		check := rpcGSS{context: acceptor, seq: rpcSequence, service: g.service}
		if err = check.verify(d, rpcSequence); err != nil {
			return err
		}
		return check.unprotect(d)
	}
}

func TestOffloadMITLifecycle(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) { runOffloadLifecycle(t, security) })
	}
}

func TestOffloadGSSCallbackAuthentication(t *testing.T) {
	for _, service := range []uint32{1, 2, 3} {
		for _, mode := range []string{"ok", "body", "header", "plain", "wrong-job", "expired", "replay"} {
			t.Run(fmt.Sprintf("%d/%s", service, mode), func(t *testing.T) {
				g, err := newGSSBackchannel(&rpcGSS{context: callbackTestPrivacy{}, handle: []byte("fore"), service: service, window: 16, established: true})
				if err != nil {
					t.Fatal(err)
				}
				id := bytes.Repeat([]byte{8}, 16)
				r := &layoutRecall{session: bytes.Repeat([]byte{9}, 16), minor: 2, offloadEnabled: true, offload: &offloadPending{fh: []byte("file"), id: id, length: 6}}
				plain := offloadCallback(r, 1, []byte("file"), id, offloadReply{count: 6, stable: 2, verifier: []byte("verifier")})
				if mode == "wrong-job" {
					plain = offloadCallback(r, 1, []byte("file"), bytes.Repeat([]byte{7}, 16), offloadReply{count: 6, stable: 2, verifier: []byte("verifier")})
				}
				raw := gssProtectCallback(t, g, plain, 1)
				if mode == "body" {
					raw[len(raw)-1] ^= 1
				}
				if mode == "header" {
					raw[0] ^= 1
				}
				if mode == "plain" {
					raw = plain
				}
				if mode == "expired" {
					g.expiry = time.Now().Add(-time.Second)
				}
				_, err = g.callback(raw, r)
				accepted := mode == "ok" || mode == "replay"
				if accepted && err != nil || (r.offload.result != nil) != accepted {
					t.Fatal("offload authentication/state", err)
				}
				if mode != "wrong-job" && !accepted && err == nil {
					t.Fatal("invalid security accepted")
				}
				if mode == "replay" {
					if _, err = g.callback(raw, r); err == nil {
						t.Fatal("RPC replay accepted")
					}
				}
			})
		}
	}
}

func TestOffloadMITTLSLifecycle(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) { runOffloadLifecycle(t, "tls-"+security) })
	}
}
