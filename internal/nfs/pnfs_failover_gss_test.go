package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	bgss "nfs-viewer/internal/krbgss"
)

// Real MIT tickets and TCP/TLS protect the scripted DS protocol. This does not
// claim native NFS multipath advertisement or filesystem interoperability.
func TestPNFSMITReadFailover(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"recover", "parallel", "default", "owner", "scope", "client-id", "unconfirmed", "spn", "second-loss", "bad-xdr", "denied", "recall", "cancel", "create-lost"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%v/%s", minor, security, secure, mode), func(t *testing.T) { runPNFSMITReadFailover(t, minor, security, secure, mode) })
				}
			}
		}
	}
}

func TestPNFSMITReadFailoverPublic(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, transport := range []string{"", "tls-"} {
				for _, parallel := range []int{1, 3} {
					t.Run(fmt.Sprintf("4.%d/%s/%sp%d", minor, security, transport, parallel), func(t *testing.T) {
						runPNFSStripedRead(t, minor, "gss-"+security+"-"+transport+"failover-dense", 128, "data", parallel)
					})
				}
			}
		}
	}
}

func runPNFSMITReadFailover(t *testing.T, minor uint32, security string, secure bool, mode string, flexProfiles ...bool) {
	flex := len(flexProfiles) != 0 && flexProfiles[0]
	dsMinor := minor
	if flex {
		dsMinor = 3 - minor
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := pnfsMITConfig(t, security, "nfs/ds.nfs.test")
	cfg.Version = fmt.Sprintf("4.%d", minor)
	parent := &Client{config: &cfg, version: cfg.Version, ReadSize: 128, WriteSize: 128, security: security, principal: cfg.Kerberos.Principal}
	parent.v4 = &v4Client{c: parent, minor: minor, clientNonce: bytes.Repeat([]byte{6}, 16)}
	state := &createSequenceServer{next: 22, clientID: 123, owner: "ds", scope: "scope"}
	var reads atomic.Int32
	read := func(code uint32, d *decoder) (encoder, Status, error) {
		wantState := append(make([]byte, 4), bytes.Repeat([]byte{7}, 12)...)
		if flex {
			wantState = bytes.Repeat([]byte{9}, 16)
		}
		if !bytes.Equal(d.take(16), wantState) || d.u64() != 123 || d.u32() != 4 {
			return nil, 0, errors.New("replayed READ changed state/range")
		}
		reads.Add(1)
		if mode == "bad-xdr" {
			return nil, 0, nil
		}
		if mode == "denied" {
			return nil, Status(13), nil
		}
		var e encoder
		e.u32(1)
		e.opaque([]byte("data"))
		return e, 0, nil
	}
	tlsConfigs := map[string]*tls.Config{}
	authConfigs := map[string]Config{}
	paths := []string{}
	var unusable atomic.Bool
	var policy TLSConfig
	var peerTLS func(int) *tls.Config
	if secure {
		policy, peerTLS = pnfsTLSFixture(t, "data")
		cfg.TLS = policy
	}
	for i := 0; i < 2; i++ {
		peer := state.peer(t, dsMinor, parent.v4, 0x40000, read)
		options := mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]}
		if secure {
			options.server = peerTLS(i)
			options.client = policy
		}
		if i == 0 && mode != "bad-xdr" && mode != "denied" {
			options.dropDataReply = 3
		}
		if i == 0 && mode == "cancel" {
			options.afterDroppedReply = cancel
		}
		if i == 1 && mode == "second-loss" {
			options.dropDataReply = 3
		}
		if i == 1 && mode == "create-lost" {
			options.dropDataReply = 2
		}
		requests := 0
		hook := func(_ net.Conn, _ *bgss.Acceptor) error {
			requests++
			if i == 0 && requests == 3 {
				if mode == "recall" {
					unusable.Store(true)
				}
			}
			return nil
		}
		endpoint := pnfsMITEndpoint(t, peer.c.nfs.conn, hook, options)
		paths = append(paths, endpoint)
		authConfigs[endpoint] = cfg
		if secure {
			tc := cfg
			tc.TLS.ServerName = "127.0.0.1"
			p, err := tc.tlsConfig()
			if err != nil {
				t.Fatal(err)
			}
			tlsConfigs[endpoint] = p
		}
	}
	usable := func() error {
		if unusable.Load() {
			return errors.New("layout recalled")
		}
		return nil
	}
	get, recoverRead, closePool := parent.pnfsDataServers(ctx, tlsConfigs, authConfigs, usable, false)
	component := func(paths []string) *flexDS {
		return &flexDS{rsize: 128, major: 4, minor: dsMinor, endpoints: paths, state: bytes.Repeat([]byte{9}, 16), handle: []byte("file")}
	}
	if flex {
		flexGet, flexRecover, _, flexClose := parent.pnfsFlexServers(ctx, tlsConfigs, authConfigs, usable)
		get = func(paths []string) (*Client, string, error) { return flexGet(component(paths)) }
		recoverRead, closePool = flexRecover, flexClose
	}
	defer closePool()
	ds, endpoint, err := get(paths)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	switch mode {
	case "minor-id":
		state.minorID++
	case "owner":
		state.owner = "other"
	case "scope":
		state.scope = "other"
	case "client-id":
		state.clientID++
	case "unconfirmed":
		state.confirmed = false
	}
	state.mu.Unlock()
	if mode == "unknown-sequence" {
		delete(parent.v4.creates.entries, *ds.v4.serverIdentity)
	}
	if mode == "uncertain-sequence" {
		parent.v4.creates.entries[*ds.v4.serverIdentity] = createSessionSequence{next: 23, uncertain: true}
	}
	if mode == "service" || mode == "principal" {
		other := cfg
		if mode == "service" {
			other.Security = "krb5"
		} else {
			other.Kerberos.Principal = "other@NFS.TEST"
		}
		authConfigs[paths[1]] = other
	}
	if mode == "spn" {
		other := cfg
		other.Kerberos.SPN = "nfs/server.nfs.test"
		authConfigs[paths[1]] = other
	}
	batch := []*pnfsRead{{ds: ds, endpoint: endpoint, paths: paths, handle: []byte("file"), offset: 123, limit: 4}}
	if mode == "parallel" {
		for i := 0; i < 2; i++ {
			otherState := &createSequenceServer{next: 42, clientID: uint64(200 + i), owner: fmt.Sprint("healthy", i), scope: "scope"}
			other := otherState.peer(t, dsMinor, parent.v4, 0x40000, func(_ uint32, d *decoder) (encoder, Status, error) {
				d.take(16)
				d.u64()
				d.u32()
				var e encoder
				e.u32(1)
				e.opaque([]byte("keep"))
				return e, 0, nil
			})
			options := mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]}
			if secure {
				options.server, options.client = peerTLS(i), policy
			}
			address := pnfsMITEndpoint(t, other.c.nfs.conn, nil, options)
			authConfigs[address] = cfg
			if secure {
				tlsConfigs[address] = tlsConfigs[paths[0]].Clone()
			}
			client, address, err := get([]string{address})
			if err != nil {
				t.Fatal(err)
			}
			batch = append(batch, &pnfsRead{ds: client, endpoint: address, paths: []string{address}, handle: []byte("other"), limit: 4})
		}
	}
	if flex {
		for _, r := range batch {
			r.flex = component(r.paths)
		}
	}
	recovery := recoverRead
	if mode == "default" {
		recovery = nil
	}
	err = readPNFSBatchRecover(ctx, batch, bytes.Repeat([]byte{7}, 16), usable, recovery)
	if mode == "recover" || mode == "parallel" || mode == "minor-id" {
		if err != nil || string(batch[0].data) != "data" || reads.Load() != 2 {
			t.Fatal(err, reads.Load())
		}
		for _, other := range batch[1:] {
			if string(other.data) != "keep" {
				t.Fatal("healthy parallel result lost")
			}
		}
		// Future stripes use the replacement; another recovery of this identity
		// is refused before connecting or creating a third session.
		cached, path, err := get(paths)
		if err != nil || cached != batch[0].ds || path != paths[1] {
			t.Fatal("replacement not reused", err)
		}
		if err := recoverRead(batch[0]); err == nil {
			t.Fatal("unbounded failover")
		}
	} else if err == nil {
		t.Fatal("unsafe success", mode)
	}
	wantReads, wantCreates := int32(1), 1
	if mode == "recover" || mode == "parallel" || mode == "minor-id" || mode == "second-loss" {
		wantReads = 2
		wantCreates = 2
	}
	if mode == "create-lost" {
		wantCreates = 2
	}
	state.mu.Lock()
	creates := len(state.requests)
	state.mu.Unlock()
	if reads.Load() != wantReads || creates != wantCreates {
		t.Fatalf("READ=%d CREATE_SESSION=%d; want %d/%d", reads.Load(), creates, wantReads, wantCreates)
	}
}
