package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	bgss "nfs-viewer/internal/krbgss"
)

func TestPNFSMITSessionTrunk(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"round-robin", "parallel", "minor-id", "owner", "scope", "client-id", "unconfirmed", "spn", "service", "principal", "bind-status", "bind-session", "bind-direction", "bind-rdma", "bind-truncated", "bind-lost", "read-lost"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%v/%s", minor, security, secure, mode), func(t *testing.T) {
						runPNFSMITSessionTrunk(t, minor, security, secure, mode)
					})
				}
			}
		}
	}
}

func TestPNFSMITSessionTrunkPublic(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, transport := range []string{"", "tls-"} {
				for _, workers := range []int{1, 3} {
					for _, packing := range []string{"dense", "sparse-many"} {
						for _, mode := range []string{"data", "holes"} {
							t.Run(fmt.Sprintf("4.%d/%s/%s/%d/%s/%s", minor, security, transport, workers, packing, mode), func(t *testing.T) {
								runPNFSStripedRead(t, minor, "gss-"+security+"-"+transport+"trunk-"+packing, 128, mode, workers)
							})
						}
					}
				}
			}
		}
	}
}

func TestPNFSSessionTrunkOptions(t *testing.T) {
	for _, security := range []string{"", "sys", "krb5"} {
		c := &Client{config: &Config{Security: security}, nfs: &rpcClient{}}
		if _, err := c.pnfsKerberosConfigs(PNFSOptions{SessionTrunking: true}); err == nil {
			t.Fatal("unprotected trunk accepted", security)
		}
	}
	c := &Client{}
	if c.ValidatePNFSWriteOptions(PNFSOptions{SessionTrunking: true}) == nil {
		t.Fatal("trunk accepted for write preflight")
	}
	if _, err := c.WritePNFSRangeFromProgress(context.Background(), nil, 0, 1, bytes.NewReader([]byte{1}), PNFSOptions{SessionTrunking: true}, nil); err == nil {
		t.Fatal("trunk accepted for writes")
	}
	for _, mode := range []string{"ok", "flex", "path", "mirror", "refresh"} {
		t.Run(mode, func(t *testing.T) {
			o := PNFSOptions{SessionTrunking: true, DataServers: map[string]string{"192.0.2.1:2049": "192.0.2.1:2049"}}
			switch mode {
			case "flex":
				o.Layout = "flex"
			case "path":
				o.ReadFailover = true
			case "mirror":
				o.MirrorFailover = true
			case "refresh":
				o.RefreshDevices = true
			}
			if _, err := validatePNFSOptions(o); (err == nil) != (mode == "ok") {
				t.Fatal("unexpected option validation", err)
			}
		})
	}
}

func runPNFSMITSessionTrunk(t *testing.T, minor uint32, security string, secure bool, mode string) {
	ctx := context.Background()
	cfg := pnfsMITConfig(t, security, "nfs/ds.nfs.test")
	cfg.Version = fmt.Sprintf("4.%d", minor)
	parent := &Client{config: &cfg, version: cfg.Version, ReadSize: 128, WriteSize: 128, security: security, principal: cfg.Kerberos.Principal}
	parent.v4 = &v4Client{c: parent, minor: minor, clientNonce: bytes.Repeat([]byte{6}, 16)}
	s := &createSequenceServer{next: 22, clientID: 123, owner: "ds", scope: "scope", trunk: true}
	if strings.HasPrefix(mode, "bind-") {
		s.trunkFailure = strings.TrimPrefix(mode, "bind-")
	}
	var reads [2]atomic.Int32
	paths := []string{}
	auth := map[string]Config{}
	tlsConfigs := map[string]*tls.Config{}
	var policy TLSConfig
	var serverTLS func(int) *tls.Config
	if secure {
		policy, serverTLS = pnfsTLSFixture(t, "data")
		cfg.TLS = policy
	}
	for index := range 2 {
		peer := s.peer(t, minor, parent.v4, 0x40000, func(code uint32, d *decoder) (encoder, Status, error) {
			if code != 25 || !bytes.Equal(d.take(16), append(make([]byte, 4), bytes.Repeat([]byte{7}, 12)...)) {
				return nil, 0, errors.New("trunk changed READ state")
			}
			offset, count := d.u64(), d.u32()
			if offset > 15 || count != 1 {
				return nil, 0, errors.New("trunk changed READ range")
			}
			reads[index].Add(1)
			var e encoder
			e.u32(0)
			e.opaque([]byte{byte('a' + offset)})
			return e, 0, nil
		})
		options := mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]}
		if secure {
			options.server, options.client = serverTLS(index), policy
		}
		if index == 1 && mode == "bind-lost" {
			options.dropDataReply = 2
		}
		if index == 1 && mode == "read-lost" {
			options.dropDataReply = 3
		}
		requests := 0
		hook := func(_ net.Conn, _ *bgss.Acceptor) error {
			requests++
			if index == 1 && requests == 1 {
				s.mu.Lock()
				defer s.mu.Unlock()
				switch mode {
				case "minor-id":
					s.minorID++
				case "owner":
					s.owner = "different"
				case "scope":
					s.scope = "different"
				case "client-id":
					s.clientID++
				case "unconfirmed":
					s.confirmed = false
				}
			}
			return nil
		}
		endpoint := pnfsMITEndpoint(t, peer.c.nfs.conn, hook, options)
		paths = append(paths, endpoint)
		auth[endpoint] = cfg
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
	other := auth[paths[1]]
	switch mode {
	case "spn":
		other.Kerberos.SPN = "nfs/server.nfs.test"
	case "service":
		other.Security = "krb5"
	case "principal":
		other.Kerberos.Principal = "other@NFS.TEST"
	}
	auth[paths[1]] = other
	usable := func() error { return nil }
	get, _, closePool := parent.pnfsDataServers(ctx, tlsConfigs, auth, usable, true)
	defer closePool()
	first, path, err := get(paths)
	if mode != "round-robin" && mode != "parallel" && mode != "read-lost" {
		if err == nil || reads[0].Load()+reads[1].Load() != 0 {
			t.Fatal("invalid trunk admitted", err)
		}
		if len(s.requests) > 1 {
			t.Fatal("binding refusal fell back to CREATE_SESSION")
		}
		return
	}
	if err != nil || path != paths[0] {
		t.Fatal("trunk setup failed", err)
	}
	for offset := uint64(0); offset < 8; {
		var batch []*pnfsRead
		width := 1
		if mode == "parallel" {
			width = 2
		}
		for range width {
			ds, endpoint := first, path
			if offset != 0 {
				ds, endpoint, err = get(paths)
				if err != nil {
					t.Fatal(err)
				}
			}
			if endpoint != paths[offset%2] {
				t.Fatal("trunk did not rotate approved connections")
			}
			batch = append(batch, &pnfsRead{ds: ds, endpoint: endpoint, handle: []byte("file"), offset: offset, limit: 1})
			offset++
		}
		err = readPNFSBatch(ctx, batch, bytes.Repeat([]byte{7}, 16), usable)
		if mode == "read-lost" && offset == 2 {
			if err == nil || !first.v4.stateLost.Load() {
				t.Fatal("lost alias reply did not poison shared slot", err)
			}
			if err := readPNFSBatch(ctx, []*pnfsRead{{ds: first, handle: []byte("file"), limit: 1}}, bytes.Repeat([]byte{7}, 16), usable); err == nil {
				t.Fatal("uncertain shared slot reused")
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range batch {
			if !bytes.Equal(r.data, []byte{byte('a' + r.offset)}) {
				t.Fatal("trunk changed returned bytes")
			}
		}
	}
	closePool()
	if len(s.requests) != 1 || s.bindings != 1 || s.destroys != 1 {
		t.Fatal("session ownership changed", s.requests, s.bindings, s.destroys)
	}
	wantReads := int32(4)
	if mode == "read-lost" {
		wantReads = 1
	}
	if reads[0].Load() != wantReads || reads[1].Load() != wantReads {
		t.Fatal("lost reply replayed or a trunk path unused", reads[0].Load(), reads[1].Load())
	}
}
