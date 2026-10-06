package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// Independent NFS reply-cache oracle behind real MIT GSS and optional TLS.
// A retransmission returns the saved compound, never executes WRITE again.
type cachedWritePeer struct {
	mu                                       sync.Mutex
	request, reply                           []byte
	session                                  []byte
	sequence                                 uint32
	creates, writes, commits, binds, replays int
	mode                                     string
	handle                                   string
	data                                     func(uint32, *decoder) (encoder, error)
	role                                     uint32
	other                                    func(uint32, *decoder) (encoder, error)
}

func (s *cachedWritePeer) client(t *testing.T, minor uint32) *Client {
	return scriptedClient(t, func(program, procedure uint32, d *decoder) (encoder, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if program != 100003 || procedure != 1 {
			return nil, errors.New("unexpected RPC")
		}
		request := bytes.Clone(d.b)
		d.str()
		if d.u32() != minor {
			return nil, errors.New("wrong minor")
		}
		count := d.u32()
		var body encoder
		cache := false
		for range count {
			code := d.u32()
			body.u32(code)
			body.u32(0)
			switch code {
			case 42:
				d.take(8)
				d.str()
				d.take(12)
				body.u64(123)
				body.u32(22)
				flags := uint32(0x40000)
				if s.role != 0 {
					flags = s.role
				}
				if s.creates > 0 {
					flags |= 0x80000000
				}
				body.u32(flags)
				body.u32(0)
				body.u64(1)
				owner := "ds"
				if s.handle != "" {
					owner += "-" + s.handle
				}
				if s.creates > 0 && s.mode == "wrong-owner" {
					owner = "other"
				}
				body.str(owner)
				body.str("scope")
				body.u32(0)
			case 43:
				if d.u64() != 123 || d.u32() != 22 || s.creates != 0 {
					return nil, errors.New("replacement CREATE_SESSION forbidden")
				}
				d.take(68)
				s.creates++
				e := createSequenceReply(22)
				s.session = bytes.Clone(e[:16])
				s.sequence = 1
				body = append(body, e...)
			case 41:
				if !bytes.Equal(d.take(16), s.session) || d.u32() != 1 || d.boolean() {
					return nil, errors.New("wrong original-session binding")
				}
				s.binds++
				body = append(body, s.session...)
				body.u32(1)
				body.u32(0)
			case 53:
				id, seq := d.take(16), d.u32()
				slot, highest, cached := d.u32(), d.u32(), d.boolean()
				if !bytes.Equal(id, s.session) || slot != 0 || highest != 0 || !cached && s.role == 0 {
					return nil, errors.New("wrong cached sequence")
				}
				if seq+1 == s.sequence {
					if !bytes.Equal(request, s.request) {
						return nil, errors.New("replay changed inner compound")
					}
					s.replays++
					if s.mode == "malformed" {
						return encoder{0}, nil
					}
					return bytes.Clone(s.reply), nil
				}
				if seq != s.sequence {
					return nil, errors.New("wrong new sequence")
				}
				s.sequence++
				cache = cached
				body = append(body, id...)
				body.u32(seq)
				for range 4 {
					body.u32(0)
				}
			case 22:
				want := s.handle
				if want == "" {
					want = "file"
				}
				if string(d.opaque(128)) != want {
					return nil, errors.New("changed filehandle")
				}
			case 38, 70:
				if s.data != nil {
					reply, err := s.data(code, d)
					if err != nil {
						return nil, err
					}
					s.writes++
					body = append(body, reply...)
					continue
				}
				if !bytes.Equal(d.take(16), bytes.Repeat([]byte{7}, 16)) || d.u64() != 123 || d.u32() != 2 || string(d.opaque(128)) != "data" {
					return nil, errors.New("changed WRITE")
				}
				s.writes++
				body.u32(4)
				body.u32(0)
				body = append(body, bytes.Repeat([]byte{8}, 8)...)
			case 5:
				if s.data != nil {
					reply, err := s.data(code, d)
					if err != nil {
						return nil, err
					}
					s.commits++
					body = append(body, reply...)
					continue
				}
				if d.u64() != 123 || d.u32() != 4 {
					return nil, errors.New("changed COMMIT")
				}
				s.commits++
				body = append(body, bytes.Repeat([]byte{8}, 8)...)
			case 44:
				d.take(16)
			case 58:
				d.u32()
			case 24:
			case 10:
				body.opaque([]byte("root"))
			default:
				if s.other != nil {
					payload, err := s.other(code, d)
					if err != nil {
						return nil, err
					}
					body = append(body, payload...)
					continue
				}
				return nil, fmt.Errorf("unexpected operation %d", code)
			}
		}
		if d.err != nil || len(d.b) != 0 {
			return nil, errors.New("invalid request body")
		}
		var e encoder
		e.u32(0)
		e.str("")
		e.u32(count)
		e = append(e, body...)
		if cache {
			s.request, s.reply = request, bytes.Clone(e)
		}
		return e, nil
	}, true)
}

func TestPNFSMITWriteFailover(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"write-loss", "commit-loss", "wrong-owner", "malformed", "second-loss"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%t/%s", minor, security, secure, mode), func(t *testing.T) {
						ctx := context.Background()
						cfg := pnfsMITConfig(t, security, "nfs/ds.nfs.test")
						cfg.Version = fmt.Sprintf("4.%d", minor)
						parent := &Client{config: &cfg, version: cfg.Version, ReadSize: 128, WriteSize: 128, security: security, principal: cfg.Kerberos.Principal}
						parent.v4 = &v4Client{c: parent, minor: minor, clientNonce: bytes.Repeat([]byte{6}, 16)}
						state := &cachedWritePeer{mode: mode}
						policies := map[string]*tls.Config{}
						auth := map[string]Config{}
						var paths []string
						var policy TLSConfig
						var peerTLS func(int) *tls.Config
						if secure {
							policy, peerTLS = pnfsTLSFixture(t, "data")
							cfg.TLS = policy
						}
						for i := 0; i < 2; i++ {
							peer := state.client(t, minor)
							options := mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]}
							if secure {
								options.server, options.client = peerTLS(i), policy
							}
							if i == 0 {
								options.dropDataReply = 3
								if mode == "commit-loss" {
									options.dropDataReply = 4
								}
							}
							if i == 1 && mode == "second-loss" {
								options.dropDataReply = 3
							}
							endpoint := pnfsMITEndpoint(t, peer.nfs.conn, nil, options)
							paths = append(paths, endpoint)
							auth[endpoint] = cfg
							if secure {
								tc := cfg
								tc.TLS.ServerName = "127.0.0.1"
								p, err := tc.tlsConfig()
								if err != nil {
									t.Fatal(err)
								}
								policies[endpoint] = p
							}
						}
						usable := func() error { return nil }
						get, _, closePool := parent.pnfsDataServers(ctx, policies, auth, usable, false)
						defer closePool()
						ds, endpoint, err := get(paths)
						if err != nil {
							t.Fatal(err)
						}
						if err := parent.enablePNFSWriteRecovery(ds, paths, endpoint, policies, auth, usable); err != nil {
							t.Fatal(err)
						}
						w := &flexWrite{ds: ds, component: &flexDS{major: 4, minor: minor, state: bytes.Repeat([]byte{7}, 16), handle: []byte("file")}}
						err = writeFlexPiece(ctx, w, 123, []byte("data"), func(bool) error { return nil })
						state.mu.Lock()
						defer state.mu.Unlock()
						success := mode == "write-loss" || mode == "commit-loss"
						if (err == nil) != success || state.creates != 1 || state.writes != 1 {
							t.Fatalf("err=%v creates=%d writes=%d replays=%d", err, state.creates, state.writes, state.replays)
						}
						if success && (state.commits != 1 || state.binds != 1 || state.replays != 1 || ds.v4.stateLost.Load()) {
							t.Fatalf("unsafe recovery counts commit=%d bind=%d replay=%d lost=%v", state.commits, state.binds, state.replays, ds.v4.stateLost.Load())
						}
						if !success && !ds.v4.stateLost.Load() {
							t.Fatal("unknown mutation not quarantined")
						}
					})
				}
			}
		}
	}
}
