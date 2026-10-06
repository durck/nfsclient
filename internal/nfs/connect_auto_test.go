package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	bgss "nfsclient/internal/krbgss"
	"nfsclient/internal/testutil/kdcfixture"
)

// Real encrypted service tickets, minted only inside this test, exercise GSS
// mutual authentication and integrity/privacy with a loopback KDC protocol peer and no ambient identity.
func autoCredentials(t *testing.T) (KerberosConfig, string) {
	t.Helper()
	dir := t.TempDir()
	kt := keytab.New()
	now := time.Now().UTC().Truncate(time.Second)
	if err := kt.AddEntry("nfs/server.nfs.test", "NFS.TEST", "test-only-auto-ticket", now, 1, 18); err != nil {
		t.Fatal(err)
	}
	ticket, key, err := messages.NewTicket(types.NewPrincipalName(1, "root"), "NFS.TEST", types.NewPrincipalName(2, "nfs/server.nfs.test"), "NFS.TEST", types.NewKrbFlags(), kt, 18, 1, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	kdc := kdcfixture.Start(t, func(_ string, wire []byte) []byte {
		var req messages.TGSReq
		if err := req.Unmarshal(wire); err != nil {
			t.Error(err)
			return nil
		}
		if req.ReqBody.SName.PrincipalNameString() != "nfs/server.nfs.test" {
			t.Error("SPN changed")
			return nil
		}
		part := messages.EncKDCRepPart{Key: key, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now.Add(-time.Minute), StartTime: now.Add(-time.Minute), EndTime: now.Add(time.Hour), RenewTill: now.Add(time.Hour), SRealm: "NFS.TEST", SName: ticket.SName}
		plain, err := part.Marshal()
		if err != nil {
			t.Error(err)
			return nil
		}
		encrypted, err := crypto.GetEncryptedData(plain, types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
		if err != nil {
			t.Error(err)
			return nil
		}
		reply := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 13, CRealm: "NFS.TEST", CName: types.NewPrincipalName(1, "root"), Ticket: ticket, EncPart: encrypted}}
		out, err := reply.Marshal()
		if err != nil {
			t.Error(err)
			return nil
		}
		return out
	})
	b := closeRenewalCache(t, false)
	k := KerberosConfig{Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test", ConfigFile: filepath.Join(dir, "krb5.conf"), CCache: filepath.Join(dir, "test.ccache")}
	conf := fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n dns_lookup_kdc = false\n udp_preference_limit = 1\n[realms]\n NFS.TEST = {\n kdc = %s\n }\n[domain_realm]\n .nfs.test = NFS.TEST\n", kdc.Address)
	server := filepath.Join(dir, "server.keytab")
	kb, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string][]byte{k.ConfigFile: []byte(conf), k.CCache: b, server: kb} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return k, server
}

type autoPeer struct {
	tls                                    *tls.Config
	t                                      *testing.T
	keytab, target, mode                   string
	mu                                     sync.Mutex
	probes                                 []string
	versions                               []uint32
	init, destroy, closed, accepted, state int
	cancel                                 context.CancelFunc
}

func (p *autoPeer) serve(conn net.Conn) {
	defer conn.Close()
	defer func() { p.mu.Lock(); p.closed++; p.mu.Unlock() }()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	options := []bgss.Option[bgss.Acceptor]{bgss.WithKeytab[bgss.Acceptor](p.keytab)}
	if p.tls != nil {
		raw, err := readRecord(conn)
		if err != nil {
			return
		}
		d := &decoder{b: raw}
		xid := d.u32()
		for _, want := range []uint32{0, 2, nfsProgram, 4, 0, 7, 0, 0, 0} {
			if d.u32() != want {
				p.t.Error("credentials sent before TLS")
				return
			}
		}
		var r encoder
		for _, v := range []uint32{xid, 1, 0, 0} {
			r.u32(v)
		}
		r.str("STARTTLS")
		r.u32(0)
		if _, err = conn.Write(record(r, true)); err != nil {
			return
		}
		secured := tls.Server(conn, p.tls)
		if err := secured.Handshake(); err != nil {
			if p.mode != "tls-untrusted" {
				p.t.Error(err)
			}
			return
		}
		conn = secured
		binding, err := tlsGSSBinding(secured)
		if err != nil {
			p.t.Error(err)
			return
		}
		options = append(options, bgss.WithChannelBinding[bgss.Acceptor](binding))
	}
	a, err := bgss.NewAcceptor(options...)
	if err != nil {
		p.t.Error(err)
		return
	}
	defer a.Close()
	var highest uint32
	for {
		raw, err := readRecord(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				p.t.Error(err)
			}
			return
		}
		d := &decoder{b: raw}
		xid := d.u32()
		if d.u32() != 0 || d.u32() != 2 || d.u32() != nfsProgram {
			p.t.Error("unexpected RPC program")
			return
		}
		version, proc, flavor := d.u32(), d.u32(), d.u32()
		if flavor != 6 {
			p.t.Error("security downgrade")
			return
		}
		cred := &decoder{b: d.opaque(400)}
		signed := len(raw) - len(d.b)
		rv, control, seq, service := cred.u32(), cred.u32(), cred.u32(), cred.u32()
		handle := cred.opaque(380)
		vf, mic := d.u32(), d.opaque(400)
		if rv != 1 || cred.err != nil || len(cred.b) != 0 {
			p.t.Error("bad credential")
			return
		}
		var body encoder
		replySeq := seq
		if control == 1 {
			p.mu.Lock()
			p.init++
			p.versions = append(p.versions, version)
			p.mu.Unlock()
			if proc != 0 || seq != 0 || service != 1 || len(handle) != 0 || vf != 0 {
				p.t.Error("bad INIT")
				return
			}
			if p.mode == "rpc-denied" {
				var r encoder
				for _, v := range []uint32{xid, 1, 1, 1, 1} {
					r.u32(v)
				}
				conn.Write(record(r, true))
				continue
			}
			if p.mode == "rpc-unavailable" || p.mode == "truncated-mismatch" {
				var r encoder
				for _, v := range []uint32{xid, 1, 0, 0, 0} {
					r.u32(v)
				}
				if p.mode == "rpc-unavailable" {
					r.u32(1)
				} else {
					r.u32(2)
					r.u32(3) // Missing high bound is not a valid mismatch.
				}
				conn.Write(record(r, true))
				continue
			}
			if p.target == "3" || p.target == "2" {
				if version != uint32(p.target[0]-'0') {
					var r encoder
					for _, v := range []uint32{xid, 1, 0, 0, 0, 2, uint32(p.target[0] - '0'), uint32(p.target[0] - '0')} {
						r.u32(v)
					}
					conn.Write(record(r, true))
					continue
				}
			}
			token, more, err := a.Accept(d.opaque(1 << 20))
			if err != nil || more {
				p.t.Errorf("accept: %v more=%v", err, more)
				return
			}
			body.opaque([]byte("auto-context"))
			body.u32(0)
			body.u32(0)
			body.u32(64)
			body.opaque(token)
			replySeq = 64
		} else {
			if vf != 6 || !bytes.Equal(handle, []byte("auto-context")) || seq <= highest || a.VerifySignature(raw[:signed], mic) != nil {
				p.t.Error("invalid protected call")
				return
			}
			highest = seq
			if control == 3 {
				p.mu.Lock()
				p.destroy++
				p.mu.Unlock()
			} else if control == 0 {
				g := &rpcGSS{context: a, seq: seq, service: service}
				if err := g.unprotect(d); err != nil {
					p.t.Error(err)
					return
				}
				if version == 4 {
					d.str()
					minor, count := d.u32(), d.u32()
					selected := fmt.Sprintf("4.%d", minor)
					status := Status(0)
					if count == 0 {
						p.mu.Lock()
						p.probes = append(p.probes, selected)
						p.mu.Unlock()
						if p.mode == "cancel" {
							p.cancel()
							continue
						}
						if selected != p.target {
							status = 10021
						}
					} else {
						p.mu.Lock()
						p.state++
						p.mu.Unlock()
					}
					var ops encoder
					done := uint32(0)
					if status == 0 {
						for ; done < count; done++ {
							code := d.u32()
							var payload encoder
							if (p.mode == "late-mismatch" || p.mode == "denied") && code == 42 {
								status = 10021
								if p.mode == "denied" {
									status = 13
								}
								ops.u32(code)
								ops.u32(uint32(status))
								done++
								break
							}
							switch code {
							case 35:
								d.take(8)
								d.str()
								d.u32()
								d.str()
								d.str()
								d.u32()
								payload.u64(123)
								payload = append(payload, make([]byte, 8)...)
							case 36:
								d.take(16)
							case 30:
								d.u64()
							case 22:
								d.opaque(128)
							case 10:
								payload.opaque([]byte("root"))
							case 42, 43, 53, 58, 24, 44, 57, 9:
								var e error
								payload, status, e = (&offloadVerificationPeer{}).operation(code, d)
								if e != nil {
									p.t.Error(e)
									return
								}
							default:
								p.t.Errorf("unexpected operation/mutation %d", code)
								return
							}
							ops.u32(code)
							ops.u32(uint32(status))
							ops = append(ops, payload...)
						}
					}
					body.u32(uint32(status))
					body.str("")
					body.u32(done)
					body = append(body, ops...)
				} else if proc != 0 {
					p.t.Errorf("legacy mutation %d", proc)
					return
				}

				var e error
				body, e = g.protect(body)
				if e != nil {
					p.t.Error(e)
					return
				}
			} else {
				p.t.Error("unknown GSS procedure")
				return
			}
		}
		signature, err := a.MakeSignature(binary.BigEndian.AppendUint32(nil, replySeq))
		if err != nil {
			p.t.Error(err)
			return
		}
		if p.mode == "bad-mic" && control == 0 {
			signature[0] ^= 1
		}
		var reply encoder
		reply.u32(xid)
		reply.u32(1)
		reply.u32(0)
		reply.u32(6)
		reply.opaque(signature)
		reply.u32(0)
		reply = append(reply, body...)
		if _, err = conn.Write(record(reply, true)); err != nil {
			p.t.Error(err)
			return
		}
	}
}

func (p *autoPeer) listen() (int, func()) {
	p.t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		p.t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.accepted++
			p.mu.Unlock()
			wg.Add(1)
			go func() { defer wg.Done(); p.serve(c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close(); wg.Wait() }
}

func TestKerberosAutoProtocol(t *testing.T) {
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		for _, target := range []string{"4.2", "4.1", "4.0", "3", "2"} {
			t.Run(security+"/"+target, func(t *testing.T) {
				k, key := autoCredentials(t)
				p := &autoPeer{t: t, keytab: key, target: target}
				port, stop := p.listen()
				defer stop()
				cfg := Config{Host: "127.0.0.1", Version: "auto", Security: security, Kerberos: k, NFSPort: port, MountPort: port, Timeout: time.Second}
				c, err := Connect(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				if c.Version() != target || c.Identity() != "root@NFS.TEST ("+security+")" || c.config.Kerberos.SPN != k.SPN || c.config.Kerberos.CCache != k.CCache || c.config.Version != target {
					t.Error("negotiation changed selected profile")
				}
				c.Close()
				stop()
				p.mu.Lock()
				defer p.mu.Unlock()
				want := []string{"4.2"}
				if target == "4.1" {
					want = append(want, "4.1")
				}
				if target == "4.0" {
					want = append(want, "4.1", "4.0")
				}
				if target == "3" || target == "2" {
					want = nil
				}
				if !reflect.DeepEqual(p.probes, want) {
					t.Errorf("probes %v want %v", p.probes, want)
				}
				wantVersions := []uint32{4}
				switch target {
				case "4.1":
					wantVersions = []uint32{4, 4}
				case "4.0":
					wantVersions = []uint32{4, 4, 4}
				case "3":
					wantVersions = []uint32{4, 4, 4, 3}
				case "2":
					wantVersions = []uint32{4, 4, 4, 3, 2}
				}
				if !reflect.DeepEqual(p.versions, wantVersions) || p.closed != p.accepted {
					t.Errorf("attempt order/cleanup: versions=%v want=%v closed=%d accepted=%d", p.versions, wantVersions, p.closed, p.accepted)
				}
				// Successful minor-version probes all destroy their GSS context; program
				// mismatches during INIT never created one.
				contexts := len(want)
				if contexts == 0 {
					contexts = 1
				}
				if p.destroy != contexts {
					t.Errorf("destroyed %d contexts want %d", p.destroy, contexts)
				}
			})
		}
	}
}

func TestKerberosAutoStopsAndCleansUp(t *testing.T) {
	for _, mode := range []string{"denied", "rpc-denied", "rpc-unavailable", "truncated-mismatch", "bad-mic", "cancel", "late-mismatch", "credentials"} {
		t.Run(mode, func(t *testing.T) {
			k, key := autoCredentials(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &autoPeer{t: t, keytab: key, target: "4.2", mode: mode, cancel: cancel}
			port, stop := p.listen()
			if mode == "credentials" {
				k.CCache = filepath.Join(t.TempDir(), "missing.ccache")
			}
			c, err := Connect(ctx, Config{Host: "127.0.0.1", Version: "auto", Security: "krb5p", Kerberos: k, NFSPort: port, MountPort: port, Timeout: time.Second})
			if c != nil {
				c.Close()
			}
			stop()
			if err == nil {
				t.Fatal("security failure accepted")
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Errorf("lost cancellation: %v", err)
			}
			if mode == "denied" && !errors.Is(err, Status(13)) {
				t.Errorf("lost authorization refusal: %v", err)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.accepted != 1 || p.closed != 1 {
				t.Errorf("failure retried or leaked transport: accepted=%d closed=%d", p.accepted, p.closed)
			}
			if mode != "late-mismatch" && mode != "denied" && p.state != 0 {
				t.Errorf("failed negotiation created state: %d", p.state)
			}
			if (mode == "late-mismatch" || mode == "denied") && p.state != 1 {
				t.Errorf("initialization replayed: %d requests", p.state)
			}
			if (mode == "denied" || mode == "late-mismatch") && p.destroy != 1 {
				t.Errorf("GSS context not destroyed: %d", p.destroy)
			}
		})
	}
}

// Bridge datagrams to the same record peer; each source address owns a fresh
// acceptor and context, just as each TCP connection does.
func (p *autoPeer) listenUDP() (int, func()) {
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		p.t.Fatal(err)
	}
	var wg sync.WaitGroup
	peers := map[string]net.Conn{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			for _, c := range peers {
				c.Close()
			}
		}()
		buf := make([]byte, 65536)
		for {
			n, addr, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c, ok := peers[addr.String()]
			if !ok {
				bridge, server := net.Pipe()
				c = bridge
				peers[addr.String()] = c
				p.mu.Lock()
				p.accepted++
				p.mu.Unlock()
				wg.Add(2)
				go func() { defer wg.Done(); p.serve(server) }()
				go func() {
					defer wg.Done()
					for {
						b, e := readRecord(bridge)
						if e != nil {
							return
						}
						if _, e = u.WriteToUDP(b, addr); e != nil {
							return
						}
					}
				}()
			}
			if _, err = c.Write(record(buf[:n], true)); err != nil {
				return
			}
		}
	}()
	return u.LocalAddr().(*net.UDPAddr).Port, func() { u.Close(); wg.Wait() }
}

func TestKerberosAutoUDP(t *testing.T) {
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		for _, target := range []string{"3", "2"} {
			t.Run(security+"/"+target, func(t *testing.T) {
				k, key := autoCredentials(t)
				p := &autoPeer{t: t, keytab: key, target: target}
				port, stop := p.listenUDP()
				defer stop()
				c, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "auto", Transport: "udp", Security: security, Kerberos: k, NFSPort: port, MountPort: port, Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				if c.Version() != target || c.Transport() != "udp" || c.Security() != security {
					t.Error("changed UDP security profile")
				}
				c.Close()
				stop()
				p.mu.Lock()
				defer p.mu.Unlock()
				want := 1
				if target == "2" {
					want = 2
				}
				if p.init != want || p.destroy != 1 || len(p.probes) != 0 {
					t.Errorf("wrong UDP negotiation init=%d destroy=%d probes=%v", p.init, p.destroy, p.probes)
				}
			})
		}
	}
}

func TestKerberosAutoTLS(t *testing.T) {
	for _, mode := range []string{"tls-client-cert", "tls-untrusted"} {
		t.Run(mode, func(t *testing.T) {
			k, key := autoCredentials(t)
			policy, server := pnfsTLSFixture(t, mode)
			policy.ServerName = "ds-0.test"
			p := &autoPeer{t: t, keytab: key, target: "4.1", mode: mode, tls: server(0)}
			port, stop := p.listen()
			defer stop()
			c, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "auto", Security: "krb5p", Kerberos: k, TLS: policy, NFSPort: port, Timeout: time.Second})
			if mode == "tls-untrusted" {
				if err == nil {
					c.Close()
					t.Fatal("untrusted TLS accepted")
				}
				stop()
				p.mu.Lock()
				defer p.mu.Unlock()
				if p.accepted != 1 || p.init != 0 {
					t.Error("TLS trust failure retried or sent GSS")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Version() != "4.1" || !reflect.DeepEqual(c.config.TLS, policy) {
				t.Error("TLS profile lost across fallback")
			}
			c.Close()
			stop()
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.accepted != 2 || p.destroy != 2 {
				t.Errorf("TLS fallback cleanup: accepted=%d destroy=%d", p.accepted, p.destroy)
			}
		})
	}
}
