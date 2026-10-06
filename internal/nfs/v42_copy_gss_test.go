package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bgss "nfs-viewer/internal/krbgss"
)

// This oracle checks the wire independently of the client's credential and
// privilege encoders. The optional MIT mode uses actual ticket-derived keys;
// the filesystem operations remain scripted in both modes.
type copyGSSOracle struct {
	mu                                                             sync.Mutex
	secret                                                         []byte
	creates, destroys, notifies, copies, revokes, cancels, commits atomic.Int32
}

func copyGSSWrap(t *testing.T, c *Client, role, mode string, mit bool, oracle *copyGSSOracle, callback bool) {
	t.Helper()
	encrypted := strings.HasPrefix(mode, "tls-")
	mode = strings.TrimPrefix(mode, "tls-")
	upstream := c.nfs.conn
	client, server := net.Pipe()
	parentHandle := []byte(role + "-parent")
	childHandle := []byte(role + "-child")
	var mechanism micContext = callbackTestPrivacy{}
	cfg := Config{Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: 3 * time.Second, Kerberos: KerberosConfig{RPCVersion: 3, Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
	if mit {
		cfg = pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
		cfg.Version, cfg.PNFS, cfg.Kerberos.RPCVersion = "4.2", false, 3
		if !encrypted {
			acceptor, err := bgss.NewAcceptor(bgss.WithKeytab[bgss.Acceptor](os.Getenv("NFS_VIEWER_PNFS_GSS_SERVER_KEYTAB")))
			if err != nil {
				t.Fatal(err)
			}
			mechanism = acceptor
			t.Cleanup(func() { _ = acceptor.Close() })
		}
	}
	var serverTLS *tls.Config
	if encrypted {
		policy, serverPolicy := pnfsTLSFixture(t, "tls-client-cert")
		policy.ServerName = "ds-0.test"
		cfg.TLS, serverTLS = policy, serverPolicy(0)
	}
	c.config, c.security, c.principal = &cfg, "krb5p", cfg.Kerberos.Principal
	c.nfs = &rpcClient{conn: client, timeout: cfg.Timeout}
	if !mit {
		c.nfs.gss = &rpcGSS{context: mechanism, handle: parentHandle, service: 3, rpcVersion: 3, window: 64, established: true, nfsVersion: 4, expiry: time.Now().Add(time.Hour), renewAt: time.Now().Add(50 * time.Minute)}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		defer upstream.Close()
		if encrypted {
			request, err := readRecord(server)
			if err != nil {
				t.Error(err)
				return
			}
			d := &decoder{b: request}
			xid := d.u32()
			for _, want := range []uint32{0, 2, nfsProgram, 4, 0, 7, 0, 0, 0} {
				if d.u32() != want {
					t.Error("GSS before TLS")
					return
				}
			}
			if d.err != nil || len(d.b) != 0 {
				t.Error("bad AUTH_TLS framing")
				return
			}
			var reply encoder
			reply.u32(xid)
			reply.u32(1)
			reply.u32(0)
			reply.u32(0)
			reply.str("STARTTLS")
			reply.u32(0)
			if _, err = server.Write(record(reply, true)); err != nil {
				t.Error(err)
				return
			}
			secured := tls.Server(server, serverTLS)
			handshakeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err = secured.HandshakeContext(handshakeCtx)
			cancel()
			if err != nil {
				t.Error(err)
				return
			}
			server = secured
			binding, err := tlsGSSBinding(secured)
			if err != nil {
				t.Error(err)
				return
			}
			acceptor, err := bgss.NewAcceptor(bgss.WithKeytab[bgss.Acceptor](os.Getenv("NFS_VIEWER_PNFS_GSS_SERVER_KEYTAB")), bgss.WithChannelBinding[bgss.Acceptor](binding))
			if err != nil {
				t.Error(err)
				return
			}
			mechanism = acceptor
			defer acceptor.Close()
		}
		highest := map[string]uint32{string(parentHandle): 0}
		var callbackSeq uint32
		for {
			raw, err := readRecord(server)
			if err != nil {
				return
			}
			d := &decoder{b: raw}
			xid := d.u32()
			if d.u32() != 0 || d.u32() != 2 || d.u32() != nfsProgram || d.u32() != 4 {
				t.Error("invalid v3 RPC header")
				return
			}
			proc := d.u32()
			if d.u32() != 6 {
				t.Error("security fallback")
				return
			}
			a := &decoder{b: d.opaque(400)}
			signedSize := len(raw) - len(d.b)
			version, control, seq, service := a.u32(), a.u32(), a.u32(), a.u32()
			handle := bytes.Clone(a.opaque(380))
			flavor, mic := d.u32(), d.opaque(400)
			if version != 3 || a.err != nil || len(a.b) != 0 || d.err != nil {
				t.Error("invalid v3 credential")
				return
			}
			var body encoder
			if control == 1 && mit {
				if seq != 0 || proc != 0 || service != 1 || len(handle) != 0 || flavor != 0 || len(mic) != 0 {
					t.Error("invalid v3 INIT")
					return
				}
				token := d.opaque(1 << 20)
				acceptor := mechanism.(*bgss.Acceptor)
				reply, more, err := acceptor.Accept(token)
				if err != nil || more || d.err != nil || len(d.b) != 0 {
					t.Errorf("MIT INIT: %v", err)
					return
				}
				body.opaque(parentHandle)
				body.u32(0)
				body.u32(0)
				body.u32(64)
				body.opaque(reply)
			} else {
				previous, known := highest[string(handle)]
				if !known || seq <= previous || seq >= 0x80000000 || flavor != 6 || mechanism.VerifySignature(raw[:signedSize], mic) != nil {
					t.Error("invalid handle, sequence or request MIC")
					return
				}
				highest[string(handle)] = seq
				if control == 3 {
					if proc != 0 || service != 1 || len(d.b) != 0 {
						t.Error("invalid DESTROY")
						return
					}
					if bytes.Equal(handle, childHandle) {
						oracle.destroys.Add(1)
						if mode == role+"-destroy-lost" {
							return
						}
						delete(highest, string(handle))
					} else if len(highest) != 1 {
						t.Error("parent destroyed before its child")
						return
					}
				} else {
					if service != 3 {
						t.Error("COPY privilege privacy downgrade")
						return
					}
					token := d.opaque(maxRecord)
					plain, err := mechanism.(interface{ Unseal([]byte) ([]byte, error) }).Unseal(token)
					if err != nil || d.err != nil || len(d.b) != 0 || len(plain) < 4 || binary.BigEndian.Uint32(plain) != seq {
						t.Errorf("bad v3 privacy body: %v", err)
						return
					}
					p := &decoder{b: plain[4:]}
					if control == 5 {
						oracle.creates.Add(1)
						if !bytes.Equal(handle, parentHandle) || proc != 0 || p.u32() != 0 || p.u32() != 0 || p.u32() != 1 || p.u32() != 1 {
							t.Error("invalid CREATE assertion framing")
							return
						}
						name, privilege := p.str(), bytes.Clone(p.opaque(32768))
						want := "copy_from_auth"
						if role == "destination" {
							want = "copy_to_auth"
						}
						q := &decoder{b: privilege}
						secret := q.opaque(32)
						if len(secret) != 32 || bytes.Contains(raw, secret) || name != want || p.err != nil || len(p.b) != 0 {
							t.Error("invalid or exposed privilege")
							return
						}
						oracle.mu.Lock()
						if role == "source" {
							oracle.secret = bytes.Clone(secret)
						} else if !bytes.Equal(secret, oracle.secret) {
							t.Error("different source/destination secrets")
						}
						oracle.mu.Unlock()
						address := "192.0.2.2.8.1"
						if role == "destination" {
							if q.u32() != 1 {
								t.Error("changed source count")
								return
							}
							address = "192.0.2.1.8.1"
						}
						if q.u32() != 3 || q.str() != "tcp" || q.str() != address || q.str() != "root@nfs.test" || q.err != nil || len(q.b) != 0 {
							t.Error("changed privilege binding")
							return
						}
						if mode == role+"-create-lost" {
							return
						}
						highest[string(childHandle)] = 0
						returned := childHandle
						if mode == role+"-empty-handle" {
							returned = nil
						}
						if mode == role+"-parent-handle" {
							returned = parentHandle
						}
						body.opaque(returned)
						body.u32(0)
						body.u32(0)
						body.u32(1)
						body.u32(1)
						body.str(name)
						if mode == role+"-mapped-privilege" {
							privilege[len(privilege)-1] ^= 1
						}
						body.opaque(privilege)
						if mode == role+"-truncated-create" {
							body = body[:len(body)-1]
						}
					} else if control == 0 {
						if proc != 1 {
							t.Error("unexpected data procedure")
							return
						}
						compound := bytes.Clone(p.b)
						// COMMIT and file state traffic use the parent; all copy-related
						// operations use the scoped child, including STATUS/CANCEL.
						p.str()
						p.u32()
						count := p.u32()
						code := uint32(0)
						for range count {
							code = p.u32()
							if code == 53 {
								p.take(32)
							} else if code == 22 {
								p.opaque(128)
							} else if code != 32 {
								break
							}
						}
						copyOp := code == 60 || code == 61 || code == 66 || code == 67
						if copyOp != bytes.Equal(handle, childHandle) {
							t.Errorf("wrong context for operation %d", code)
							return
						}
						plainRPC := append(encoder(nil), raw[:24]...)
						for range 4 {
							plainRPC.u32(0)
						}
						plainRPC = append(plainRPC, compound...)
						if _, err = upstream.Write(record(plainRPC, true)); err != nil {
							t.Error(err)
							return
						}
						reply, err := readRecord(upstream)
						if err != nil || len(reply) < 24 {
							t.Errorf("scripted response: %v", err)
							return
						}
						body = bytes.Clone(reply[24:])
						if code == 60 && mode == "copy-lost" || code == 61 && mode == "notify-lost" {
							return
						}
						if callback && (code == 60 || code == 67) {
							callbackSeq++
							g := c.v4.recall.gss
							serverGSS := &gssBackchannel{context: mechanism, handle: g.handle, service: 3, rpcVersion: 3}
							callbackRaw := gssProtectCallback(t, serverGSS, offloadCallback(c.v4.recall, callbackSeq, []byte("destination"), bytes.Repeat([]byte{5}, 16), offloadReply{count: 8192, stable: 2, verifier: []byte("verifier")}), callbackSeq)
							if mode == "callback-tamper" {
								callbackRaw[len(callbackRaw)-1] ^= 1
							}
							if _, err = server.Write(record(callbackRaw, true)); err != nil {
								return
							}
							callbackReply, err := readRecord(server)
							if mode == "callback-tamper" {
								return
							}
							if err != nil {
								t.Error(err)
								return
							}
							x := &decoder{b: callbackReply}
							x.take(12)
							flavor := x.u32()
							verifier := x.opaque(400)
							y := &decoder{b: callbackRaw}
							y.take(24)
							y.u32()
							y.opaque(400)
							signed := bytes.Clone(callbackRaw[:len(callbackRaw)-len(y.b)])
							binary.BigEndian.PutUint32(signed[4:8], 1)
							if flavor != 6 || mechanism.VerifySignature(signed, verifier) != nil || x.u32() != 0 {
								t.Error("unbound v3 callback reply")
								return
							}
						}
					} else {
						t.Errorf("unexpected v3 control %d", control)
						return
					}
					wrapped, err := mechanism.(interface{ Seal([]byte) ([]byte, error) }).Seal(append(binary.BigEndian.AppendUint32(nil, seq), body...))
					if err != nil {
						t.Error(err)
						return
					}
					body = nil
					body.opaque(wrapped)
				}
			}
			signed := bytes.Clone(raw[:signedSize])
			binary.BigEndian.PutUint32(signed[4:8], 1)
			if control == 5 && mode == role+"-v1-verifier" {
				signed = binary.BigEndian.AppendUint32(nil, seq)
			}
			if control == 0 && mode == "wrong-handle-verifier" && bytes.Equal(handle, childHandle) {
				signed[len(signed)-1] ^= 1
			}
			verifier, err := mechanism.MakeSignature(signed)
			if err != nil {
				t.Error(err)
				return
			}
			var reply encoder
			reply.u32(xid)
			reply.u32(1)
			reply.u32(0)
			reply.u32(6)
			reply.opaque(verifier)
			reply.u32(0)
			reply = append(reply, body...)
			if _, err = server.Write(record(reply, true)); err != nil {
				return
			}
			if control == 3 && bytes.Equal(handle, parentHandle) {
				return
			}
		}
	}()
	t.Cleanup(func() { client.Close(); <-done })
	if encrypted {
		policy, err := cfg.tlsConfig()
		if err != nil {
			t.Fatal(err)
		}
		if err = c.nfs.startTLS(context.Background(), nfsProgram, 4, policy); err != nil {
			t.Fatal(err)
		}
	}
	if mit {
		if err := c.authenticateKerberos(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			c.nfs.destroyKerberos(context.Background())
			if c.closeKerberos != nil {
				c.closeKerberos()
			}
		})
	}
	if role == "destination" {
		c.v4.recall = &layoutRecall{session: bytes.Repeat([]byte{9}, 16), minor: 2, offloadEnabled: true}
		g, err := newGSSBackchannel(c.nfs.gss)
		if err != nil {
			t.Fatal(err)
		}
		c.v4.recall.gss = g
		c.nfs.pinnedBackchannelGSS = true
		c.nfs.duplex = startDuplex(c.nfs, func(raw []byte) ([]byte, error) { return g.callback(raw, c.v4.recall) })
	}
}

func TestCopyFromGSS(t *testing.T) { runCopyFromGSS(t, false, false) }
func TestCopyFromMIT(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	runCopyFromGSS(t, true, false)
}

func TestCopyFromMITTLS(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	runCopyFromGSS(t, true, true)
}

func runCopyFromGSS(t *testing.T, mit, encrypted bool, persistent ...bool) {
	for _, mode := range []string{"sync", "unstable", "async", "cancel", "notify-denied", "copy-denied", "unapproved", "copy-lost", "notify-lost", "callback-tamper", "wrong-handle-verifier", "source-create-lost", "destination-create-lost", "source-empty-handle", "source-parent-handle", "source-mapped-privilege", "destination-mapped-privilege", "source-truncated-create", "source-v1-verifier", "destination-v1-verifier", "source-destroy-lost", "destination-destroy-lost"} {
		t.Run(mode, func(t *testing.T) {
			o := &copyGSSOracle{}
			token, job := bytes.Repeat([]byte{4}, 16), bytes.Repeat([]byte{5}, 16)
			var locations encoder
			locations.u32(1)
			locations = append(locations, copyNetaddr("192.0.2.1:2049")...)
			source := copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 61:
					o.notifies.Add(1)
					if mode == "notify-denied" {
						return nil, 13, nil
					}
					if !bytes.Equal(d.take(16), bytes.Repeat([]byte{7}, 16)) || !bytes.Equal(d.take(len(copyNetaddr("192.0.2.2:2049"))), copyNetaddr("192.0.2.2:2049")) {
						return nil, 0, errors.New("wrong notify binding")
					}
					e.u64(60)
					e.u32(0)
					e = append(e, token...)
					e = append(e, locations...)
				case 66:
					o.revokes.Add(1)
					if !bytes.Equal(d.take(16), token) {
						return nil, 0, errors.New("wrong revoked grant")
					}
				default:
					return nil, 0, fmt.Errorf("unexpected source op %d", code)
				}
				return e, 0, nil
			})
			destination := copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 32:
					return nil, 0, nil
				case 60:
					o.copies.Add(1)
					if !bytes.Equal(d.take(16), token) || !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) || d.u64() != 17 || d.u64() != 23 || d.u64() != 8192 || !d.boolean() || d.boolean() || !bytes.Equal(d.take(len(locations)), locations) {
						return nil, 0, errors.New("wrong COPY binding")
					}
					if mode == "copy-denied" {
						return nil, 13, nil
					}
					async := mode == "async" || mode == "cancel" || mode == "callback-tamper"
					if async {
						e.u32(1)
						e = append(e, job...)
					} else {
						e.u32(0)
					}
					e.u64(8192)
					if mode == "unstable" {
						e.u32(0)
					} else {
						e.u32(2)
					}
					e = append(e, []byte("verifier")...)
					e.u32(1)
					if async {
						e.u32(0)
					} else {
						e.u32(1)
					}
				case 66:
					o.cancels.Add(1)
					if !bytes.Equal(d.take(16), job) {
						return nil, 0, errors.New("wrong cancelled job")
					}
				case 67:
					if !bytes.Equal(d.take(16), job) {
						return nil, 0, errors.New("wrong status job")
					}
					e.u64(8192)
					e.u32(1)
					e.u32(0)
				case 5:
					o.commits.Add(1)
					if d.u64() != 23 || d.u32() != 0 {
						return nil, 0, errors.New("wrong durability range")
					}
					return encoder("verifier"), 0, nil
				default:
					return nil, 0, fmt.Errorf("unexpected destination op %d", code)
				}
				return e, 0, nil
			})
			wireMode := mode
			if encrypted {
				wireMode = "tls-" + mode
			}
			copyGSSWrap(t, source, "source", wireMode, mit, o, false)
			copyGSSWrap(t, destination, "destination", wireMode, mit, o, mode == "async" || mode == "callback-tamper")
			if len(persistent) > 0 && persistent[0] {
				destination.config.OffloadJournal = filepath.Join(t.TempDir(), "offload-state")
			}
			wait := time.Second
			if mode == "cancel" {
				wait = 50 * time.Millisecond
			}
			options := CopyFromOptions{Destination: "192.0.2.2:2049", SourceServers: []string{"192.0.2.1:2049"}, SourceSPN: "nfs/server.nfs.test", CopyUser: "root@nfs.test"}
			if encrypted {
				options.SourceTLSName = source.config.TLS.ServerName
			}
			if mode == "unapproved" {
				options.SourceServers = []string{"192.0.2.99:2049"}
			}
			n, err := destination.CopyRangeFrom(context.Background(), source, []byte("source"), []byte("destination"), 17, 23, 8192, wait, options)
			good := mode == "sync" || mode == "unstable" || mode == "async"
			if (err == nil) != good || good && n != 8192 {
				t.Fatal(n, err)
			}
			if len(persistent) > 0 && persistent[0] {
				r, readErr := InspectOffloadJournal(destination.config.OffloadJournal)
				if readErr != nil || r.Pending == good || r.SourceProfile != source.offloadProfile() || r.Offset != 23 || r.Length != 8192 || good && r.Outcome != "completed" {
					t.Fatal("protected crash evidence", r, readErr)
				}
				before := o.copies.Load()
				repeatErr := error(nil)
				if !good && !destination.v4.stateLost.Load() && !source.v4.stateLost.Load() {
					_, repeatErr = destination.CopyRangeFrom(context.Background(), source, []byte("source"), []byte("destination"), 17, 23, 8192, wait, options)
					if !errors.Is(repeatErr, ErrOffloadPending) || o.copies.Load() != before {
						t.Fatal("protected unknown operation replayed", repeatErr)
					}
				}
			}
			if o.notifies.Load() > 1 || o.copies.Load() > 1 || o.revokes.Load() > 1 || o.cancels.Load() > 1 || o.creates.Load() > 2 || o.destroys.Load() > 2 {
				t.Fatal("mutation replay")
			}
			if good && (o.creates.Load() != 2 || o.destroys.Load() != 2 || o.revokes.Load() != 1 || o.copies.Load() != 1) {
				t.Fatal("lost authorization cleanup")
			}
			if (o.commits.Load() == 1) != (mode == "unstable") || (o.cancels.Load() == 1) != (mode == "cancel") {
				t.Fatal("durability or cancellation", o.commits.Load(), o.cancels.Load(), err)
			}
			if strings.HasPrefix(mode, "source-") && mode != "source-destroy-lost" && o.copies.Load() != 0 || strings.HasPrefix(mode, "destination-") && mode != "destination-destroy-lost" && o.copies.Load() != 0 {
				t.Fatal("COPY after privilege refusal")
			}
			if strings.Contains(mode, "empty-handle") || strings.Contains(mode, "parent-handle") {
				if !source.nfs.closed || !strings.Contains(err.Error(), "unverified") {
					t.Fatal("unknown privilege left parent usable", err)
				}
			}
			if source.nfs.gss.parent != nil || destination.nfs.gss.parent != nil {
				t.Fatal("child context leaked into ordinary traffic")
			}
		})
	}
}

func TestCopyGSSParentGuards(t *testing.T) {
	for _, mode := range []string{"unbounded", "short-life", "v1", "integrity", "child", "closed", "expired", "sequence-exhausted"} {
		t.Run(mode, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			g := &rpcGSS{context: callbackTestPrivacy{}, handle: []byte("parent"), service: 3, rpcVersion: 3, established: true, renewAt: time.Now().Add(time.Hour), expiry: time.Now().Add(time.Hour)}
			c := &rpcClient{conn: a, gss: g}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch mode {
			case "unbounded":
				ctx = context.Background()
			case "short-life":
				g.renewAt = time.Now().Add(2 * time.Second)
			case "v1":
				g.rpcVersion = 1
			case "integrity":
				g.service = 2
			case "child":
				g.parent = &rpcGSS{}
			case "closed":
				c.closed = true
			case "expired":
				g.expiry = time.Now().Add(-time.Second)
			case "sequence-exhausted":
				g.seq = 0x7ffffffe
			}
			if _, release, err := c.pinCopyParent(ctx); err == nil {
				release()
				t.Fatal("unsafe parent accepted")
			}
		})
	}
}

func TestCopyFromGSSGuards(t *testing.T) {
	for _, mode := range []string{"principal", "source-v1", "source-integrity", "source-spn", "missing-username", "bad-username", "bad-tls-name", "source-short-life", "destination-short-life", "tls-mismatch", "tls-name-without-tls", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			o := &copyGSSOracle{}
			refuse := func(uint32, *decoder) (encoder, Status, error) {
				t.Error("NFS I/O before COPY preflight")
				return nil, 0, nil
			}
			source, destination := copyPeer(t, refuse), copyPeer(t, refuse)
			copyGSSWrap(t, source, "source", mode, false, o, false)
			copyGSSWrap(t, destination, "destination", mode, false, o, false)
			options := CopyFromOptions{Destination: "192.0.2.2:2049", SourceServers: []string{"192.0.2.1:2049"}, SourceSPN: "nfs/server.nfs.test", CopyUser: "root@nfs.test"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "principal":
				source.principal = "alice@NFS.TEST"
			case "source-v1":
				source.config.Kerberos.RPCVersion = 1
			case "source-integrity":
				source.security = "krb5i"
			case "source-spn":
				options.SourceSPN = "nfs/different.test"
			case "missing-username":
				options.CopyUser = ""
			case "bad-username":
				options.CopyUser = "root"
			case "bad-tls-name":
				options.SourceTLSName = "bad/name"
			case "source-short-life":
				source.nfs.gss.renewAt = time.Now().Add(2 * time.Second)
			case "destination-short-life":
				destination.nfs.gss.renewAt = time.Now().Add(2 * time.Second)
			case "tls-mismatch":
				destination.nfs.conn = tls.Client(destination.nfs.conn, &tls.Config{MinVersion: tls.VersionTLS13})
			case "tls-name-without-tls":
				options.SourceTLSName = "source.test"
			case "canceled":
				cancel()
			}
			_, err := destination.CopyRangeFrom(ctx, source, []byte("source"), []byte("destination"), 0, 0, 1, time.Second, options)
			if err == nil || o.creates.Load() != 0 || o.notifies.Load() != 0 || o.copies.Load() != 0 {
				t.Fatal("COPY preflight bypassed", err)
			}
		})
	}
}

func TestRPCGSSV3Config(t *testing.T) {
	for _, mode := range []string{"valid", "sys", "krb5i", "udp", "v41", "auto", "pnfs", "v2"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Version: "4.2", Transport: "tcp", Security: "krb5p", Kerberos: KerberosConfig{ConfigFile: "explicit.conf", Keytab: "explicit.keytab", Principal: "alice@NFS.TEST", SPN: "nfs/server.test", RPCVersion: 3}}
			switch mode {
			case "sys":
				cfg.Security = "sys"
			case "krb5i":
				cfg.Security = "krb5i"
			case "udp":
				cfg.Transport = "udp"
			case "v41":
				cfg.Version = "4.1"
			case "auto":
				cfg.Version = "auto"
			case "pnfs":
				cfg.PNFS = true
			case "v2":
				cfg.Kerberos.RPCVersion = 2
			}
			if err := validateSecurity(&cfg); (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
		})
	}
}

// The v3 verifier must distinguish equal sequence numbers on different handles
// and must not accept a v1 MIC or a different procedure/XID.
func TestGSSV3ReplyBinding(t *testing.T) {
	for _, mode := range []string{"ok", "v1", "xid", "handle", "procedure"} {
		t.Run(mode, func(t *testing.T) {
			g := &rpcGSS{context: testMIC{}, rpcVersion: 3, service: 3, handle: []byte("child"), established: true}
			var header encoder
			for _, n := range []uint32{7, 0, 2, nfsProgram, 4, 1} {
				header.u32(n)
			}
			if err := g.encode(&header, 0); err != nil {
				t.Fatal(err)
			}
			signed := bytes.Clone(g.replyHeader)
			switch mode {
			case "v1":
				signed = binary.BigEndian.AppendUint32(nil, g.seq)
			case "xid":
				signed[0] ^= 1
			case "procedure":
				signed[23] ^= 1
			case "handle":
				signed[len(signed)-1] ^= 1
			}
			mic, _ := (testMIC{}).MakeSignature(signed)
			err := g.verify(&decoder{verifierFlavor: 6, verifier: mic}, g.seq)
			if (err == nil) != (mode == "ok") {
				t.Fatal("unbound reply accepted", err)
			}
		})
	}
}
