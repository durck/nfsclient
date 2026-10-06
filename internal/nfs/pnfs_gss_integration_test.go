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
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	bgss "nfsclient/internal/krbgss"
)

// These opt-in tests use real MIT-issued tickets and the Go GSS acceptor.
// The NFS filesystem peers remain scripted: this is not native pNFS server
// certification. Ganesha 4.3 does not implement a v4.1 GSS backchannel.
func pnfsMITConfig(t *testing.T, security, spn string) Config {
	t.Helper()
	if os.Getenv("NFS_VIEWER_PNFS_GSS") != "1" {
		t.Skip("set NFS_VIEWER_PNFS_GSS=1 with explicit MIT fixture paths")
	}
	k := KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_PNFS_GSS_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_PNFS_GSS_CLIENT_KEYTAB"), Principal: "root@NFS.TEST", SPN: spn}
	for _, path := range []string{k.ConfigFile, k.Keytab, os.Getenv("NFS_VIEWER_PNFS_GSS_SERVER_KEYTAB")} {
		if path == "" {
			t.Fatal("missing explicit MIT fixture path")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	return Config{Version: "4.1", Transport: "tcp", PNFS: true, Timeout: 10 * time.Second, Security: security, Kerberos: k}
}

// The immutable upstream is an AUTH_NONE, in-process scripted peer. The only
// network endpoint accepts RPCSEC_GSS; no cleartext fallback is accepted.
type mitTLSOptions struct {
	accepted          *atomic.Int32
	allowReadAbort    bool
	expectedService   uint32
	server            *tls.Config
	client            TLSConfig
	badBinding        string
	native            bool
	dropDataReply     int // Test-only loss after a fully processed, protected reply.
	afterDroppedReply func()
}

func pnfsMITEndpoint(t *testing.T, upstream net.Conn, beforeData func(net.Conn, *bgss.Acceptor) error, tlsOptions ...mitTLSOptions) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if len(tlsOptions) != 0 && tlsOptions[0].accepted != nil {
			tlsOptions[0].accepted.Add(1)
		}
		defer upstream.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		acceptOptions := []bgss.Option[bgss.Acceptor]{bgss.WithKeytab[bgss.Acceptor](os.Getenv("NFS_VIEWER_PNFS_GSS_SERVER_KEYTAB"))}
		var nativeBinding []byte
		if len(tlsOptions) != 0 && tlsOptions[0].server != nil {
			request, err := readRecord(conn)
			if err != nil {
				t.Error(err)
				return
			}
			d := &decoder{b: request}
			xid := d.u32()
			for _, want := range []uint32{0, 2, nfsProgram, 4, 0, 7, 0, 0, 0} {
				if d.u32() != want {
					t.Error("GSS sent before TLS")
					return
				}
			}
			if d.err != nil || len(d.b) != 0 {
				t.Error("invalid AUTH_TLS")
				return
			}
			var reply encoder
			for _, n := range []uint32{xid, 1, 0, 0} {
				reply.u32(n)
			}
			reply.str("STARTTLS")
			reply.u32(0)
			if _, err = conn.Write(record(reply, true)); err != nil {
				t.Error(err)
				return
			}
			secured := tls.Server(conn, tlsOptions[0].server)
			if err = secured.HandshakeContext(context.Background()); err != nil {
				t.Error(err)
				return
			}
			conn = secured
			binding, err := tlsGSSBinding(secured)
			if err != nil {
				t.Error(err)
				return
			}
			if tlsOptions[0].badBinding == "different" {
				binding[len(binding)-1] ^= 1
			}
			if tlsOptions[0].badBinding == "missing" {
				binding = nil
			}
			acceptOptions = append(acceptOptions, bgss.WithChannelBinding[bgss.Acceptor](binding))
			nativeBinding = binding
		}
		acceptor, err := bgss.NewAcceptor(acceptOptions...)
		if err != nil {
			t.Error(err)
			return
		}
		defer acceptor.Close()
		handle := []byte("mit-pnfs-fore-context")
		var highest uint32
		established := false
		dataReplies := 0
		for {
			raw, err := readRecord(conn)
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || len(tlsOptions) != 0 && tlsOptions[0].allowReadAbort && established && dataReplies >= 2 && mitExpectedReset(err) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			d := &decoder{b: raw}
			xid := d.u32()
			if d.u32() != 0 || d.u32() != 2 || d.u32() != nfsProgram || d.u32() != 4 {
				t.Error("invalid GSS RPC header")
				return
			}
			proc := d.u32()
			if d.u32() != 6 {
				t.Error("GSS downgraded")
				return
			}
			a := &decoder{b: d.opaque(400)}
			signedSize := len(raw) - len(d.b)
			version, control, seq, service := a.u32(), a.u32(), a.u32(), a.u32()
			gotHandle := a.opaque(380)
			flavor, mic := d.u32(), d.opaque(400)
			if a.err != nil || len(a.b) != 0 || d.err != nil || version != 1 {
				t.Error("bad GSS framing")
				return
			}
			var body encoder
			replySeq := seq
			if control == 1 {
				if established || proc != 0 || seq != 0 || service != 1 || len(gotHandle) != 0 || flavor != 0 || len(mic) != 0 {
					t.Error("bad INIT")
					return
				}
				token := d.opaque(1 << 20)
				if d.err != nil || len(d.b) != 0 {
					t.Error("bad INIT token framing")
					return
				}
				reply, more, err := acceptor.Accept(token)
				if len(tlsOptions) != 0 && tlsOptions[0].native {
					if nativeErr := nativeGSSBindingCheck(token, nativeBinding, tlsOptions[0].badBinding == "different"); nativeErr != nil {
						t.Error(nativeErr)
						return
					}
					t.Log("native MIT GSS checked channel binding")
				}
				if len(tlsOptions) != 0 && tlsOptions[0].badBinding != "" {
					if err == nil || !strings.Contains(err.Error(), "binding mismatch") {
						t.Errorf("mismatched TLS binding not rejected: %v", err)
					}
					return
				}
				if err != nil || more {
					t.Errorf("MIT AP_REQ not accepted: %v, more=%v", err, more)
					return
				}
				body.opaque(handle)
				body.u32(0)
				body.u32(0)
				body.u32(64)
				body.opaque(reply)
				replySeq, established = 64, true
			} else {
				if !established || !bytes.Equal(gotHandle, handle) || seq <= highest || seq >= 0x80000000 || flavor != 6 || service < 1 || service > 3 || acceptor.VerifySignature(raw[:signedSize], mic) != nil {
					t.Error("invalid authenticated GSS request")
					return
				}
				highest = seq
				if control == 3 {
					if proc != 0 || service != 1 || len(d.b) != 0 {
						t.Error("bad DESTROY")
						return
					}
				} else if control == 0 {
					if len(tlsOptions) != 0 && tlsOptions[0].expectedService != 0 && service != tlsOptions[0].expectedService {
						t.Error("GSS service changed")
						return
					}
					g := &rpcGSS{context: acceptor, seq: seq, service: service}
					if err := g.unprotect(d); err != nil {
						t.Error(err)
						return
					}
					if beforeData != nil {
						if err := beforeData(conn, acceptor); err != nil {
							t.Error(err)
							return
						}
					}
					plain := append(encoder(nil), raw[:24]...)
					for range 4 {
						plain.u32(0)
					}
					plain = append(plain, d.b...)
					if _, err = upstream.Write(record(plain, true)); err != nil {
						t.Error(err)
						return
					}
					reply, err := readRecord(upstream)
					if err != nil {
						t.Error(err)
						return
					}
					if len(reply) < 24 || binary.BigEndian.Uint32(reply) != xid || binary.BigEndian.Uint32(reply[20:24]) != 0 {
						t.Error("bad scripted reply")
						return
					}
					body, err = g.protect(reply[24:])
					if err != nil {
						t.Error(err)
						return
					}
					dataReplies++
					if len(tlsOptions) != 0 && dataReplies == tlsOptions[0].dropDataReply {
						if tlsOptions[0].afterDroppedReply != nil {
							tlsOptions[0].afterDroppedReply()
						}
						return
					}
				} else {
					t.Error("unexpected GSS control")
					return
				}
			}
			verifier, err := acceptor.MakeSignature(binary.BigEndian.AppendUint32(nil, replySeq))
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
			if _, err = conn.Write(record(reply, true)); err != nil {
				t.Error(err)
				return
			}
			if control == 3 {
				return
			}
		}
	}()
	t.Cleanup(func() { l.Close(); upstream.Close(); <-done })
	return l.Addr().String()
}

func pnfsMITWrapClient(t *testing.T, c *Client, security string, hook func(net.Conn, *bgss.Acceptor) error, tlsOptions ...mitTLSOptions) {
	t.Helper()
	cfg := pnfsMITConfig(t, security, "nfs/server.nfs.test")
	cfg.Version = c.Version()
	endpoint := pnfsMITEndpoint(t, c.nfs.conn, hook, tlsOptions...)
	conn, err := net.DialTimeout("tcp", endpoint, cfg.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	c.nfs = &rpcClient{conn: conn, timeout: cfg.Timeout}
	if len(tlsOptions) != 0 && tlsOptions[0].server != nil {
		cfg.TLS = tlsOptions[0].client
		cfg.TLS.ServerName = "127.0.0.1"
		policy, err := cfg.tlsConfig()
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if err = c.nfs.startTLS(context.Background(), nfsProgram, 4, policy); err != nil {
			conn.Close()
			t.Fatal(err)
		}
	}
	c.config = &cfg
	if err = c.authenticateKerberos(context.Background(), cfg); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.nfs.destroyKerberos(context.Background())
		conn.Close()
		if c.nfs.duplex != nil {
			<-c.nfs.duplex.done
		}
		if c.closeKerberos != nil {
			c.closeKerberos()
		}
	})
}

func TestPNFSMITStripedRead(t *testing.T) {
	runPNFSMITStripedRead(t, "")
}

func TestPNFSMITTLSStripedRead(t *testing.T) {
	runPNFSMITStripedRead(t, "tls-")
}

func runPNFSMITStripedRead(t *testing.T, transport string) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		for _, minor := range []uint32{1, 2} {
			for _, packing := range []string{"dense", "sparse-many"} {
				for _, parallel := range []int{1, 3} {
					t.Run(fmt.Sprintf("%s/4.%d/%s/parallel=%d", security, minor, packing, parallel), func(t *testing.T) {
						runPNFSStripedRead(t, minor, "gss-"+security+"-"+transport+packing, 128, "data", parallel)
					})
				}
			}
		}
	}
}

func TestPNFSMITBackchannel(t *testing.T) {
	runPNFSMITBackchannel(t, false)
}

func TestPNFSMITTLSBackchannel(t *testing.T) {
	runPNFSMITBackchannel(t, true)
}

func TestPNFSMITDeviceNotifications(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", secure), func(t *testing.T) { runPNFSMITBackchannel(t, secure, 14) })
	}
}

func runPNFSMITBackchannel(t *testing.T, secure bool, kinds ...uint32) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		for _, minor := range []uint32{1, 2} {
			t.Run(fmt.Sprintf("%s/4.%d", security, minor), func(t *testing.T) {
				c := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
					if program != nfsProgram || proc != 0 || len(d.b) != 0 {
						return nil, errors.New("not NULL")
					}
					return nil, nil
				})
				c.version = fmt.Sprintf("4.%d", minor)
				r := &layoutRecall{minor: minor, session: bytes.Repeat([]byte{3}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{4}, 16)}
				deviceNotify := len(kinds) != 0 && kinds[0] == 14
				if deviceNotify {
					r.deviceNotifications = true
					if len(kinds) > 1 {
						r.layoutType = kinds[1]
					}
					r.devices = map[string]deviceNotice{string(make([]byte, 16)): {}}
				} else if len(kinds) != 0 {
					r.layoutType = kinds[0]
				}
				setup := make(chan *gssBackchannel, 1)
				var tlsOptions []mitTLSOptions
				if secure {
					policy, server := pnfsTLSFixture(t, "data")
					tlsOptions = []mitTLSOptions{{server: server(0), client: policy}}
				}
				pnfsMITWrapClient(t, c, security, func(conn net.Conn, acceptor *bgss.Acceptor) error {
					g := <-setup
					server := &gssBackchannel{context: acceptor, handle: g.handle, service: g.service}
					call := gssCallbackCall(t, server, r, 1, 1)
					if deviceNotify {
						call = gssProtectCallback(t, server, deviceCallbackCall(r, 1, make([]byte, 16), 1, false), 1)
					}
					if _, err := conn.Write(record(call, true)); err != nil {
						return err
					}
					reply, err := readRecord(conn)
					if err != nil {
						return err
					}
					d := &decoder{b: reply}
					d.take(12)
					d.verifierFlavor = d.u32()
					d.verifier = d.opaque(400)
					if d.u32() != 0 {
						return errors.New("callback RPC rejected")
					}
					check := rpcGSS{context: acceptor, seq: 1, service: g.service}
					if err = check.verify(d, 1); err != nil {
						return err
					}
					if err = check.unprotect(d); err != nil {
						return err
					}
					if d.u32() != 0 {
						return errors.New("callback NFS rejected")
					}
					return nil
				}, tlsOptions...)
				g, err := newGSSBackchannel(c.nfs.gss)
				if err != nil {
					t.Fatal(err)
				}
				c.nfs.pinnedBackchannelGSS = true
				c.nfs.duplex = startDuplex(c.nfs, func(raw []byte) ([]byte, error) { return g.callback(raw, r) })
				setup <- g
				if _, err = c.nfs.call(context.Background(), nfsProgram, 4, 0, nil, nil); err != nil {
					t.Fatal(err)
				}
				r.mu.Lock()
				recalled, seq := r.recalled, r.sequence
				r.mu.Unlock()
				if deviceNotify {
					if recalled || seq != 1 || !r.devicesPending() {
						t.Fatal("protected device notification not applied")
					}
				} else if !recalled || seq != 1 {
					t.Fatal("protected recall not applied")
				}
			})
		}
	}
}

func TestPNFSMITWrites(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) { runPNFSWriteWire(t, security) })
	}
}

func TestPNFSMITTLSWrites(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) { runPNFSWriteWire(t, "tls-"+security) })
	}
}

func pnfsGSSPacking(packing string) (string, string) {
	if !strings.HasPrefix(packing, "gss-") {
		return "", packing
	}
	security, rest, _ := strings.Cut(strings.TrimPrefix(packing, "gss-"), "-")
	return security, rest
}

// Windows exposes Winsock error numbers, not syscall's application errno aliases.
func mitExpectedReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(10053)) || errors.Is(err, syscall.Errno(10054)))
}
