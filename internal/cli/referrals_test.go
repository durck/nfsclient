package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

type referralTLSListener struct {
	net.Listener
	config *tls.Config
}

func (l *referralTLSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if err = c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.Close()
		return nil, err
	}
	b, _, err := readObservedRPC(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	d := &missingV4Decoder{b: b}
	xid := d.word()
	for _, v := range []uint32{0, 2, 100003, 4, 0, 7, 0, 0, 0} {
		if d.word() != v {
			c.Close()
			return nil, errors.New("referral STARTTLS probe leaked identity or malformed")
		}
	}
	r := missingV4Words(nil, xid, 1, 0, 0)
	r = missingV4Opaque(r, []byte("STARTTLS"))
	r = missingV4Words(r, 0)
	w := append(missingV4Words(nil, uint32(len(r))|0x80000000), r...)
	if _, err = c.Write(w); err != nil {
		c.Close()
		return nil, err
	}
	secured := tls.Server(c, l.config)
	if err = secured.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	return secured, nil
}

func referralTLSPolicy(t *testing.T) (nfs.TLSConfig, *tls.Config) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"referral.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, x, x, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return nfs.TLSConfig{Enabled: true, CAFile: ca, ServerName: "referral.test"}, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"sunrpc"}}
}

type referralWirePeer struct {
	base                    blockCLIPeer
	mode                    string
	origin                  bool
	moved                   atomic.Bool
	reads, opens, locations atomic.Int32
	data                    []byte
	sid                     []byte
}

func (p *referralWirePeer) operation(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
	var e []byte
	absent := func() bool {
		return p.origin && p.moved.Load() && strings.HasPrefix(*current, "/data/junction") || !p.origin && p.mode == "cycle" && strings.HasPrefix(*current, "/relocated")
	}
	switch code {
	case 43:
		d.take(8)
		sequence := d.word()
		d.word()
		fore, back := d.take(28), d.take(28)
		//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
		if d.word() != 0 || d.word() != 0 {
			return nil, 0, errors.New("ordinary referral requested backchannel"), true
		}
		e = append(e, p.sid...)
		e = missingV4Words(e, sequence, 0)
		e = append(e, fore...)
		e = append(e, back...)
	case 35, 36:
		var v missingV4Peer
		e, s, err := v.operation(code, d, current)
		return e, s, err, true
	case 24:
		*current = "/"
	case 22:
		*current = string(d.opaque())
	case 15:
		part := string(d.opaque())
		*current = strings.TrimSuffix(*current, "/") + "/" + part
		if !strings.HasPrefix(*current, "/data") && !strings.HasPrefix(*current, "/relocated") {
			return nil, 2, nil, true
		}
	case 10:
		if absent() {
			return nil, 10019, nil, true
		}
		e = missingV4Opaque(e, []byte(*current))
	case 9:
		bits := d.bitmap()
		var values []byte
		if reflect.DeepEqual(bits, []uint32{24}) {
			p.locations.Add(1)
			root, server, dest := []string{"data", "junction"}, "approved.test", []string{"relocated"}
			if !p.origin {
				root = []string{"relocated"}
			}
			if p.mode == "fs-root-mismatch" {
				root = []string{"elsewhere"}
			}
			if p.mode == "unapproved" {
				server = "unapproved.invalid"
			}
			values = missingV4Words(values, uint32(len(root)))
			for _, s := range root {
				values = missingV4Opaque(values, []byte(s))
			}
			values = missingV4Words(values, 1, 1)
			values = missingV4Opaque(values, []byte(server))
			values = missingV4Words(values, uint32(len(dest)))
			for _, s := range dest {
				values = missingV4Opaque(values, []byte(s))
			}
		} else {
			if absent() {
				return nil, 10019, nil, true
			}
			file := strings.HasSuffix(*current, "/file")
			for _, bit := range bits {
				switch bit {
				case 1:
					kind := uint32(2)
					if file {
						kind = 1
					}
					if p.mode == "symlink" && *current == "/data/junction" {
						kind = 5
					}
					values = missingV4Words(values, kind)
				case 3:
					v := uint64(7)
					if file && !p.origin && p.mode == "changed-source" {
						v++
					}
					values = blockCLIQuad(values, v)
				case 4:
					values = blockCLIQuad(values, uint64(len(p.data)))
				case 8:
					values = blockCLIQuad(blockCLIQuad(values, 7), 8)
				case 10:
					values = missingV4Words(values, 60)
				case 20:
					id := uint64(1)
					if file {
						id = 2
					}
					values = blockCLIQuad(values, id)
				case 30, 31:
					values = blockCLIQuad(values, 32768)
				case 33:
					values = missingV4Words(values, 0644)
				case 36, 37:
					values = missingV4Opaque(values, []byte("fixture"))
				case 52, 53:
					values = missingV4Words(values, 0, 1, 0)
				default:
					return nil, 0, fmt.Errorf("unexpected referral attribute %d", bit), true
				}
			}
		}
		e = blockCLIBitmap(e, bits)
		e = missingV4Opaque(e, values)
	case 18:
		d.word()
		if d.word() != 1 || d.word() != 0 {
			return nil, 0, errors.New("referral OPEN must be read-only"), true
		}
		d.take(8)
		owner := d.opaque()
		if len(owner) != 16 || d.word() != 0 || d.word() != 0 || string(d.opaque()) != "file" {
			return nil, 0, errors.New("referral OPEN replay/create profile"), true
		}
		*current = strings.TrimSuffix(*current, "/") + "/file"
		p.opens.Add(1)
		e = append(e, p.sid...)
		e = missingV4Words(e, 1, 0, 1, 0, 1, 0, 0, 0)
	case 25:
		if !bytes.Equal(d.take(16), p.sid) {
			return nil, 0, errors.New("foreign OPEN stateid reused across namespace"), true
		}
		off := uint64(d.word())<<32 | uint64(d.word())
		size := int(d.word())
		if p.origin && p.moved.Load() {
			return nil, 10019, nil, true
		}
		if off > uint64(len(p.data)) {
			return nil, 0, errors.New("read offset beyond fixture"), true
		}
		end := min(int(off)+size, len(p.data))
		eof := uint32(0)
		if end == len(p.data) {
			eof = 1
		}
		e = missingV4Words(e, eof)
		e = missingV4Opaque(e, p.data[int(off):end])
		p.reads.Add(1)
		if p.origin && p.mode != "initial" && p.mode != "unapproved" && p.mode != "fs-root-mismatch" && p.mode != "symlink" && p.mode != "cycle" {
			p.moved.Store(true)
		}
	case 4:
		d.word()
		if !bytes.Equal(d.take(16), p.sid) {
			return nil, 0, errors.New("foreign CLOSE stateid"), true
		}
		e = append(e, p.sid...)
		if p.origin && p.mode == "cleanup-error" {
			return nil, 10011, nil, true
		}
	default:
		return nil, 0, nil, false
	}
	return e, 0, nil, true
}

func TestReferralProtectedPublication(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, mode := range []string{"initial", "migration", "changed-source", "bad-prefix", "unapproved", "fs-root-mismatch", "cycle", "symlink", "callback-auth", "wrong-tls-name", "cleanup-error"} {
			if os.Getenv("NFS_VIEWER_TEST_BINARY") != "" && mode == "callback-auth" {
				continue
			}
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				policy, server := referralTLSPolicy(t)
				payload := bytes.Repeat([]byte("referral-independent-payload\x00\xff"), 4000)
				original := &referralWirePeer{origin: true, mode: mode, data: payload, sid: bytes.Repeat([]byte{7}, 16)}
				if mode == "initial" || mode == "unapproved" || mode == "fs-root-mismatch" || mode == "cycle" || mode == "wrong-tls-name" {
					original.moved.Store(true)
				}
				target := &referralWirePeer{mode: mode, data: bytes.Clone(payload), sid: bytes.Repeat([]byte{8}, 16)}
				if mode == "bad-prefix" {
					target.data[0] ^= 1
				}
				var listeners []net.Listener
				var joined []chan error
				start := func(p *referralWirePeer) string {
					l, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					listeners = append(listeners, l)
					done := make(chan error, 1)
					joined = append(joined, done)
					p.base.minor = minor
					p.base.operationHook = p.operation
					go func() { done <- p.base.serve(&referralTLSListener{Listener: l, config: server}) }()
					return l.Addr().String()
				}
				originAddress, targetAddress := start(original), start(target)
				var c *nfs.Client
				var once sync.Once
				stop := func() {
					once.Do(func() {
						if c != nil {
							c.Close()
						}
						for _, l := range listeners {
							l.Close()
						}
						for _, done := range joined {
							err := <-done
							if err != nil && mode != "wrong-tls-name" {
								t.Errorf("referral peer: %v", err)
							}
						}
					})
				}
				t.Cleanup(stop)
				_, port, _ := net.SplitHostPort(originAddress)
				number, _ := strconv.Atoi(port)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var err error
				var s *session.Session
				approval := session.ReferralTarget{Server: "approved.test", Target: nfs.ReadReplica{Address: targetAddress, TLSName: "referral.test"}}
				if mode == "wrong-tls-name" {
					approval.Target.TLSName = "wrong.test"
				}
				local := filepath.Join(t.TempDir(), "output")
				var count int64
				if os.Getenv("NFS_VIEWER_TEST_BINARY") != "" {
					args := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(number), "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--tls", "--tls-ca", policy.CAFile, "--tls-server-name", policy.ServerName, "--command", "reget --referral approved.test=" + targetAddress + ",," + approval.Target.TLSName + " junction/file " + strconv.Quote(local)}
					out, e := runKerberosCLI(t, args)
					err = e
					if err == nil {
						count = int64(len(payload))
					}
					t.Logf("REFERRAL_RELEASE_CLI mode=%s error=%v output=%s", mode, err, out)
				} else {
					c, err = nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", NFSPort: number, Version: fmt.Sprintf("4.%d", minor), Timeout: time.Second, TLS: policy})
					if err != nil {
						t.Fatal(err)
					}
					s = session.New(c, "127.0.0.1", false, false, io.Discard)
					if err = s.Use(ctx, "/data"); err != nil {
						t.Fatal(err)
					}
					count, err = s.GetResumeReferrals(ctx, "junction/file", local, []session.ReferralTarget{approval}, func(done, _ uint64) {
						if mode == "callback-auth" && done > 0 {
							c.Auth.UID++
						}
					})
				}
				stop()
				if mode == "initial" || mode == "migration" {
					if err != nil || count != int64(len(payload)) {
						t.Fatal("referral publication failed", count, err)
					}
					got, e := os.ReadFile(local)
					if e != nil || !bytes.Equal(got, payload) {
						t.Fatal("published bytes differ", e)
					}
					if target.opens.Load() != 1 || target.reads.Load() == 0 || original.locations.Load() != 1 || s != nil && (s.Client != c || s.Export != "/data") {
						t.Fatal("fresh state or interactive namespace changed")
					}
					if mode == "migration" && original.reads.Load() != 1 {
						t.Fatal("old READ was replayed")
					}
				} else {
					if err == nil {
						t.Fatal("unsafe referral published")
					}
					if _, e := os.Stat(local); !errors.Is(e, os.ErrNotExist) {
						t.Fatal("failed referral published a destination")
					}
				}
			})
		}
	}
}

func TestReferralCommandSyntax(t *testing.T) {
	for _, line := range []string{"reget --referral", "reget --referral host:2049,, source", "reget --referral x=host:2049 source", "reget --referral x=host:2049,, --retries 1 source", "reget --referral x=host:2049,, --failover host:2049,, source", "reget --referral x=host:2049,, source out extra"} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), line); err == nil {
			t.Fatal("invalid referral syntax accepted", line)
		}
	}
}
