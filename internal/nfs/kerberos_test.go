package nfs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// A synthetic MIC mechanism isolates RFC 2203 framing from Kerberos crypto.
// MIT KDC/Ganesha integration tests exercise the actual mechanism separately.
type testMIC struct{}

func (testMIC) MakeSignature(b []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte("synthetic-test-key"))
	h.Write(b)
	return h.Sum(nil), nil
}
func (m testMIC) VerifySignature(b, signature []byte) error {
	expected, _ := m.MakeSignature(b)
	if !hmac.Equal(expected, signature) {
		return errors.New("bad test MIC")
	}
	return nil
}

func TestGSSSignedCalls(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-sequence", "tampered-mic", "no-verifier", "denied", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			c := &rpcClient{conn: client, timeout: time.Second, gss: &rpcGSS{context: testMIC{}, handle: []byte("context"), established: true}}
			peerErr := make(chan error, 1)
			go func() {
				raw, err := readRecord(server)
				if err != nil {
					peerErr <- err
					return
				}
				d := &decoder{b: raw}
				xid := d.u32()
				for _, want := range []uint32{0, 2, nfsProgram, 3, 6, 6} {
					if d.u32() != want {
						peerErr <- errors.New("wrong RPC header")
						return
					}
				}
				cred := &decoder{b: d.opaque(400)}
				for _, want := range []uint32{1, 0, 1, 1} {
					if cred.u32() != want {
						peerErr <- errors.New("wrong GSS credential")
						return
					}
				}
				if string(cred.opaque(380)) != "context" || cred.err != nil || len(cred.b) != 0 {
					peerErr <- errors.New("bad context handle")
					return
				}
				signedLength := len(raw) - len(d.b)
				if d.u32() != 6 {
					peerErr <- errors.New("missing request MIC")
					return
				}
				if err := (testMIC{}).VerifySignature(raw[:signedLength], d.opaque(400)); err != nil {
					peerErr <- err
					return
				}
				if d.u32() != 99 || d.err != nil || len(d.b) != 0 {
					peerErr <- errors.New("krb5 modified plain arguments")
					return
				}
				var reply encoder
				reply.u32(xid)
				reply.u32(1)
				if mode == "denied" {
					reply.u32(1)
					reply.u32(1)
					reply.u32(14)
				} else {
					reply.u32(0)
					seq := uint32(1)
					if mode == "wrong-sequence" {
						seq = 0
					}
					mic, _ := (testMIC{}).MakeSignature(binary.BigEndian.AppendUint32(nil, seq))
					if mode == "tampered-mic" {
						mic[0] ^= 1
					}
					if mode == "no-verifier" {
						reply.u32(0)
						reply.opaque(nil)
					} else {
						reply.u32(6)
						reply.opaque(mic)
					}
					reply.u32(0)
					reply.u32(42)
				}
				if mode == "truncated" {
					reply = reply[:17]
				}
				_, err = server.Write(record(reply, true))
				peerErr <- err
			}()
			var args encoder
			args.u32(99)
			d, err := c.call(context.Background(), nfsProgram, 3, 6, &Auth{UID: 999}, args)
			if mode == "valid" {
				if err != nil || d.u32() != 42 {
					t.Fatalf("valid reply: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("unverified reply accepted")
				}
				if _, err = c.call(context.Background(), nfsProgram, 3, 0, nil, nil); err == nil {
					t.Fatal("reused failed GSS connection")
				}
			}
			if err := <-peerErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGSSControlAndLimits(t *testing.T) {
	g := &rpcGSS{context: testMIC{}}
	var e encoder
	if err := g.encode(&e, 1); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 6, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(e, want) {
		t.Fatalf("INIT credential: %x", e)
	}
	if err := g.encode(&e, 0); err == nil {
		t.Fatal("DATA before mutual authentication")
	}
	g.established = true
	g.handle = []byte("context")
	e = nil
	if err := g.encode(&e, 3); err != nil {
		t.Fatal(err)
	}
	d := &decoder{b: e}
	d.u32()
	cred := &decoder{b: d.opaque(400)}
	cred.u32()
	if cred.u32() != 3 || cred.u32() != 1 {
		t.Fatal("DESTROY missing procedure/sequence")
	}
	signed := len(e) - len(d.b)
	d.u32()
	if err := (testMIC{}).VerifySignature(e[:signed], d.opaque(400)); err != nil {
		t.Fatal(err)
	}
	g.seq = 0x7fffffff
	if err := g.encode(&e, 0); err == nil || g.seq != 0x7fffffff {
		t.Fatal("sequence wrapped")
	}
	g.seq = 0
	g.handle = make([]byte, 381)
	if err := g.encode(&e, 0); err == nil {
		t.Fatal("oversize credential")
	}
}

func TestSecurityValidationBeforeNetwork(t *testing.T) {
	valid := Config{Host: "must-not-resolve.invalid", Transport: "tcp", Version: "auto", Security: "krb5", Timeout: time.Second,
		Kerberos: KerberosConfig{ConfigFile: "missing.conf", Keytab: "missing.keytab", Principal: "client@NFS.TEST", SPN: "nfs/server.nfs.test"}}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"unsupported-version", func(c *Config) { c.Version = "1" }, "requires NFSv2"},
		{"v4-udp", func(c *Config) { c.Version, c.Transport = "4.2", "udp" }, "UDP supports only"},
		{"auto-pnfs", func(c *Config) { c.PNFS = true }, "pNFS requires explicit"},
		{"auto-offload", func(c *Config) { c.Offload = true }, "offload requires explicit"},
		{"auto-gss-v3", func(c *Config) { c.Security, c.Kerberos.RPCVersion = "krb5p", 3 }, "RPCSEC_GSS v3 requires explicit"},
		{"sys", func(c *Config) { c.Security = "sys" }, "require --sec"},
		{"principal", func(c *Config) { c.Kerberos.Principal = "client" }, "NAME@REALM"},
		{"keytab", func(c *Config) { c.Kerberos.Keytab = "" }, "requires --krb5-config"},
		{"two-credentials", func(c *Config) { c.Kerberos.CCache = "cache.file" }, "exactly one"},
		{"spn", func(c *Config) { c.Kerberos.SPN = "host/server" }, "SPN must"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.change(&cfg)
			if _, err := Connect(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v", err)
			}
		})
	}
	if err := validateSecurity(&valid); err != nil || valid.Version != "auto" {
		t.Fatalf("auto selection: %v", err)
	}
	valid.Version = ""
	if err := validateSecurity(&valid); err != nil || valid.Version != "3" {
		t.Fatalf("omitted API version default: %v", err)
	}
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		for _, transport := range []string{"tcp", "udp"} {
			valid.Security, valid.Version, valid.Transport = security, "2", transport
			if err := validateSecurity(&valid); err != nil || valid.Version != "2" || valid.Security != security || valid.Transport != transport {
				t.Fatalf("explicit v2 authentication selection: %v", err)
			}
		}
		valid.Security, valid.Version, valid.Transport = security, "auto", "udp"
		if err := validateSecurity(&valid); err != nil || valid.Version != "auto" || valid.Security != security {
			t.Fatalf("UDP authentication selection: %v", err)
		}
	}
	for _, version := range []string{"4", "4.0", "4.1", "4.2"} {
		valid.Version, valid.Transport = version, "tcp"
		if err := validateSecurity(&valid); err != nil || valid.Version != version {
			t.Fatalf("explicit v4 selection: %v", err)
		}
	}
}
