package nfs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPNFSTLSReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, packing := range []string{"dense", "sparse-many"} {
			for _, parallel := range []int{1, 3} {
				for _, mode := range []string{"data", "tls-name", "tls-wrong-name", "tls-untrusted", "tls-no-upgrade", "tls-no-alpn", "tls-client-cert", "tls-client-cert-missing", "denied", "recall-hole"} {
					t.Run(fmt.Sprintf("4.%d/%s/%d/%s", minor, packing, parallel, mode), func(t *testing.T) {
						runPNFSStripedRead(t, minor, "tls-acquire-paths-segments-"+packing, 128, mode, parallel)
					})
				}
			}
		}
	}
}

func TestPNFSTLSOptions(t *testing.T) {
	const target = "127.0.0.1:2049"
	for _, name := range []string{"", " ", "ds\x00name", "ds\nname", "ds/name", "ds\\name", "ds@name", strings.Repeat("a", 254)} {
		t.Run(fmt.Sprintf("invalid-%q", name), func(t *testing.T) {
			_, err := validatePNFSOptions(PNFSOptions{DataServers: map[string]string{target: target}, TLSNames: map[string]string{target: name}})
			if err == nil {
				t.Fatal("accepted invalid name")
			}
		})
	}
	for _, names := range []map[string]string{
		{"127.0.0.2:2049": "ds.test"},
		{target: "ds.test", "[::ffff:127.0.0.1]:2049": "ds.test"},
	} {
		if _, err := validatePNFSOptions(PNFSOptions{DataServers: map[string]string{target: target}, TLSNames: names}); err == nil {
			t.Fatal("accepted unapproved or duplicate target")
		}
	}
	o, err := validatePNFSOptions(PNFSOptions{DataServers: map[string]string{"127.0.0.2:2049": target}, TLSNames: map[string]string{"[::ffff:127.0.0.1]:2049": "ds.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pnfsTLSConfigs(Config{}, o); err == nil {
		t.Fatal("TLS name accepted without TLS")
	}
	configs, err := pnfsTLSConfigs(Config{Transport: "tcp", TLS: TLSConfig{Enabled: true, ServerName: "mds.test"}}, o)
	if err != nil || configs[target].ServerName != "ds.test" || len(configs) != 1 {
		t.Fatal("wrong target identity", configs, err)
	}
	for _, minor := range []string{"4.1", "4.2"} {
		_, err := Connect(context.Background(), Config{Version: minor, PNFS: true, TLS: TLSConfig{Enabled: true}})
		if err == nil || err.Error() != "timeout must be positive" {
			t.Fatal("TLS pNFS profile refused before timeout validation", err)
		}
	}
}

func pnfsTLSFixture(t *testing.T, mode string) (TLSConfig, func(int) *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pNFS test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	issue := func(serial int64, name string, client bool) tls.Certificate {
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if client {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, root, public, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	policy := TLSConfig{Enabled: true, CAFile: caPath, ServerName: "mds.example.invalid"}
	if mode == "tls-untrusted" {
		policy.CAFile = ""
	}
	if mode == "tls-client-cert" {
		cert := issue(10, "pnfs-client", true)
		key, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		policy.CertFile, policy.KeyFile = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
		if err := os.WriteFile(policy.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policy.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return policy, func(server int) *tls.Config {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{issue(int64(server+2), fmt.Sprintf("ds-%d.test", server), false)}, NextProtos: []string{"sunrpc"}}
		if mode == "tls-no-alpn" {
			cfg.NextProtos = nil
		}
		if mode == "tls-client-cert" || mode == "tls-client-cert-missing" {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			cfg.ClientCAs = roots
		}
		return cfg
	}
}

func pnfsTLSPeerEndpoint(t *testing.T, peer *v4Client, config *tls.Config, mode string) string {
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
		defer peer.c.nfs.conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := readRecord(conn)
		if err != nil {
			t.Error(err)
			return
		}
		d := &decoder{b: request}
		xid := d.u32()
		for _, want := range []uint32{0, 2, nfsProgram, 4, 0, 7, 0, 0, 0} {
			if d.u32() != want {
				t.Error("credentials or NFS operations sent before TLS")
				return
			}
		}
		if d.err != nil || len(d.b) != 0 {
			t.Error("malformed AUTH_TLS")
			return
		}
		var reply encoder
		for _, n := range []uint32{xid, 1, 0, 0} {
			reply.u32(n)
		}
		if mode == "tls-no-upgrade" {
			reply.str("")
		} else {
			reply.str("STARTTLS")
		}
		reply.u32(0)
		if _, err := conn.Write(record(reply, true)); err != nil {
			t.Error(err)
			return
		}
		if mode == "tls-no-upgrade" {
			b, _ := io.ReadAll(conn)
			if len(b) != 0 {
				t.Error("plaintext fallback")
			}
			return
		}
		secured := tls.Server(conn, config)
		if err := secured.HandshakeContext(context.Background()); err != nil {
			if mode != "tls-wrong-name" && mode != "tls-untrusted" && mode != "tls-client-cert-missing" {
				t.Error(err)
			}
			return
		}
		if mode == "tls-no-alpn" {
			b, _ := io.ReadAll(secured)
			if len(b) != 0 {
				t.Error("NFS sent without ALPN")
			}
			return
		}
		if mode == "tls-client-cert" && len(secured.ConnectionState().VerifiedChains) == 0 {
			t.Error("client certificate not verified")
			return
		}
		conn.SetDeadline(time.Time{})
		up := make(chan struct{})
		go func() { io.Copy(peer.c.nfs.conn, secured); peer.c.nfs.conn.Close(); close(up) }()
		io.Copy(secured, peer.c.nfs.conn)
		conn.Close()
		<-up
	}()
	t.Cleanup(func() { l.Close(); <-done })
	return l.Addr().String()
}
