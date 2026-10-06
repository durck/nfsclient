package nfs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

// Generate a private, synthetic chain for each policy. All checks below use
// AUTH_TLS followed by an actual TLS handshake, not just the verifier helper.
func rpcTLSCertificateChain(t *testing.T, leafPurpose, intermediatePurpose, rootPurpose string, names []string, expired bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	var parent *x509.Certificate
	var parentKey ed25519.PrivateKey
	var chain [][]byte
	var leafKey ed25519.PrivateKey
	roots := x509.NewCertPool()
	for i, purpose := range []string{rootPurpose, intermediatePurpose, leafPurpose} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if i < 2 {
			template.IsCA, template.BasicConstraintsValid = true, true
			template.KeyUsage |= x509.KeyUsageCertSign
		} else {
			template.DNSNames = names
			if expired {
				template.NotBefore, template.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			}
		}
		switch purpose {
		case "rpc":
			template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 34}}
		case "server":
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "both":
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 34}}
		case "client":
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case "any":
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		case "unknown":
			template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 35}}
		}
		if parent == nil {
			parent, parentKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			roots.AddCert(parsed)
		}
		chain = append([][]byte{der}, chain...)
		parent, parentKey, leafKey = parsed, key, key
	}
	return tls.Certificate{Certificate: chain, PrivateKey: leafKey}, roots
}

func TestRPCTLSCertificatePolicy(t *testing.T) {
	for _, tc := range []struct {
		name, leaf, intermediate, root                string
		dns                                           []string
		expired, wrongName, untrusted, insecure, want bool
	}{
		{name: "rpc-only-entire-chain", leaf: "rpc", intermediate: "rpc", root: "rpc", want: true},
		{name: "rpc-only-unconstrained-ca", leaf: "rpc", want: true},
		{name: "ordinary-server-auth", leaf: "server", intermediate: "server", root: "server", want: true},
		{name: "ordinary-server-unconstrained-ca", leaf: "server", want: true},
		{name: "both-leaf-rpc-ca", leaf: "both", intermediate: "rpc", want: true},
		{name: "no-eku", want: true},
		{name: "any-eku", leaf: "any", intermediate: "any", root: "any", want: true},
		{name: "client-only-leaf", leaf: "client"},
		{name: "unknown-purpose", leaf: "unknown"},
		{name: "rpc-leaf-server-intermediate", leaf: "rpc", intermediate: "server"},
		{name: "server-leaf-rpc-intermediate", leaf: "server", intermediate: "rpc"},
		{name: "rpc-leaf-client-intermediate", leaf: "rpc", intermediate: "client"},
		{name: "client-only-root", leaf: "rpc", root: "client"},
		{name: "different-purpose-at-root", leaf: "both", intermediate: "rpc", root: "server"},
		{name: "wildcard", leaf: "server", dns: []string{"*.example.test"}},
		{name: "unused-wildcard", leaf: "server", dns: []string{"nfs.example.test", "*.other.test"}},
		{name: "expired-rpc-certificate", leaf: "rpc", expired: true},
		{name: "wrong-name", leaf: "rpc", wrongName: true},
		{name: "untrusted", leaf: "rpc", untrusted: true},
		{name: "insecure-wildcard", leaf: "server", dns: []string{"*.example.test"}, insecure: true, want: true},
		{name: "insecure-expired", leaf: "rpc", expired: true, insecure: true, want: true},
		{name: "insecure-wrong-purpose", leaf: "client", insecure: true, want: true},
		{name: "insecure-wrong-name-untrusted", leaf: "rpc", wrongName: true, untrusted: true, insecure: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dns == nil {
				tc.dns = []string{"nfs.example.test"}
			}
			cert, roots := rpcTLSCertificateChain(t, tc.leaf, tc.intermediate, tc.root, tc.dns, tc.expired)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			release := make(chan struct{})
			defer close(release)
			done := make(chan error, 1)
			go func() {
				request, err := readRecord(server)
				if err != nil {
					done <- err
					return
				}
				var reply encoder
				reply.u32(binary.BigEndian.Uint32(request))
				for _, value := range []uint32{1, 0, 0} {
					reply.u32(value)
				}
				reply.str("STARTTLS")
				reply.u32(0)
				if _, err := server.Write(record(reply, true)); err != nil {
					done <- err
					return
				}
				secured := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"sunrpc"}, Certificates: []tls.Certificate{cert}})
				done <- secured.Handshake()
				<-release
			}()
			config := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"sunrpc"}, RootCAs: roots, ServerName: "nfs.example.test", InsecureSkipVerify: tc.insecure}
			if tc.wrongName {
				config.ServerName = "other.example.test"
			}
			if tc.untrusted {
				config.RootCAs = x509.NewCertPool()
			}
			c := &rpcClient{conn: client, timeout: 2 * time.Second}
			owner := &Client{nfs: c}
			if owner.TLSCertificateVerified() {
				t.Fatal("plain connection marked verified")
			}
			err := c.startTLS(context.Background(), nfsProgram, 3, config)
			if (err == nil) != tc.want {
				t.Fatalf("handshake result differs from certificate policy: %v", err)
			}
			if config.InsecureSkipVerify != tc.insecure {
				t.Fatal("handshake mutated shared TLS configuration")
			}
			if owner.TLSCertificateVerified() != (tc.want && !tc.insecure) {
				t.Fatal("certificate verification state differs from negotiated policy")
			}
			if tc.want {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				state := c.conn.(*tls.Conn).ConnectionState()
				if len(state.VerifiedChains) != 0 {
					t.Fatal("custom policy unexpectedly changed crypto/tls verification state")
				}
				if !tc.insecure && (len(c.tlsVerifiedChains) == 0 || len(c.tlsVerifiedChains[0]) != 3) {
					t.Fatal("complete verified chain was not retained")
				}
				// A failed reuse must invalidate even a previously successful result.
				c.udp = true
				if c.startTLS(context.Background(), nfsProgram, 3, config) == nil || owner.TLSCertificateVerified() {
					t.Fatal("failed reuse retained previous certificate verification")
				}
			} else {
				if len(c.tlsVerifiedChains) != 0 {
					t.Fatal("failed handshake retained verified chains")
				}
				if err := <-done; err == nil {
					t.Fatal("server handshake succeeded after certificate refusal")
				}
			}
		})
	}
}
