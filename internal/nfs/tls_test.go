package nfs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestRPCSTARTTLS(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"nfs.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, failure := range []string{"", "wrong-name", "untrusted", "expired", "insecure-self-signed", "insecure-expired", "no-alpn", "no-starttls", "wrong-xid", "non-success-probe"} {
		t.Run(failure, func(t *testing.T) {
			peerDER := der
			peerRoots := roots
			if failure == "expired" || failure == "insecure-expired" {
				expired := *template
				expired.NotBefore, expired.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
				var err error
				peerDER, err = x509.CreateCertificate(rand.Reader, &expired, &expired, pub, key)
				if err != nil {
					t.Fatal(err)
				}
				peerCert, err := x509.ParseCertificate(peerDER)
				if err != nil {
					t.Fatal(err)
				}
				peerRoots = x509.NewCertPool()
				peerRoots.AddCert(peerCert)
			}
			insecure := failure == "insecure-self-signed" || failure == "insecure-expired"
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				request, err := readRecord(server)
				if err != nil {
					done <- err
					return
				}
				d := &decoder{b: request}
				xid := d.u32()
				for _, want := range []uint32{0, 2, nfsProgram, 3, 0, 7, 0, 0, 0} {
					if d.u32() != want {
						done <- fmt.Errorf("probe leaked credentials or wrong program")
						return
					}
				}
				if d.err != nil || len(d.b) != 0 {
					done <- fmt.Errorf("malformed probe")
					return
				}
				var response encoder
				if failure == "wrong-xid" {
					xid++
				}
				response.u32(xid)
				response.u32(1)
				response.u32(0)
				response.u32(0)
				token := "STARTTLS"
				if failure == "no-starttls" {
					token = ""
				}
				response.str(token)
				status := uint32(0)
				if failure == "non-success-probe" {
					status = 1
				}
				response.u32(status)
				if _, err := server.Write(record(response, true)); err != nil {
					done <- err
					return
				}
				if failure == "no-starttls" || failure == "wrong-xid" {
					var b [1]byte
					n, _ := server.Read(b[:])
					if n != 0 {
						done <- fmt.Errorf("client sent data after refused upgrade")
					} else {
						done <- nil
					}
					return
				}
				config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{peerDER}, PrivateKey: key}}, NextProtos: []string{"sunrpc"}}
				if failure == "no-alpn" {
					config.NextProtos = nil
				}
				secured := tls.Server(server, config)
				if err := secured.Handshake(); err != nil {
					if failure != "" && failure != "non-success-probe" && !insecure {
						done <- nil
					} else {
						done <- err
					}
					return
				}
				request, err = readRecord(secured)
				if failure == "no-alpn" {
					if len(request) != 0 {
						done <- fmt.Errorf("RPC leaked without ALPN")
					} else {
						done <- nil
					}
					return
				}
				if err != nil {
					done <- err
					return
				}
				var reply encoder
				reply.u32(binary.BigEndian.Uint32(request))
				for i := 0; i < 5; i++ {
					if i == 0 {
						reply.u32(1)
					} else {
						reply.u32(0)
					}
				}
				_, err = secured.Write(record(reply, true))
				done <- err
			}()
			c := &rpcClient{conn: client, timeout: time.Second, xid: 42}
			config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: peerRoots, ServerName: "nfs.test", NextProtos: []string{"sunrpc"}}
			if failure == "wrong-name" {
				config.ServerName = "other.test"
			}
			if failure == "untrusted" {
				config.RootCAs = x509.NewCertPool()
			}
			if insecure {
				config, err = (Config{Host: "wrong.test", Transport: "tcp", TLS: TLSConfig{Enabled: true, InsecureSkipVerify: true}}).tlsConfig()
				if err != nil {
					t.Fatal(err)
				}
				config.RootCAs = x509.NewCertPool()
			}
			err := c.startTLS(context.Background(), nfsProgram, 3, config)
			if failure == "" || failure == "non-success-probe" || insecure {
				if err == nil {
					_, err = c.call(context.Background(), nfsProgram, 3, 0, nil, nil)
				}
				if err != nil {
					t.Error(err)
				}
				owner := &Client{nfs: c}
				if !owner.TLSActive() || owner.TLSCertificateVerified() == insecure {
					t.Error("TLS verification status does not match the negotiated policy")
				}
			} else if err == nil {
				t.Error("accepted invalid TLS peer/upgrade")
			}
			client.Close()
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
}

func TestTLSConfigurationRefusesDowngrade(t *testing.T) {
	for _, cfg := range []Config{
		{TLS: TLSConfig{InsecureSkipVerify: true}},
		{TLS: TLSConfig{CAFile: "ca.pem"}},
		{Transport: "udp", TLS: TLSConfig{Enabled: true}},
		{Transport: "tcp", TLS: TLSConfig{Enabled: true, CertFile: "client.pem"}},
	} {
		if _, err := cfg.tlsConfig(); err == nil {
			t.Fatal("accepted incomplete TLS policy")
		}
	}
}
