package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestReadReplicaPreflight(t *testing.T) {
	cfg := Config{Host: "original.test", Version: "4.1", Transport: "tcp", Security: "krb5p", Timeout: time.Second}
	c := &Client{config: &cfg, version: "4.1", security: "krb5p"}
	good := ReadReplica{Address: "127.0.0.1:2049", SPN: "nfs/backup.test"}
	if err := c.ValidateReadReplica(good); err != nil {
		t.Fatal(err)
	}
	for _, target := range []ReadReplica{{}, {Address: "host:0", SPN: good.SPN}, {Address: "host:65536", SPN: good.SPN}, {Address: "host:2049"}, {Address: "host:2049", SPN: good.SPN, TLSName: "unused"}, {Address: " host:2049", SPN: good.SPN}} {
		if err := c.ValidateReadReplica(target); err == nil {
			t.Fatalf("accepted %+v", target)
		}
	}
	for _, spn := range []string{"service", "nfs/", "nfs/host@REALM", "nfs/host name", "nfs/host\x00"} {
		invalid := good
		invalid.SPN = spn
		if c.ValidateReadReplica(invalid) == nil {
			t.Fatal("accepted malformed SPN", spn)
		}
	}
	for _, mode := range []string{"legacy", "unprotected", "insecure", "callback", "rdma"} {
		t.Run(mode, func(t *testing.T) {
			copyCfg := cfg
			other := Client{config: &copyCfg, version: c.version, security: c.security}
			modeTarget := good
			switch mode {
			case "legacy":
				other.version = "3"
			case "unprotected":
				other.security = "sys"
			case "insecure":
				copyCfg.TLS = TLSConfig{Enabled: true, InsecureSkipVerify: true}
				modeTarget.TLSName = "backup.test"
			case "callback":
				copyCfg.PNFS = true
			case "rdma":
				copyCfg.Transport = "iwarp"
			}
			if err := other.ValidateReadReplica(modeTarget); err == nil {
				t.Fatal("accepted unsafe profile")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ConnectReadReplica(ctx, good); !errors.Is(err, context.Canceled) {
		t.Fatal("accepted cancelled attempt")
	}
}

func readReplicaPeer(t *testing.T, minor uint32) *v4Client {
	return peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 35:
			d.take(8)
			d.str()
			d.u32()
			d.str()
			d.str()
			d.u32()
			e.u64(123)
			e = append(e, make([]byte, 8)...)
		case 36:
			d.take(16)
		case 30, 57:
			d.take(8)
		case 42:
			d.take(8)
			d.str()
			d.take(12)
			e.u64(123)
			e.u32(1)
			e.u32(0x10000)
			e.u32(0)
			e.u64(1)
			e.str("replica")
			e.str("scope")
			e.u32(0)
		case 43:
			d.u64()
			sequence := d.u32()
			d.take(68)
			e = createSequenceReply(sequence)
		case 53:
			e = append(e, d.take(16)...)
			e.u32(d.u32())
			d.take(12)
			for range 4 {
				e.u32(0)
			}
		case 58:
			d.boolean()
		case 24:
		case 10:
			e.str("root")
		case 9:
			if fmt.Sprint(readBitmap4(d)) != "[10]" {
				return nil, 0, errors.New("unexpected metadata request")
			}
			bitmap4(&e, 10)
			var lease encoder
			lease.u32(60)
			e.opaque(lease)
		case 44:
			d.take(16)
		default:
			return nil, 0, fmt.Errorf("unexpected operation %d", code)
		}
		return e, 0, nil
	})
}

func TestReadReplicaTLS(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, mode := range []string{"tls-client-cert", "tls-wrong-name", "tls-untrusted", "tls-no-alpn"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				policy, serverTLS := pnfsTLSFixture(t, mode)
				peer := readReplicaPeer(t, minor)
				endpoint := pnfsTLSPeerEndpoint(t, peer, serverTLS(0), mode)
				cfg := Config{Version: fmt.Sprintf("4.%d", minor), Timeout: time.Second, TLS: policy}
				original := &Client{config: &cfg, version: cfg.Version}
				target := ReadReplica{Address: endpoint, TLSName: "ds-0.test"}
				if mode == "tls-wrong-name" {
					target.TLSName = "wrong.test"
				}
				fresh, err := original.ConnectReadReplica(context.Background(), target)
				if mode == "tls-client-cert" {
					if err != nil {
						t.Fatal(err)
					}
					defer fresh.Close()
					if !fresh.TLSCertificateVerified() || fresh.config.TLS.ServerName != target.TLSName || fresh.Identity() != original.Identity() {
						t.Fatal("target policy changed")
					}
				} else if err == nil {
					fresh.Close()
					t.Fatal("unsafe TLS accepted")
				}
			})
		}
	}
}

func TestMITReadReplica(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				t.Run(fmt.Sprintf("4.%d/%s/tls=%v", minor, security, secure), func(t *testing.T) {
					cfg := pnfsMITConfig(t, security, "nfs/server.nfs.test")
					cfg.PNFS = false
					cfg.Version = fmt.Sprintf("4.%d", minor)
					peer := readReplicaPeer(t, minor)
					options := mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]}
					if secure {
						policy, server := pnfsTLSFixture(t, "tls-client-cert")
						cfg.TLS = policy
						options.server = server(0)
						options.client = policy
					}
					endpoint := pnfsMITEndpoint(t, peer.c.nfs.conn, nil, options)
					host, port, _ := net.SplitHostPort(endpoint)
					cfg.Host = host
					cfg.NFSPort, _ = strconv.Atoi(port)
					original := &Client{config: &cfg, version: cfg.Version, security: security, principal: cfg.Kerberos.Principal}
					original.v4 = &v4Client{c: original, clientNonce: bytes.Repeat([]byte{6}, 16)}
					target := ReadReplica{Address: endpoint, SPN: cfg.Kerberos.SPN}
					if secure {
						target.TLSName = "ds-0.test"
					}
					fresh, err := original.ConnectReadReplica(context.Background(), target)
					if err != nil {
						t.Fatal(err)
					}
					defer fresh.Close()
					if fresh.nfs.gss == nil || fresh.Identity() != original.Identity() || bytes.Equal(fresh.v4.clientNonce, original.v4.clientNonce) || fresh.v4.creates != nil && fresh.v4.creates == original.v4.creates {
						t.Fatal("security or fresh state violated")
					}
					if secure && !fresh.TLSCertificateVerified() {
						t.Fatal("certificate not verified")
					}
				})
			}
		}
	}
}
