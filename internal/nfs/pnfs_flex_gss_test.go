package nfs

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// MIT supplies the tickets; NFS peers remain scripted. Each network endpoint
// verifies RPCSEC_GSS and the exact requested service, with TLS binding if used.
type flexMITProfile struct {
	failover         bool
	mirrorFailover   bool
	refreshMode      string
	connections      atomic.Int32
	allowDSReadAbort bool
	security         string
	options          mitTLSOptions
}

func flexMITSelected(profiles []*flexMITProfile) *flexMITProfile {
	if len(profiles) == 0 {
		return nil
	}
	return profiles[0]
}

func newFlexMITProfile(t *testing.T, security string, secure bool) *flexMITProfile {
	p := &flexMITProfile{security: security}
	p.options.expectedService = map[string]uint32{"krb5": 1, "krb5i": 2, "krb5p": 3}[security]
	if secure {
		policy, server := pnfsTLSFixture(t, "data")
		p.options.client, p.options.server = policy, server(0)
	}
	return p
}

func (p *flexMITProfile) endpoint(t *testing.T, peer *v4Client, o *PNFSOptions, drop int) string {
	opts := p.options
	opts.accepted = &p.connections
	opts.allowReadAbort = p.allowDSReadAbort
	opts.dropDataReply = drop
	endpoint := pnfsMITEndpoint(t, peer.c.nfs.conn, nil, opts)
	if o.SPNs == nil {
		o.SPNs = map[string]string{}
	}
	o.SPNs[endpoint] = "nfs/ds.nfs.test"
	if opts.server != nil {
		if o.TLSNames == nil {
			o.TLSNames = map[string]string{}
		}
		o.TLSNames[endpoint] = "127.0.0.1"
	}
	return endpoint
}

func (p *flexMITProfile) wrap(t *testing.T, c *Client) {
	pnfsMITWrapClient(t, c, p.security, nil, p.options)
}

func TestFlexMITRead(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, width := range []int{1, 3} {
					for _, mode := range []string{"data", "short", "holes", "denied", "bad-count", "zero", "recall", "return-failure", "loose"} {
						t.Run(fmt.Sprintf("4.%d/%s/tls=%v/w%d/%s", minor, security, secure, width, mode), func(t *testing.T) {
							runFlexReadWire(t, minor, 2, width, width, mode, newFlexMITProfile(t, security, secure))
						})
					}
				}
			}
		}
	}
}

func TestFlexMITWrite(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, width := range []int{1, 3} {
					for _, mode := range []string{"stable", "short", "unstable", "data-sync", "one-mirror", "denied", "commit-error", "layout-error", "recall", "cancel", "drop", "loose"} {
						t.Run(fmt.Sprintf("4.%d/%s/tls=%v/w%d/%s", minor, security, secure, width, mode), func(t *testing.T) {
							runFlexWriteWire(t, minor, 4, 2, width, width, mode, newFlexMITProfile(t, security, secure))
						})
					}
				}
			}
		}
	}
}

func TestFlexMITBackchannel(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", secure), func(t *testing.T) { runPNFSMITBackchannel(t, secure, 4) })
	}
}

func TestFlexGSSPoolRefusesBeforeDial(t *testing.T) {
	for _, mode := range []string{"loose", "missing", "service", "principal", "spn", "configured-only"} {
		t.Run(mode, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			endpoint := l.Addr().String()
			cfg := Config{Security: "krb5p", Timeout: time.Millisecond * 100, Kerberos: KerberosConfig{Principal: "root@NFS.TEST", SPN: "nfs/ds.nfs.test"}}
			c := &Client{config: &cfg, security: "krb5p", principal: cfg.Kerberos.Principal}
			ds := &flexDS{major: 4, minor: 1, endpoints: []string{endpoint}}
			auth := cfg
			switch mode {
			case "loose":
				ds.major = 3
			case "service":
				auth.Security = "sys"
			case "principal":
				auth.Kerberos.Principal = "other@NFS.TEST"
			case "spn":
				auth.Kerberos.SPN = ""
			case "configured-only":
				c.security = ""
			}
			configs := map[string]Config{endpoint: auth}
			if mode == "missing" {
				delete(configs, endpoint)
			}
			get, _, _, closePool := c.pnfsFlexServers(context.Background(), nil, configs, func() error { return nil })
			defer closePool()
			if _, _, err = get(ds); err == nil {
				t.Fatal("unsafe profile accepted")
			}
			l.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond))
			conn, err := l.Accept()
			if err == nil {
				conn.Close()
				t.Fatal("DS contacted before security validation")
			}
		})
	}
}
