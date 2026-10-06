package nfs

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/krbconfig"
	bgss "nfsclient/internal/krbgss"
	"nfsclient/internal/sspi"
)

func TestSSPIProfilePreflight(t *testing.T) {
	for _, mode := range []string{"valid", "sys", "principal", "spn", "file-config", "ccache", "keytab", "pkinit", "fast", "tls", "pnfs", "offload", "gss-v3", "provider"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Host: "server.invalid", Version: "3", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{Provider: "sspi", Principal: "user@EXAMPLE.TEST", SPN: "nfs/server.test"}}
			switch mode {
			case "sys":
				cfg.Security = "sys"
			case "principal":
				cfg.Kerberos.Principal = ""
			case "spn":
				cfg.Kerberos.SPN = "HTTP/server.test"
			case "file-config":
				cfg.Kerberos.ConfigFile = "not-opened"
			case "ccache":
				cfg.Kerberos.CCache = "MSLSA:CURRENT"
			case "keytab":
				cfg.Kerberos.Keytab = "not-opened"
			case "pkinit":
				cfg.Kerberos.PKINIT.Cert = "not-opened"
			case "fast":
				cfg.Kerberos.RequireFAST = true
			case "tls":
				cfg.TLS.Enabled = true
			case "pnfs":
				cfg.PNFS = true
				cfg.Version = "4.1"
			case "offload":
				cfg.Offload = true
				cfg.Version = "4.2"
			case "gss-v3":
				cfg.Kerberos.RPCVersion = 3
			case "provider":
				cfg.Kerberos.Provider = "negotiate"
			}
			err := validateSecurity(&cfg)
			if mode == "valid" && runtime.GOOS == "windows" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsupported SSPI profile accepted")
			}
			if runtime.GOOS != "windows" && mode != "provider" && !errors.Is(err, sspi.ErrUnsupported) {
				t.Fatal("platform refusal lost", err)
			}
		})
	}
}

// The shared provider boundary uses a separately established real Kerberos
// mechanism and an independent acceptor/RPC peer. This validates all RPCSEC_GSS
// framing without pretending that a portable mechanism is a native SSPI test.
type checkedProvider struct {
	*bgss.Initiator
	closed atomic.Int32
}

func (p *checkedProvider) Close() error { p.closed.Add(1); return p.Initiator.Close() }

func TestGSSProviderHandshakeRPC(t *testing.T) {
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		for _, version := range []uint32{2, 3, 4} {
			for _, fault := range []string{"success", "bad-mic"} {
				t.Run(security+"/"+string(rune('0'+version))+"/"+fault, func(t *testing.T) {
					k, key := autoCredentials(t)
					target := string(rune('0' + version))
					if version == 4 {
						target = "4.1"
					}
					peer := &autoPeer{t: t, keytab: key, target: target, mode: fault}
					port, stop := peer.listen()
					defer stop()
					ctx := context.Background()
					r, err := dialRPC(ctx, "127.0.0.1", port, time.Second, false)
					if err != nil {
						t.Fatal(err)
					}
					defer r.conn.Close()
					snapshot, err := krbconfig.Load(k.ConfigFile)
					if err != nil {
						t.Fatal(err)
					}
					init, err := bgss.NewInitiator(bgss.WithConfigSnapshot(snapshot), bgss.WithRealm[bgss.Initiator]("NFS.TEST"), bgss.WithUsername[bgss.Initiator]("root"), bgss.WithCCache(k.CCache), bgss.WithNetworkContext(ctx))
					if err != nil {
						t.Fatal(err)
					}
					provider := &checkedProvider{Initiator: init}
					selected := KerberosConfig{Provider: "sspi", Principal: k.Principal, SPN: k.SPN}
					r.mu.Lock()
					cleanup, err := r.establishGSSInitiatorLocked(ctx, selected, security, version, provider)
					r.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
					var args encoder
					proc := uint32(0)
					if version == 4 {
						proc = 1
						args.str("")
						args.u32(1)
						args.u32(0)
					}
					_, err = r.call(ctx, nfsProgram, version, proc, nil, args)
					if fault == "bad-mic" {
						if err == nil || !strings.Contains(err.Error(), "signature") {
							t.Fatal("tampered response accepted", err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
					if fault == "success" {
						r.destroyKerberos(ctx)
					}
					cleanup()
					r.conn.Close()
					stop()
					if provider.closed.Load() != 1 {
						t.Fatal("provider cleanup count", provider.closed.Load())
					}
					peer.mu.Lock()
					calls := peer.init
					peer.mu.Unlock()
					if calls != 1 {
						t.Fatal("failed request retried or changed mechanism", calls)
					}
				})
			}
		}
	}
}
