package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"nfsclient/internal/testutil/kdcfixture"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestPureGoASNativeWire(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PUREGO_AS_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT FAST/PKINIT KDC")
	}
	dir := os.Getenv("NFS_VIEWER_PUREGO_AS_FILES")
	for _, mechanism := range []string{"fast", "pkinit", "fast-pkinit"} {
		for _, network := range []string{"tcp", "udp"} {
			modes := []string{"valid", "aes128", "stripped", "tampered", "wrong-realm"}
			if mechanism == "fast" {
				modes = append(modes, "armor-key", "armor-expired", "armor-missing")
			} else {
				modes = append(modes, "wrong-ca", "foreign-cert", "key-mismatch", "expired-cert", "revoked-kdc", "malformed-crl")
			}
			if mechanism == "pkinit" {
				modes = append(modes, "no-freshness")
			}
			if mechanism == "fast-pkinit" {
				modes = append(modes, "armor-key", "armor-expired", "armor-missing")
			}
			for _, mode := range modes {
				t.Run(mechanism+"/"+network+"/"+mode, func(t *testing.T) {
					cfg, err := config.Load(os.Getenv("NFS_VIEWER_PUREGO_AS_CONFIG"))
					if err != nil {
						t.Fatal(err)
					}
					if len(cfg.Realms) != 1 || len(cfg.Realms[0].KDC) != 1 {
						t.Fatal("requires one explicit disposable KDC")
					}
					target := cfg.Realms[0].KDC[0]
					var protected, plain, changed atomic.Int32
					peer := kdcfixture.Start(t, func(transport string, wire []byte) []byte {
						var req messages.ASReq
						if req.Unmarshal(wire) == nil {
							if req.PAData.Contains(2) {
								plain.Add(1)
							}
							if (mechanism == "fast" || mechanism == "fast-pkinit") && req.PAData.Contains(136) || mechanism == "pkinit" && req.PAData.Contains(16) {
								protected.Add(1)
							}
							if (mechanism == "fast" || mechanism == "fast-pkinit") && !req.PAData.Contains(136) {
								t.Error("unarmored required FAST request")
							}
						}
						reply := nativeASForward(t, transport, target, wire)
						filter := func(pa types.PADataSequence) types.PADataSequence {
							out := make(types.PADataSequence, 0, len(pa))
							for _, p := range pa {
								selected := (mechanism == "fast" || mechanism == "fast-pkinit") && p.PADataType == 136 || mechanism == "pkinit" && (p.PADataType == 16 || p.PADataType == 17)
								if selected && mode == "stripped" || mode == "no-freshness" && p.PADataType == 150 {
									changed.Add(1)
									continue
								}
								if selected && mode == "tampered" && len(p.PADataValue) > 0 {
									p.PADataValue = append([]byte(nil), p.PADataValue...)
									p.PADataValue[len(p.PADataValue)-1] ^= 1
									changed.Add(1)
								}
								out = append(out, p)
							}
							return out
						}
						var failure messages.KRBError
						if failure.Unmarshal(reply) == nil {
							var pa types.PADataSequence
							if _, err := asn1.Unmarshal(failure.EData, &pa); err == nil {
								failure.EData, _ = asn1.Marshal(filter(pa))
								reply, _ = failure.Marshal()
							}
						} else {
							var rep messages.ASRep
							if rep.Unmarshal(reply) == nil {
								rep.PAData = filter(rep.PAData)
								reply, _ = rep.Marshal()
							}
						}
						return reply
					})
					cfg.Realms[0].KDC = []string{peer.Address}
					cfg.LibDefaults.UDPPreferenceLimit = 1
					if network == "udp" {
						cfg.LibDefaults.UDPPreferenceLimit = 32700
					}
					if mode == "aes128" {
						cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{17}
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					var cl *Client
					var loginErr error
					if mechanism == "fast" {
						kt, err := keytab.Load(filepath.Join(dir, "alice.keytab"))
						if err != nil {
							t.Fatal(err)
						}
						armor, err := credentials.LoadCCache(filepath.Join(dir, "alice.ccache"))
						if err != nil {
							t.Fatal(err)
						}
						switch mode {
						case "wrong-realm":
							armor.DefaultPrincipal.Realm = "OTHER.TEST"
						case "armor-missing":
							armor.Credentials = nil
						case "armor-key":
							for _, c := range armor.Credentials {
								if len(c.Key.KeyValue) > 0 {
									c.Key.KeyValue[0] ^= 1
								}
							}
						case "armor-expired":
							for _, c := range armor.Credentials {
								c.EndTime = time.Now().Add(-time.Hour)
							}
						}
						cl = NewWithKeytab("alice", "NFS.TEST", kt, cfg, NetworkContext(ctx))
						loginErr = cl.LoginFAST(armor)
					} else {
						files := PKINITIdentity{Cert: filepath.Join(dir, "client.crt"), Key: filepath.Join(dir, "client.key"), CA: filepath.Join(dir, "ca.crt"), CRL: filepath.Join(dir, "clean.crl")}
						realm := "NFS.TEST"
						switch mode {
						case "wrong-realm":
							realm = "OTHER.TEST"
						case "wrong-ca":
							files.CA = filepath.Join(dir, "other-ca.crt")
						case "foreign-cert":
							files.Cert = filepath.Join(dir, "foreign.crt")
							files.Key = filepath.Join(dir, "foreign.key")
						case "key-mismatch":
							files.Key = filepath.Join(dir, "foreign.key")
						case "expired-cert":
							files.Cert = filepath.Join(dir, "expired.crt")
							files.Key = filepath.Join(dir, "expired.key")
						case "revoked-kdc":
							files.CRL = filepath.Join(dir, "revoked.crl")
						case "malformed-crl":
							files.CRL = filepath.Join(dir, "client.crt")
						}
						cl = NewWithPassword("root", realm, "", cfg, NetworkContext(ctx))
						if mechanism == "fast-pkinit" {
							armor, err := credentials.LoadCCache(filepath.Join(dir, "alice.ccache"))
							if err != nil {
								t.Fatal(err)
							}
							switch mode {
							case "armor-missing":
								armor.Credentials = nil
							case "armor-expired":
								for _, c := range armor.Credentials {
									c.EndTime = time.Now().Add(-time.Hour)
								}
							case "armor-key":
								for _, c := range armor.Credentials {
									if len(c.Key.KeyValue) > 0 {
										c.Key.KeyValue[0] ^= 1
									}
								}
							}
							loginErr = cl.LoginFASTPKINIT(files, armor)
						} else {
							loginErr = cl.LoginPKINIT(files)
						}
					}
					defer cl.Destroy()
					if mode == "valid" || mode == "aes128" {
						if loginErr != nil {
							t.Fatal(loginErr)
						}
						if _, key, err := cl.GetServiceTicket("nfs/server.nfs.test"); err != nil || len(key.KeyValue) == 0 {
							t.Fatal("native service ticket", err)
						}
						if protected.Load() < 1 {
							t.Fatal("missing protected AS request")
						}
						if network == "udp" && peer.UDP.Load() < 2 || network == "tcp" && peer.TCP.Load() < 2 {
							t.Fatal("required KDC transport unobserved")
						}
					} else if loginErr == nil {
						t.Fatal("unsafe native AS accepted")
					}
					if plain.Load() != 0 {
						t.Fatal("plaintext timestamp fallback")
					}
					if mode == "stripped" || mode == "tampered" || mode == "no-freshness" {
						if changed.Load() == 0 {
							t.Fatal("negative control did not alter native response")
						}
					}
				})
			}
		}
	}
}

func nativeASForward(t *testing.T, network, target string, wire []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout(network, target, time.Second)
	if err != nil {
		t.Error(err)
		return nil
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if network == "udp" {
		if _, err := c.Write(wire); err != nil {
			t.Error(err)
			return nil
		}
		reply := make([]byte, 65536)
		n, err := c.Read(reply)
		if err != nil {
			t.Error(err)
			return nil
		}
		return reply[:n]
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(wire)))
	packet = append(packet, wire...)
	if _, err := c.Write(packet); err != nil {
		t.Error(err)
		return nil
	}
	var prefix [4]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Error(err)
		return nil
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > 1<<20 {
		t.Error("invalid native KDC record")
		return nil
	}
	reply := make([]byte, n)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Error(err)
		return nil
	}
	return reply
}
