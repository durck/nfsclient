package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"golang.org/x/net/dns/dnsmessage"
	"nfs-viewer/internal/testutil/dnsfixture"
)

func TestKerberosCustomDNS(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_PORT") == "" {
		t.Skip("requires local MIT/Ganesha fixture")
	}
	base, err := config.Load(os.Getenv("NFS_VIEWER_KRB5_CONFIG"))
	if err != nil || len(base.Realms) != 1 || len(base.Realms[0].KDC) != 1 {
		t.Fatalf("fixture KDC configuration: %v", err)
	}
	_, port, err := net.SplitHostPort(base.Realms[0].KDC[0])
	if err != nil {
		t.Fatal(err)
	}
	kdcPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	versions := []string{"3"}
	if os.Getenv("NFS_VIEWER_KRB5_V4") == "1" {
		versions = append(versions, "4.2")
	}
	for _, version := range versions {
		for _, tcp := range []bool{false, true} {
			for _, srv := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/tcp=%t/srv=%t", version, tcp, srv), func(t *testing.T) {
					var kdcQueries, nfsQueries, srvQueries atomic.Int32
					dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message {
						r := dnsfixture.Loopback(q)
						if len(q.Questions) != 1 {
							return r
						}
						question := q.Questions[0]
						switch strings.ToLower(question.Name.String()) {
						case "nfs.synthetic.invalid.":
							nfsQueries.Add(1)
						case "kdc.synthetic.invalid.":
							kdcQueries.Add(1)
						case "_kerberos._tcp.nfs.test.":
							srvQueries.Add(1)
							target, _ := dnsmessage.NewName("kdc.synthetic.invalid.")
							r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.SRVResource{Port: uint16(kdcPort), Target: target}}}
						}
						return r
					})
					configuration := fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n dns_lookup_kdc = %t\n dns_lookup_realm = false\n rdns = false\n udp_preference_limit = 1\n", srv)
					if !srv {
						configuration += fmt.Sprintf("[realms]\n NFS.TEST = {\n kdc = kdc.synthetic.invalid.:%d\n }\n", kdcPort)
					}
					path := filepath.Join(t.TempDir(), "krb5.conf")
					if err := os.WriteFile(path, []byte(configuration), 0600); err != nil {
						t.Fatal(err)
					}
					args := []string{"nfs.synthetic.invalid.", "--dns-server", dns.Address, fmt.Sprintf("--dns-tcp=%t", tcp), "--nfs-version", version, "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"), "--sec", "krb5p", "--krb5-config", path, "--keytab", os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), "--principal", "root@NFS.TEST", "--spn", "nfs/server.nfs.test", "--export", "/private", "--auto-escape=false", "--no-banner", "--color", "never", "-c", "pwd"}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					var out bytes.Buffer
					var err error
					if binary := os.Getenv("NFS_VIEWER_TEST_BINARY"); binary != "" {
						b, e := exec.CommandContext(ctx, binary, args...).CombinedOutput()
						out.Write(b)
						err = e
					} else {
						cmd := NewCommand(strings.NewReader(""), &out, &out)
						cmd.SetArgs(args)
						err = cmd.ExecuteContext(ctx)
					}
					if err != nil {
						t.Fatalf("Kerberos custom DNS: %v\n%s", err, out.String())
					}
					if kdcQueries.Load() == 0 || nfsQueries.Load() == 0 || srv && srvQueries.Load() == 0 {
						t.Fatalf("missing routed lookups: NFS=%d KDC=%d SRV=%d", nfsQueries.Load(), kdcQueries.Load(), srvQueries.Load())
					}
					if tcp && (dns.UDP.Load() != 0 || dns.TCP.Load() == 0) || !tcp && (dns.TCP.Load() != 0 || dns.UDP.Load() == 0) {
						t.Fatal("Kerberos ignored DNS transport")
					}
				})
			}
		}
	}
}

func TestCustomDNSCLI(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprint(tcp), func(t *testing.T) {
			root, port := testServer(t)
			if err := os.WriteFile(filepath.Join(root, "dns-fixture.txt"), []byte("DNS reached the local NFS fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message { return dnsfixture.Loopback(q) })
			args := []string{"nfs.synthetic.invalid.", "--dns-server", dns.Address, fmt.Sprintf("--dns-tcp=%t", tcp), "--nfs-version", "3", "--mount-port", fmt.Sprint(port), "--nfs-port", fmt.Sprint(port), "--export", "/", "--auto-escape=false", "--no-banner", "--color", "never", "-c", "cat dns-fixture.txt"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var out bytes.Buffer
			var err error
			if binary := os.Getenv("NFS_VIEWER_TEST_BINARY"); binary != "" {
				var b []byte
				b, err = exec.CommandContext(ctx, binary, args...).CombinedOutput()
				out.Write(b)
			} else {
				cmd := NewCommand(strings.NewReader(""), &out, &out)
				cmd.SetArgs(args)
				err = cmd.ExecuteContext(ctx)
			}
			if err != nil || !strings.Contains(out.String(), "DNS reached the local NFS fixture") {
				t.Fatalf("custom DNS CLI: %v\n%s", err, out.String())
			}
			if tcp && (dns.UDP.Load() != 0 || dns.TCP.Load() == 0) || !tcp && (dns.TCP.Load() != 0 || dns.UDP.Load() == 0) {
				t.Fatal("CLI ignored requested DNS transport")
			}
		})
	}
}
