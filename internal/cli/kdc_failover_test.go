package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/testutil/dnsfixture"
	"nfsclient/internal/testutil/kdcfixture"
)

func TestKerberosKDCFailover(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_REPLICA_TCP_PORT") == "" {
		t.Skip("requires the disposable two-KDC fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				if version == "3-udp" && security != "krb5" {
					continue
				}
				for _, credential := range []string{"keytab", "ccache"} {
					t.Run(network+"/"+version+"/"+security+"/"+credential, func(t *testing.T) {
						t.Parallel()
						testKDCFailoverCLI(t, network, version, security, credential, "switch-tgs", false)
					})
				}
			}
		}
		for _, fault := range []string{"silent", "denied"} {
			t.Run(network+"/"+fault, func(t *testing.T) { t.Parallel(); testKDCFailoverCLI(t, network, "3", "krb5p", "keytab", fault, false) })
		}
		t.Run(network+"/SRV", func(t *testing.T) {
			t.Parallel()
			testKDCFailoverCLI(t, network, "4.2", "krb5p", "keytab", "silent", true)
		})
	}
}

func testKDCFailoverCLI(t *testing.T, network, version, security, credential, fault string, srv bool) {
	t.Helper()
	if credential == "ccache" && os.Getenv("NFS_VIEWER_KRB5_CCACHE") == "" {
		t.Skip("requires explicit root FILE cache")
	}
	base, err := config.Load(os.Getenv("NFS_VIEWER_KRB5_CONFIG"))
	if err != nil || len(base.Realms) != 1 || len(base.Realms[0].KDC) != 1 {
		t.Fatalf("invalid local fixture config: %v", err)
	}
	primary := base.Realms[0].KDC[0]
	host, _, err := net.SplitHostPort(primary)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("fixture requires loopback KDC")
	}
	replica := net.JoinHostPort(host, os.Getenv("NFS_VIEWER_KRB5_REPLICA_TCP_PORT"))
	if network == "udp" {
		primary = net.JoinHostPort(host, os.Getenv("NFS_VIEWER_KRB5_KDC_UDP_PORT"))
		replica = net.JoinHostPort(host, os.Getenv("NFS_VIEWER_KRB5_REPLICA_UDP_PORT"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	forward := func(address string, request []byte) []byte {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		if err != nil {
			t.Errorf("local KDC relay connection: %v", err)
			return nil
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		var reply []byte
		if network == "tcp" {
			err = writeKDCFixtureRecord(c, request)
			if err == nil {
				reply, err = readKDCFixtureRecord(c)
			}
		} else {
			_, err = c.Write(request)
			if err == nil {
				buf := make([]byte, 65536)
				var n int
				n, err = c.Read(buf)
				reply = buf[:n]
			}
		}
		if err != nil && ctx.Err() == nil {
			t.Errorf("local KDC relay exchange: %v", err)
		}
		return reply
	}
	code := errorcode.KDC_ERR_SVC_UNAVAILABLE
	if fault == "denied" {
		code = errorcode.KDC_ERR_PREAUTH_FAILED
	}
	e := messages.NewKRBError(types.PrincipalName{NameString: []string{"krbtgt", "NFS.TEST"}}, "NFS.TEST", code, "synthetic fault injection")
	errorWire, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var primaryAS, failedTGS, replicaTGS atomic.Int32
	var silentMu sync.Mutex
	var silentRequest []byte
	var silentChanged atomic.Bool
	first := kdcfixture.Start(t, func(actual string, request []byte) []byte {
		if actual != network {
			t.Error("KDC transport changed")
			return errorWire
		}
		if fault == "silent" {
			silentMu.Lock()
			if silentRequest == nil {
				silentRequest = bytes.Clone(request)
			} else if !bytes.Equal(silentRequest, request) {
				silentChanged.Store(true)
			}
			silentMu.Unlock()
			return nil
		}
		if fault == "denied" {
			return errorWire
		}
		if len(request) > 0 && request[0] == 0x6c {
			failedTGS.Add(1)
			return errorWire
		}
		if len(request) > 0 && request[0] == 0x6a {
			primaryAS.Add(1)
		}
		return forward(primary, request)
	})
	second := kdcfixture.Start(t, func(actual string, request []byte) []byte {
		if actual != network {
			t.Error("KDC transport changed")
			return nil
		}
		if len(request) > 0 && request[0] == 0x6c {
			replicaTGS.Add(1)
		}
		return forward(replica, request)
	})
	t.Cleanup(cancel)
	pref := 1
	if network == "udp" {
		pref = 32700
	}
	conf := fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n dns_lookup_kdc = %t\n dns_lookup_realm = false\n rdns = false\n udp_preference_limit = %d\n", srv, pref)
	var dns *dnsfixture.Server
	var queries atomic.Int32
	if srv {
		dns = dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message {
			r := dnsfixture.Loopback(q)
			if len(q.Questions) == 1 && q.Questions[0].Type == dnsmessage.TypeSRV && strings.EqualFold(q.Questions[0].Name.String(), "_kerberos._"+network+".nfs.test.") {
				queries.Add(1)
				for i, address := range []string{first.Address, second.Address} {
					_, p, _ := net.SplitHostPort(address)
					port, _ := strconv.Atoi(p)
					name, _ := dnsmessage.NewName(fmt.Sprintf("kdc%d.synthetic.invalid.", i))
					r.Answers = append(r.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SRVResource{Target: name, Port: uint16(port), Priority: uint16(i * 10)}})
				}
			}
			return r
		})
	} else {
		conf += fmt.Sprintf("[realms]\n NFS.TEST = {\n kdc = %s\n kdc = %s\n }\n", first.Address, second.Address)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(configPath, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"127.0.0.1", "--nfs-version", version, "--sec", security, "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"), "--krb5-config", configPath, "--principal", "root@NFS.TEST", "--spn", "nfs/server.nfs.test", "--export", "/data", "--auto-escape=false", "--timeout", "3s", "--no-banner", "--color", "never", "--progress", "never"}
	if version == "3-udp" {
		args = append(args, "--nfs-version", "3", "--transport", "udp", "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
	}
	if credential == "ccache" {
		args = append(args, "--ccache", os.Getenv("NFS_VIEWER_KRB5_CCACHE"))
	} else {
		args = append(args, "--keytab", os.Getenv("NFS_VIEWER_KRB5_KEYTAB"))
	}
	if srv {
		args = append(args, "--dns-server", dns.Address, "--dns-tcp")
	}
	if fault == "denied" {
		out, err := runKerberosCLI(t, append(args, "-c", "pwd"))
		if err == nil || second.TCP.Load()+second.UDP.Load() != 0 {
			t.Fatalf("authentication denial routed around: %v %s", err, out)
		}
		return
	}
	source, dest := filepath.Join(dir, "source.bin"), filepath.Join(dir, "dest.bin")
	payload := bytes.Repeat([]byte{0, 255, 27, 'F'}, 2400)
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("failover-%x", nonce)
	args = append(args, "-c", "put "+strconv.Quote(source)+" "+name, "-c", "get "+name+" "+strconv.Quote(dest), "-c", "id")
	out, err := runKerberosCLI(t, args)
	if err != nil || !strings.Contains(out, "root@NFS.TEST ("+security+")") {
		t.Fatalf("replica-authenticated CLI: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("failover content: %v", err)
	}
	if replicaTGS.Load() == 0 {
		t.Fatal("replica did not issue service ticket")
	}
	if fault == "switch-tgs" && (failedTGS.Load() != 1 || credential == "keytab" && primaryAS.Load() == 0) {
		t.Fatal("AS/TGS did not cross actual primary/replica")
	}
	if fault == "silent" {
		count, limit := first.TCP.Load()+first.UDP.Load(), int32(1)
		if network == "udp" {
			limit = 3 // Identical datagram retransmissions are allowed in one exchange.
		}
		if count < 1 || count > limit || silentChanged.Load() {
			t.Fatal("silent KDC retried during later login exchanges")
		}
	}
	if srv && (queries.Load() == 0 || dns.UDP.Load() != 0 || dns.TCP.Load() == 0) {
		t.Fatal("SRV discovery ignored selected DNS transport")
	}
}
