package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/testutil/dnsfixture"
	"nfsclient/internal/testutil/loopback"
)

func TestKerberosKDCUDP(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_KDC_UDP_PORT") == "" {
		t.Skip("requires local MIT KDC UDP port")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			if version == "3-udp" && security != "krb5" {
				continue
			}
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					testKerberosKDCUDP(t, version, security, credential, "", false)
				})
			}
		}
	}
	t.Run("SRV-over-DNS-TCP", func(t *testing.T) {
		testKerberosKDCUDP(t, "4.2", "krb5p", "keytab", "", true)
	})
	if os.Getenv("NFS_VIEWER_KRB5_KDC_SMALL") != "1" {
		for _, loss := range []string{"as", "tgs", "blackhole"} {
			t.Run("loss-"+loss, func(t *testing.T) {
				testKerberosKDCUDP(t, "3", "krb5p", "keytab", loss, false)
			})
		}
	}
}

func testKerberosKDCUDP(t *testing.T, version, security, credential, loss string, srv bool) {
	t.Helper()
	if credential == "ccache" && os.Getenv("NFS_VIEWER_KRB5_CCACHE") == "" {
		t.Skip("requires explicit root FILE cache")
	}
	base, err := config.Load(os.Getenv("NFS_VIEWER_KRB5_CONFIG"))
	if err != nil || len(base.Realms) != 1 || len(base.Realms[0].KDC) != 1 {
		t.Fatalf("invalid local fixture KDC configuration: %v", err)
	}
	upstream := base.Realms[0].KDC[0]
	host, _, err := net.SplitHostPort(upstream)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("KDC fixture must use a literal loopback address")
	}
	udpPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_KDC_UDP_PORT"))
	if err != nil || udpPort < 1 || udpPort > 65535 {
		t.Fatal("invalid fixture KDC UDP port")
	}
	relay := startKDCRelay(t, upstream, net.JoinHostPort(host, strconv.Itoa(udpPort)), loss)
	configuration := fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n dns_lookup_kdc = %t\n dns_lookup_realm = false\n rdns = false\n udp_preference_limit = 32700\n", srv)
	var dns *dnsfixture.Server
	var udpSRV, tcpSRV atomic.Int32
	if srv {
		_, relayPort, _ := net.SplitHostPort(relay.address)
		p, _ := strconv.Atoi(relayPort)
		dns = dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message {
			r := dnsfixture.Loopback(q)
			if len(q.Questions) == 1 && q.Questions[0].Type == dnsmessage.TypeSRV {
				question := q.Questions[0]
				switch strings.ToLower(question.Name.String()) {
				case "_kerberos._udp.nfs.test.":
					udpSRV.Add(1)
				case "_kerberos._tcp.nfs.test.":
					tcpSRV.Add(1)
				default:
					return r
				}
				target, _ := dnsmessage.NewName("kdc.synthetic.invalid.")
				r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SRVResource{Target: target, Port: uint16(p)}}}
			}
			return r
		})
	} else {
		configuration += fmt.Sprintf("[realms]\n NFS.TEST = {\n kdc = %s\n }\n", relay.address)
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(conf, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"127.0.0.1", "--nfs-version", version, "--sec", security, "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"),
		"--krb5-config", conf, "--principal", "root@NFS.TEST", "--spn", "nfs/server.nfs.test", "--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
	if version == "3-udp" {
		args = append(args, "--nfs-version", "3", "--transport", "udp", "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
	}
	if srv {
		args = append(args, "--dns-server", dns.Address, "--dns-tcp")
	}
	if credential == "ccache" {
		args = append(args, "--ccache", os.Getenv("NFS_VIEWER_KRB5_CCACHE"))
	} else {
		args = append(args, "--keytab", os.Getenv("NFS_VIEWER_KRB5_KEYTAB"))
	}
	if loss == "blackhole" {
		args = append(args, "--timeout", "250ms", "-c", "pwd")
		start := time.Now()
		_, err := runKerberosCLI(t, args)
		if err == nil || time.Since(start) > 2*time.Second || relay.udp.Load() != 1 || relay.tcp.Load() != 0 {
			t.Fatalf("blackholed KDC exceeded deadline or retried after it: %v UDP=%d TCP=%d", err, relay.udp.Load(), relay.tcp.Load())
		}
		return
	}
	source, dest := filepath.Join(dir, "source.bin"), filepath.Join(dir, "received.bin")
	payload := bytes.Repeat([]byte{0, 255, 27, 'K', 'D', 'C'}, 1400)
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("kdc-%x", nonce)
	args = append(args, "-c", "put "+strconv.Quote(source)+" "+name, "-c", "get "+name+" "+strconv.Quote(dest), "-c", "id")
	out, err := runKerberosCLI(t, args)
	if err != nil || !strings.Contains(out, "root@NFS.TEST ("+security+")") || !strings.Contains(out, "Ticket ends") {
		t.Fatalf("real UDP KDC transfer: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("KDC-authenticated round trip: %v", err)
	}
	small := os.Getenv("NFS_VIEWER_KRB5_KDC_SMALL") == "1"
	if relay.udp.Load() == 0 || relay.tgs.Load() == 0 || credential == "keytab" && relay.as.Load() == 0 {
		t.Fatal("missing real KDC UDP AS/TGS exchange")
	}
	if small && (relay.tooBig.Load() == 0 || relay.tcp.Load() == 0) || !small && (relay.tooBig.Load() != 0 || relay.tcp.Load() != 0) {
		t.Fatalf("wrong KDC fallback: UDP=%d TCP=%d too-big=%d", relay.udp.Load(), relay.tcp.Load(), relay.tooBig.Load())
	}
	if loss != "" && (relay.dropped.Load() != 1 || relay.retried.Load() != 1) {
		t.Fatal("lost real AS/TGS reply was not recovered with an identical UDP retry")
	}
	if srv && (udpSRV.Load() == 0 || small && tcpSRV.Load() == 0 || dns.UDP.Load() != 0 || dns.TCP.Load() == 0) {
		t.Fatal("KDC SRV discovery ignored selected DNS transport or KDC protocol")
	}
}

type kdcRelay struct {
	address                                     string
	udp, tcp, as, tgs, tooBig, dropped, retried atomic.Int32
}

// Relay only local MIT traffic; never fabricate authentication responses or
// record ticket/key bytes. Both transports share one downstream endpoint.
func startKDCRelay(t *testing.T, upstreamTCP, upstreamUDP, loss string) *kdcRelay {
	t.Helper()
	l, u, err := loopback.Pair()
	if err != nil {
		t.Fatal(err)
	}
	r := &kdcRelay{address: l.Addr().String()}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	t.Cleanup(func() { cancel(); l.Close(); u.Close(); wg.Wait() })
	forward := func(network, address string, request []byte) ([]byte, error) {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if network == "tcp" {
			if err := writeKDCFixtureRecord(c, request); err != nil {
				return nil, err
			}
			return readKDCFixtureRecord(c)
		}
		if _, err := c.Write(request); err != nil {
			return nil, err
		}
		buf := make([]byte, 65536)
		n, err := c.Read(buf)
		return buf[:n], err
	}
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		var droppedRequest []byte
		var source string
		for {
			n, from, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			request := buf[:n]
			r.udp.Add(1)
			if len(request) > 0 && request[0] == 0x6a {
				r.as.Add(1)
			}
			if len(request) > 0 && request[0] == 0x6c {
				r.tgs.Add(1)
			}
			if droppedRequest != nil {
				if bytes.Equal(request, droppedRequest) && from.String() == source {
					r.retried.Add(1)
				}
				droppedRequest = nil
			}
			reply, err := forward("udp", upstreamUDP, request)
			if err != nil {
				if ctx.Err() == nil {
					t.Errorf("local KDC UDP relay: %v", err)
				}
				return
			}
			var krbErr messages.KRBError
			if krbErr.Unmarshal(reply) == nil && krbErr.ErrorCode == errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				r.tooBig.Add(1)
			}
			if loss == "blackhole" {
				continue
			}
			if r.dropped.Load() == 0 && len(reply) > 0 && (loss == "as" && reply[0] == 0x6b || loss == "tgs" && reply[0] == 0x6d) {
				droppedRequest, source = append([]byte(nil), request...), from.String()
				r.dropped.Add(1)
				continue
			}
			if _, err := u.WriteTo(reply, from); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			r.tcp.Add(1)
			func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				request, err := readKDCFixtureRecord(c)
				if err == nil {
					var reply []byte
					reply, err = forward("tcp", upstreamTCP, request)
					if err == nil {
						err = writeKDCFixtureRecord(c, reply)
					}
				}
				if err != nil && ctx.Err() == nil {
					t.Errorf("local KDC TCP relay: %v", err)
				}
			}()
		}
	}()
	return r
}

func readKDCFixtureRecord(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > 1<<20 {
		return nil, errors.New("invalid local KDC relay record length")
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeKDCFixtureRecord(w io.Writer, b []byte) error {
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	packet = append(packet, b...)
	_, err := io.Copy(w, bytes.NewReader(packet))
	return err
}
