package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	bgss "nfs-viewer/internal/krbgss"
	"nfs-viewer/internal/testutil/kdcfixture"
)

// A structurally valid FILE TGT already inside its renewal margin. The silent
// KDC need not decrypt the synthetic ticket: this tests request cancellation.
func closeRenewalCache(t *testing.T, renewal bool) []byte {
	t.Helper()
	data := func(b, v []byte) []byte {
		return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...)
	}
	principal := func(b []byte, parts ...string) []byte {
		b = binary.BigEndian.AppendUint32(b, 1)
		b = binary.BigEndian.AppendUint32(b, uint32(len(parts)))
		b = data(b, []byte("NFS.TEST"))
		for _, p := range parts {
			b = data(b, []byte(p))
		}
		return b
	}
	ticket := messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: types.NewPrincipalName(2, "krbtgt/NFS.TEST"), EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic TGT")}}
	wire, err := ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b := principal([]byte{5, 4, 0, 0}, "root")
	b = principal(b, "root")
	b = principal(b, "krbtgt", "NFS.TEST")
	b = binary.BigEndian.AppendUint16(b, 18)
	b = data(b, bytes.Repeat([]byte{0x42}, 32))
	now := time.Now()
	end := now.Add(time.Hour)
	if renewal {
		end = now.Add(time.Minute)
	}
	for _, v := range []time.Time{now.Add(-time.Hour), now.Add(-time.Hour), end, now.Add(2 * time.Hour)} {
		b = binary.BigEndian.AppendUint32(b, uint32(v.Unix()))
	}
	b = append(b, 0) // is_skey
	b = binary.BigEndian.AppendUint32(b, 1<<(31-flags.Renewable))
	b = append(b, make([]byte, 8)...) // addresses and authdata
	b = data(b, wire)
	return data(b, nil)
}

func TestClientCloseCancelsForegroundKerberos(t *testing.T) {
	for _, phase := range []string{"file-renewal", "service-ticket"} {
		t.Run(phase, func(t *testing.T) { testClientCloseCancelsForegroundKerberos(t, phase == "file-renewal") })
	}
}

func testClientCloseCancelsForegroundKerberos(t *testing.T, renewal bool) {
	seen := make(chan struct{}, 1)
	kdc := kdcfixture.Start(t, func(network string, wire []byte) []byte {
		var req messages.TGSReq
		if err := req.Unmarshal(wire); err != nil {
			t.Error(err)
		} else if types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renew) != renewal {
			t.Error("KDC request reached the wrong renewal phase")
		}
		seen <- struct{}{}
		return nil
	})
	dir := t.TempDir()
	k := KerberosConfig{Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test", ConfigFile: filepath.Join(dir, "krb5.conf"), CCache: filepath.Join(dir, "selected.ccache")}
	conf := fmt.Sprintf("[libdefaults]\n default_realm = NFS.TEST\n udp_preference_limit = 1\n[realms]\n NFS.TEST = {\n kdc = %s\n }\n", kdc.Address)
	if err := os.WriteFile(k.ConfigFile, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.CCache, closeRenewalCache(t, renewal), 0600); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	owner := bgss.NewFileCacheRenewal()
	defer owner.Close()
	session := &kerberosSession{config: k, security: "krb5p", version: 3, fileCache: owner}
	session.ctx, session.cancel = context.WithCancel(context.Background())
	defer session.cancelWork()
	rpc := &rpcClient{conn: a, timeout: 10 * time.Second,
		gss:      &rpcGSS{context: testMIC{}, established: true, expiry: time.Now().Add(time.Hour), renewAt: time.Now().Add(-time.Second)},
		kerberos: session}
	c := &Client{nfs: rpc, version: "3", closeKerberos: owner.Close}
	c.cancelKerberos.Store(&kerberosCancellation{cancel: session.cancelWork})
	defer c.Close()
	application := make(chan int, 1)
	go func() { n, _ := io.Copy(io.Discard, b); application <- int(n) }()
	callDone := make(chan error, 1)
	go func() { _, err := rpc.call(context.Background(), nfsProgram, 3, 7, nil, nil); callDone <- err }()
	select {
	case <-seen:
	case err := <-callDone:
		t.Fatalf("renewal failed before KDC request: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("foreground FILE renewal did not reach KDC")
	}
	start := time.Now()
	c.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Client.Close waited %v for KDC timeout instead of canceling foreground renewal", elapsed)
	}
	select {
	case err := <-callDone:
		if err == nil {
			t.Error("canceled renewal succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("foreground RPC survived Close")
	}
	if n := <-application; n != 0 {
		t.Fatalf("application mutation sent while renewal failed: %d bytes", n)
	}
	if kdc.TCP.Load() != 1 || kdc.UDP.Load() != 0 {
		t.Fatal("canceled renewal retried the KDC")
	}
}
