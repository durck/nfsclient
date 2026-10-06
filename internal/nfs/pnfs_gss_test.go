package nfs

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPNFSGSSOptions(t *testing.T) {
	const target = "127.0.0.1:2049"
	for _, spn := range []string{"", "host/ds", "nfs/", "nfs/a@REALM", "nfs/a/b", "nfs/a b", "nfs/a\x00b", "nfs/" + strings.Repeat("a", 254)} {
		if _, err := validatePNFSOptions(PNFSOptions{DataServers: map[string]string{target: target}, SPNs: map[string]string{target: spn}}); err == nil {
			t.Fatal("accepted invalid SPN", spn)
		}
	}
	for _, spns := range []map[string]string{{"127.0.0.2:2049": "nfs/ds"}, {target: "nfs/ds", "[::ffff:127.0.0.1]:2049": "nfs/ds"}} {
		if _, err := validatePNFSOptions(PNFSOptions{DataServers: map[string]string{target: target}, SPNs: spns}); err == nil {
			t.Fatal("accepted unapproved/duplicate target")
		}
	}
	k := KerberosConfig{ConfigFile: "/original/krb5.conf", Keytab: "/original/client.keytab", Principal: "client@TEST", SPN: "nfs/mds"}
	c := &Client{config: &Config{Version: "4.1", Security: "krb5p", Kerberos: KerberosConfig{ConfigFile: "wrong-relative"}}, nfs: &rpcClient{kerberos: &kerberosSession{config: k}}}
	o, err := validatePNFSOptions(PNFSOptions{DataServers: map[string]string{target: target}, SPNs: map[string]string{"[::ffff:127.0.0.1]:2049": "nfs/ds"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := c.pnfsKerberosConfigs(o)
	if err != nil || cfg[target].Security != "krb5p" || cfg[target].Kerberos.SPN != "nfs/ds" || cfg[target].Kerberos.ConfigFile != k.ConfigFile || cfg[target].Kerberos.Principal != k.Principal {
		t.Fatal("identity/pinned paths not preserved", err)
	}
	delete(o.SPNs, target)
	if _, err := c.pnfsKerberosConfigs(o); err == nil {
		t.Fatal("implicit DS SPN")
	}
	o.SPNs[target] = "nfs/ds"
	c.config.Security = "sys"
	if _, err := c.pnfsKerberosConfigs(o); err == nil {
		t.Fatal("ignored SPN under sys")
	}
	c.config.Security = "krb5p"
	c.config.TLS.Enabled = true
	if configs, err := c.pnfsKerberosConfigs(o); err != nil || !configs[target].TLS.Enabled {
		t.Fatal("TLS/GSS profile lost TLS policy", err)
	}
}

func TestPNFSGSSPinnedContextNeverRenews(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	defer a.Close()
	c := &rpcClient{conn: a, pinnedBackchannelGSS: true, kerberos: &kerberosSession{}, gss: &rpcGSS{context: testMIC{}, established: true, expiry: time.Now().Add(time.Minute), renewAt: time.Now().Add(time.Second)}}
	if err := c.renewKerberosLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.gss.renewAt = time.Now().Add(-time.Second)
	if err := c.renewKerberosLocked(context.Background()); err == nil || !strings.Contains(err.Error(), "backchannel") || !c.closed || c.kerberos.renewals != 0 {
		t.Fatal("pinned context replaced", err)
	}
	if _, err := c.call(context.Background(), nfsProgram, 4, 1, nil, nil); !errors.Is(err, ErrConnectionLost) {
		t.Fatal("closed context revived", err)
	}
}
