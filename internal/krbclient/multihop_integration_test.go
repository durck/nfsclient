package client

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfsclient/internal/testutil/kerberosfixture"
)

// Require real intermediate-issued tickets, not merely a successful service
// reply which could accidentally use a direct trust installed in the fixture.
func TestKerberosMultiHopRoute(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_MULTIHOP") != "1" {
		t.Skip("requires the disposable CLIENT -> MID -> NFS fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			text, err := os.ReadFile(kerberosfixture.CrossRealmConfig(t, network, "NFS.TEST"))
			if err != nil {
				t.Fatal(err)
			}
			policy, err := ParseCAPaths(string(text))
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.NewFromString(string(text))
			if err != nil {
				t.Fatal(err)
			}
			kt, err := keytab.Load(os.Getenv("NFS_VIEWER_KRB5_CROSS_KEYTAB"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cl := NewWithKeytab("alice", "CLIENT.TEST", kt, cfg, NetworkContext(ctx), DisablePAFXFAST(true), TrustPaths(policy))
			defer cl.Destroy()
			ticket, _, err := cl.GetServiceTicket("nfs/server.nfs.test")
			if err != nil {
				t.Fatal(err)
			}
			if ticket.Realm != "NFS.TEST" || !ticket.SName.Equal(types.NewPrincipalName(2, "nfs/server.nfs.test")) {
				t.Fatal("wrong final service ticket")
			}
			for realm, issuer := range map[string]string{"CLIENT.TEST": "CLIENT.TEST", "MID.TEST": "CLIENT.TEST", "NFS.TEST": "MID.TEST"} {
				if policy != nil && realm != "CLIENT.TEST" {
					entry, ok := cl.cache.getEntry("krbtgt/" + realm)
					if !ok || entry.Ticket.Realm != issuer {
						t.Fatalf("missing expected %s-issued %s ticket", issuer, realm)
					}
					continue
				}
				session, ok := cl.sessions.get(realm)
				if !ok {
					t.Fatalf("missing %s session", realm)
				}
				_, tgt, _ := session.tgtDetails()
				if tgt.Realm != issuer || !tgt.SName.Equal(types.NewPrincipalName(2, "krbtgt/"+realm)) {
					t.Fatalf("%s ticket was not issued by expected realm %s", realm, issuer)
				}
			}
			if cl.Credentials.Realm() != "CLIENT.TEST" || cl.Credentials.UserName() != "alice" {
				t.Fatal("multi-hop acquisition changed selected identity")
			}
		})
	}
}
