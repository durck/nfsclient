package kdcfixture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// EnterpriseMappingConfig supplies an independent unauthenticated mapping peer
// before a real MIT home KDC. Only mapping is synthetic; home AS/TGS are native.
func EnterpriseMappingConfig(t *testing.T, source, upn, network string) (string, *Server) {
	t.Helper()
	peer := Start(t, func(_ string, wire []byte) []byte {
		var req messages.ASReq
		if err := req.Unmarshal(wire); err != nil {
			t.Error(err)
			return nil
		}
		if req.ReqBody.Realm != "MAP.TEST" || req.ReqBody.CName.NameType != nametype.KRB_NT_ENTERPRISE || len(req.ReqBody.CName.NameString) != 1 || req.ReqBody.CName.NameString[0] != upn || req.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
			t.Error("mapping request changed identity or sent credentials")
			return nil
		}
		ke := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/MAP.TEST"), "MAP.TEST", errorcode.KDC_ERR_WRONG_REALM, "independent mapping fixture")
		ke.CRealm = "NFS.TEST"
		ke.CName = types.NewPrincipalName(1, "poisoned-name")
		b, err := ke.Marshal()
		if err != nil {
			t.Error(err)
			return nil
		}
		return b
	})
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "[realms]") {
		t.Fatal("missing fixture realm configuration")
	}
	text = strings.Replace(text, "[realms]", fmt.Sprintf("[realms]\n MAP.TEST = {\n  kdc = %s\n }", peer.Address), 1)
	if network == "udp" {
		text = strings.Replace(text, "udp_preference_limit = 1", "udp_preference_limit = 32700", 1)
	}
	path := filepath.Join(t.TempDir(), "enterprise.conf")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path, peer
}
