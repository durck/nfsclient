package client

import (
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestCCacheRejectsExpiredAndPostdatedTGT(t *testing.T) {
	for _, postdated := range []bool{false, true} {
		c := &credentials.CCache{}
		c.DefaultPrincipal.Realm = "NFS.TEST"
		c.DefaultPrincipal.PrincipalName = types.PrincipalName{NameString: []string{"root"}}
		e := &credentials.Credential{}
		e.Server.Realm = "NFS.TEST"
		e.Server.PrincipalName = types.PrincipalName{NameString: []string{"krbtgt", "NFS.TEST"}}
		e.EndTime = time.Now().Add(-time.Second)
		if postdated {
			e.EndTime = time.Now().Add(time.Hour)
			e.StartTime = time.Now().Add(time.Minute)
		}
		c.Credentials = []*credentials.Credential{e}
		cl, err := NewFromCCache(c, config.New())
		if cl != nil {
			cl.Destroy()
		}
		if err == nil || !strings.Contains(err.Error(), "expired or not yet valid") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}
