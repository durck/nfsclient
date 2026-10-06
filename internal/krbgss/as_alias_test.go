package gssapi

import (
	"strings"
	"testing"
)

func TestASAliasExplicitKeytab(t *testing.T) {
	_, err := NewInitiator(WithConfig[Initiator]("[libdefaults]\n default_realm = NFS.TEST\n"), WithRealm[Initiator]("NFS.TEST"), WithUsername[Initiator]("alice"), WithKeytab[Initiator](""), WithASAlias("alias@NFS.TEST"))
	if err == nil || !strings.Contains(err.Error(), "explicit canonical keytab") {
		t.Fatal("ambient keytab used for alias", err)
	}
}
