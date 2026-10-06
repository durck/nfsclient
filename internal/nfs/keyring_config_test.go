package nfs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestKEYRINGConfigBeforeNetwork(t *testing.T) {
	for _, name := range []string{"KEYRING:", "KEYRING:session:c", "KEYRING:thread:c:s", "KEYRING:session::s", "KEYRING:persistent:00:s"} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{Host: "must-not-resolve.invalid", Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{ConfigFile: "missing.conf", CCache: name, Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			c, err := Connect(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("invalid source reached network")
			}
			if !strings.Contains(err.Error(), "KEYRING ") {
				t.Fatal(err)
			}
		})
	}
}
