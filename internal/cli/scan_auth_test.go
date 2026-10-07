package cli

import (
	"bytes"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
)

func TestQualifyKerberosSharedCredentials(t *testing.T) {
	for _, principal := range []string{"alice", "alice@REALM.TEST"} {
		got := qualifyKerberos(nfs.KerberosConfig{Principal: principal, SPN: "nfs/server", ConfigFile: "explicit.conf"}, "realm.test", "test-password")
		if got.Principal != "alice@REALM.TEST" || got.Password != "test-password" {
			t.Fatal("realm/password shorthand not applied")
		}
		if err := nfs.ValidateSecurityConfig(nfs.Config{Security: "krb5p", Kerberos: got}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanKerberosValidationBeforeDiscovery(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--sec", "krb5p", "--principal", "alice", "--domain", "REALM.TEST", "--password", "private-value", "--krb5-config", "explicit.conf"}, "requires --krb5-config"},
		{[]string{"--sec", "sys", "--password", "private-value"}, "require --sec"},
		{[]string{"--sec", "krb5", "--uid", "0"}, "cannot select a Kerberos identity"},
		{[]string{"--sec", "krb5", "--target-spn", "malformed"}, "TARGET="},
	} {
		var out bytes.Buffer
		cmd := newScanCommand(&out)
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(append(tc.args, "--dns-domain", "must-not-resolve.invalid"))
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("error = %v; want %q", err, tc.want)
		}
		if strings.Contains(err.Error(), "private-value") {
			t.Fatal("password leaked")
		}
	}
}
