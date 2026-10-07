package nfs

import "testing"

func TestPasswordCredentialSelection(t *testing.T) {
	base := Config{Version: "4.1", Security: "krb5p", Kerberos: KerberosConfig{ConfigFile: "explicit.conf", Principal: "alice@NFS.TEST", SPN: "nfs/server.nfs.test", Password: "test-only-password"}}
	if err := validateSecurity(&base); err != nil {
		t.Fatalf("password-only configuration rejected: %v", err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Kerberos.Keytab = "explicit.keytab" },
		func(c *Config) { c.Kerberos.CCache = "explicit.ccache" },
		func(c *Config) { c.Kerberos.PKINIT.Cert = "explicit.pem" },
		func(c *Config) { c.Security = "sys"; c.Kerberos = KerberosConfig{Password: "test-only-password"} },
		func(c *Config) { c.Kerberos.Provider = "sspi"; c.Kerberos.ConfigFile = "" },
	} {
		cfg := base
		change(&cfg)
		if err := validateSecurity(&cfg); err == nil {
			t.Fatal("accepted conflicting or ignored password credentials")
		}
	}
}
