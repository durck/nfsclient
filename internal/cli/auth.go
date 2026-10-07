package cli

import (
	"strings"

	"nfsclient/internal/nfs"
)

// qualifyKerberos applies the shared command-line realm and password shorthand.
func qualifyKerberos(k nfs.KerberosConfig, domain, password string) nfs.KerberosConfig {
	if domain != "" && k.Principal != "" && !strings.Contains(k.Principal, "@") {
		k.Principal += "@" + strings.ToUpper(domain)
	}
	k.Password = password
	return k
}
