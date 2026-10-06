package gssapi

import client "nfs-viewer/internal/krbclient"

func ValidateASAlias(alias, realm string) error {
	_, err := client.ValidateASAlias(alias, realm)
	return err
}

func ValidateEnterpriseAS(upn, start, home string, realms []string) error {
	return client.ValidateEnterpriseAS(upn, start, home, realms)
}
