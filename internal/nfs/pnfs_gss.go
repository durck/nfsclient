package nfs

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

func validatePNFSSPNs(o *PNFSOptions, names map[string]string) error {
	o.SPNs = map[string]string{}
	approved := map[string]bool{}
	for _, target := range o.DataServers {
		approved[target] = true
	}
	for target, spn := range names {
		endpoint, err := pnfsEndpoint(target)
		if err != nil {
			return err
		}
		if !approved[endpoint] || o.SPNs[endpoint] != "" {
			return errors.New("unapproved or duplicate pNFS Kerberos target")
		}
		host := strings.TrimPrefix(spn, "nfs/")
		if !strings.HasPrefix(spn, "nfs/") || len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "/@\\\\") || strings.IndexFunc(host, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
			return errors.New("pNFS SPN must be nfs/server-hostname")
		}
		o.SPNs[endpoint] = spn
	}
	return nil
}

func (c *Client) pnfsKerberosConfigs(o PNFSOptions) (map[string]Config, error) {
	if c.config == nil || c.nfs == nil {
		return nil, errors.New("pNFS connection profile unavailable")
	}
	cfg := *c.config
	if (o.ReadFailover || o.WriteFailover || o.MirrorFailover || o.RefreshDevices || o.SessionTrunking) && cfg.Security != "krb5i" && cfg.Security != "krb5p" {
		return nil, errors.New("pNFS recovery requires krb5i or krb5p")
	}
	if cfg.Security == "" || cfg.Security == "sys" {
		if len(o.SPNs) != 0 {
			return nil, errors.New("pNFS DS SPNs require Kerberos")
		}
		return nil, nil
	}
	// Use the effective absolute credential paths retained by the authenticated
	// MDS context, never re-resolve a caller's relative path after local navigation.
	c.nfs.mu.Lock()
	if c.nfs.kerberos == nil {
		c.nfs.mu.Unlock()
		return nil, errors.New("pNFS MDS Kerberos identity unavailable")
	}
	cfg.Kerberos = c.nfs.kerberos.config
	c.nfs.mu.Unlock()
	configs := map[string]Config{}
	for _, target := range o.DataServers {
		spn := o.SPNs[target]
		if spn == "" {
			return nil, fmt.Errorf("pNFS Kerberos requires an explicit DS SPN for %s", target)
		}
		selected := cfg
		selected.Kerberos.SPN = spn
		if err := validateSecurity(&selected); err != nil {
			return nil, err
		}
		configs[target] = selected
	}
	return configs, nil
}
