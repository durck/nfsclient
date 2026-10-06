package nfs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"
)

func validatePNFSTLSNames(o *PNFSOptions, names map[string]string) error {
	o.TLSNames = make(map[string]string, len(names))
	approved := make(map[string]bool, len(o.DataServers))
	for _, target := range o.DataServers {
		approved[target] = true
	}
	for target, name := range names {
		endpoint, err := pnfsEndpoint(target)
		if err != nil {
			return err
		}
		if !approved[endpoint] || o.TLSNames[endpoint] != "" {
			return fmt.Errorf("unapproved or duplicate pNFS TLS target %q", target)
		}
		if len(name) == 0 || len(name) > 253 || strings.ContainsAny(name, "/\\@") || strings.IndexFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return errors.New("invalid pNFS TLS certificate name")
		}
		o.TLSNames[endpoint] = name
	}
	return nil
}

func pnfsTLSConfigs(cfg Config, o PNFSOptions) (map[string]*tls.Config, error) {
	if !cfg.TLS.Enabled && len(o.TLSNames) != 0 {
		return nil, errors.New("pNFS TLS names require an enabled TLS connection")
	}
	base, err := cfg.tlsConfig()
	if err != nil || base == nil {
		return nil, err
	}
	configs := make(map[string]*tls.Config, len(o.DataServers))
	for _, target := range o.DataServers {
		policy := base.Clone()
		policy.ServerName = o.TLSNames[target]
		if policy.ServerName == "" {
			policy.ServerName, _, _ = net.SplitHostPort(target)
		}
		configs[target] = policy
	}
	return configs, nil
}
