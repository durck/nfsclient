package gssapi

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	client "nfsclient/internal/krbclient"
)

func ValidateNativeAS(helper, armor string, required bool) error {
	if !required {
		if helper != "" || armor != "" {
			return errors.New("--as-helper/--fast-armor require --require-fast")
		}
		return nil
	}
	armor = strings.TrimPrefix(armor, "FILE:")
	if (helper != "" && !filepath.IsAbs(helper)) || !filepath.IsAbs(armor) || strings.ContainsAny(helper+armor, "\x00\r\n") {
		return errors.New("required FAST needs an explicit absolute FILE --fast-armor and an absolute --as-helper when selected")
	}
	if helper != "" {
		return nativeASPlatform()
	}
	return nil
}

func validateNativeKDCs(cfg *config.Config) error {
	if cfg.LibDefaults.DNSLookupKDC || len(cfg.Realms) == 0 {
		return errors.New("native AS requires explicit numeric KDC endpoints and dns_lookup_kdc=false")
	}
	for _, realm := range cfg.Realms {
		if !nativeRealmName(realm.Realm) {
			return errors.New("native AS realm names require 1..256 ASCII letters, digits, dots, hyphens or underscores")
		}
		if len(realm.KDC) == 0 {
			return errors.New("native AS requires explicit numeric KDC endpoints for every realm")
		}
		for _, endpoint := range realm.KDC {
			host := endpoint
			if h, p, err := net.SplitHostPort(endpoint); err == nil {
				host = h
				port, err := strconv.Atoi(p)
				if err != nil || port < 1 || port > 65535 {
					return errors.New("native AS KDC port must be numeric and within 1..65535")
				}
			} else if strings.Contains(endpoint, ":") && net.ParseIP(endpoint) == nil {
				return errors.New("native AS KDC endpoint must be a numeric address with an optional port")
			}
			if net.ParseIP(host) == nil {
				return errors.New("native AS KDC endpoint must be a numeric address with an optional port")
			}
		}
	}
	return nil
}

func nativeRealmName(realm string) bool {
	if realm == "" || len(realm) > 256 {
		return false
	}
	for _, c := range realm {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func nativeASConfiguration(cfg *config.Config, home string) (string, error) {
	if !nativeRealmName(home) {
		return "", errors.New("native AS requires a bounded plain home realm")
	}
	if err := validateNativeKDCs(cfg); err != nil {
		return "", err
	}
	if cfg.LibDefaults.UDPPreferenceLimit < 1 || cfg.LibDefaults.UDPPreferenceLimit > 32700 {
		return "", errors.New("native AS UDP preference must be within 1..32700")
	}
	var b strings.Builder
	b.WriteString("[libdefaults]\n default_realm = " + home + "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n kdc_timesync = 0\n canonicalize = false\n udp_preference_limit = " + strconv.Itoa(cfg.LibDefaults.UDPPreferenceLimit) + "\n default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n[realms]\n")
	for _, r := range cfg.Realms {
		b.WriteString(" " + r.Realm + " = {\n")
		for _, kdc := range r.KDC {
			b.WriteString("  kdc = " + kdc + "\n")
		}
		b.WriteString(" }\n")
	}
	return b.String(), nil
}

func clearNativeCache(c *credentials.CCache) {
	for _, cred := range c.Credentials {
		clear(cred.Key.KeyValue)
		clear(cred.Ticket)
		clear(cred.SecondTicket)
	}
}

func validateArmorTGT(cache *credentials.CCache) error {
	cl, err := client.NewFromCCache(cache, config.New())
	if cl != nil {
		cl.Destroy()
	}
	return err
}
