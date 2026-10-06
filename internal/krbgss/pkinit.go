package gssapi

import (
	"errors"
	"path/filepath"
	"strings"
)

// PKINITFiles selects one explicit FILE identity and KDC trust bundle.
type PKINITFiles struct{ Cert, Key, CA, CRL string }

func (p PKINITFiles) Selected() bool { return p.Cert != "" || p.Key != "" || p.CA != "" || p.CRL != "" }

func ValidatePKINIT(helper string, p PKINITFiles) error {
	if !p.Selected() {
		return nil
	}
	for _, path := range []string{p.Cert, p.Key, p.CA} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return errors.New("PKINIT needs absolute --pkinit-cert, --pkinit-key and --pkinit-ca FILE paths")
		}
	}
	if p.CRL != "" && (!filepath.IsAbs(p.CRL) || strings.ContainsAny(p.CRL, "\x00\r\n")) {
		return errors.New("PKINIT CRL must be an absolute FILE path")
	}
	if helper != "" {
		if !filepath.IsAbs(helper) || strings.ContainsAny(helper, "\x00\r\n") {
			return errors.New("PKINIT --as-helper must be an absolute FILE path when selected")
		}
		return nativeASPlatform()
	}
	return nil
}

func WithPKINIT(helper string, p PKINITFiles) Option[Initiator] {
	return func(i *Initiator) error { i.asHelper, i.pkinit = helper, p; return nil }
}

// ValidatePKINITFAST validates the combined pure-Go profile without starting AS.
func ValidatePKINITFAST(helper, armor string, required bool) error {
	if !required {
		if armor != "" {
			return errors.New("PKINIT armor requires --require-fast")
		}
		return nil
	}
	if helper != "" {
		return errors.New("combined FAST PKINIT requires the pure-Go provider; omit --as-helper")
	}
	return ValidateNativeAS("", armor, true)
}
