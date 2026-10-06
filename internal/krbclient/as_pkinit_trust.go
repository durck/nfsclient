package client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"slices"
	"time"
)

// PKINITIdentity pins explicit PEM files; no ambient identities or trust roots.
type PKINITIdentity struct{ Cert, Key, CA, CRL string }
type pkTrust struct {
	roots *x509.CertPool
	crls  []*x509.RevocationList
	realm string
	name  []string
}

func pkReadPEM(path string) ([]*pem.Block, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("PKINIT FILE must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if len(data) > 1<<20 {
		return nil, errors.New("PKINIT FILE exceeds limit")
	}
	var out []*pem.Block
	for len(bytes.TrimSpace(data)) != 0 {
		// pem.Decode otherwise silently ignores arbitrary prefixes.
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, errors.New("invalid PKINIT PEM framing")
		}
		block, rest := pem.Decode(data)
		if block == nil || len(block.Headers) != 0 || len(out) >= 16 {
			return nil, errors.New("invalid PKINIT PEM block")
		}
		out = append(out, block)
		data = rest
	}
	if len(out) == 0 {
		return nil, errors.New("empty PKINIT PEM file")
	}
	return out, nil
}
func pkCertificates(path string) ([]*x509.Certificate, error) {
	blocks, err := pkReadPEM(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, b := range blocks {
		if b.Type != "CERTIFICATE" {
			return nil, errors.New("PKINIT expected certificate PEM")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}
func pkLoadIdentity(files PKINITIdentity, realm string, name []string) ([]*x509.Certificate, crypto.Signer, *pkTrust, error) {
	certs, err := pkCertificates(files.Cert)
	if err != nil {
		return nil, nil, nil, err
	}
	roots, err := pkCertificates(files.CA)
	if err != nil {
		return nil, nil, nil, err
	}
	t := &pkTrust{roots: x509.NewCertPool(), realm: realm, name: name}
	for _, c := range roots {
		if !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, nil, nil, errors.New("PKINIT anchor is not a signing CA")
		}
		t.roots.AddCert(c)
	}
	if files.CRL != "" {
		blocks, err := pkReadPEM(files.CRL)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, b := range blocks {
			if b.Type != "X509 CRL" {
				return nil, nil, nil, errors.New("PKINIT expected CRL PEM")
			}
			crl, err := x509.ParseRevocationList(b.Bytes)
			if err != nil {
				return nil, nil, nil, err
			}
			t.crls = append(t.crls, crl)
		}
	}
	blocks, err := pkReadPEM(files.Key)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		for _, b := range blocks {
			clear(b.Bytes)
		}
	}()
	if len(blocks) != 1 {
		return nil, nil, nil, errors.New("PKINIT requires one private key")
	}
	var key any
	switch blocks[0].Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(blocks[0].Bytes)
	default:
		err = errors.New("PKINIT requires an unencrypted RSA/ECDSA FILE key")
	}
	if err != nil {
		return nil, nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("unsupported PKINIT private key")
	}
	switch k := signer.Public().(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, nil, nil, errors.New("PKINIT RSA key is below 2048 bits")
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return nil, nil, nil, errors.New("PKINIT EC key is below 256 bits")
		}
	default:
		return nil, nil, nil, errors.New("unsupported PKINIT key algorithm")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, certs[0].RawSubjectPublicKeyInfo) {
		return nil, nil, nil, errors.New("PKINIT certificate/private key mismatch")
	}
	if err := t.verify(certs[0], certs, false); err != nil {
		return nil, nil, nil, err
	}
	return certs, signer, t, nil
}

func (t *pkTrust) verify(cert *x509.Certificate, certs []*x509.Certificate, kdc bool) error {
	if t == nil || t.roots == nil || cert == nil || cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("PKINIT requires a trusted signing leaf")
	}
	eku := "1.3.6.1.5.2.3.4"
	name := t.name
	if kdc {
		eku = "1.3.6.1.5.2.3.5"
		name = []string{"krbtgt", t.realm}
	}
	got := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.String() == eku {
			got = true
		}
	}
	if !got {
		return errors.New("PKINIT certificate EKU mismatch")
	}
	if err := pkVerifySAN(cert, t.realm, name); err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs {
		if c != cert {
			intermediates.AddCert(c)
		}
	}
	chains, err := cert.Verify(x509.VerifyOptions{Roots: t.roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: time.Now()})
	if err != nil {
		return errors.New("PKINIT certificate chain/lifetime verification failed")
	}
	for _, chain := range chains {
		purposeOK := true
		for _, issuer := range chain[1:] {
			for _, ext := range issuer.Extensions {
				if ext.Id.String() != "2.5.29.37" {
					continue
				}
				allowed := slices.Contains(issuer.ExtKeyUsage, x509.ExtKeyUsageAny)
				for _, oid := range issuer.UnknownExtKeyUsage {
					allowed = allowed || oid.String() == eku
				}
				purposeOK = purposeOK && allowed
			}
		}
		// ExtKeyUsageAny lets x509 verify custom PKINIT OIDs. Enforce their
		// restriction ourselves on every CA, including the selected anchor.
		if purposeOK && (len(t.crls) == 0 || t.verifyCRLs(chain) == nil) {
			return nil
		}
	}
	return errors.New("PKINIT certificate purpose/revocation verification failed")
}
func (t *pkTrust) verifyCRLs(chain []*x509.Certificate) error {
	now := time.Now()
	for i := 0; i+1 < len(chain); i++ {
		found := false
		for _, crl := range t.crls {
			for _, ext := range crl.Extensions {
				id := ext.Id.String()
				if id == "2.5.29.27" || id == "2.5.29.28" || ext.Critical && id != "2.5.29.20" && id != "2.5.29.35" {
					return errors.New("unsupported PKINIT CRL scope or critical extension")
				}
			}
			for _, entry := range crl.RevokedCertificateEntries {
				for _, ext := range entry.Extensions {
					if ext.Critical || ext.Id.String() == "2.5.29.29" {
						return errors.New("unsupported PKINIT CRL entry extension")
					}
				}
			}
			if !bytes.Equal(crl.RawIssuer, chain[i+1].RawSubject) {
				continue
			}
			if crl.CheckSignatureFrom(chain[i+1]) != nil || crl.ThisUpdate.After(now) || crl.NextUpdate.IsZero() || !crl.NextUpdate.After(now) {
				return errors.New("invalid or stale PKINIT CRL")
			}
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(chain[i].SerialNumber) == 0 {
					return errors.New("revoked PKINIT certificate")
				}
			}
			found = true
		}
		if !found {
			return errors.New("missing PKINIT issuer CRL")
		}
	}
	return nil
}
func pkVerifySAN(cert *x509.Certificate, realm string, name []string) error {
	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.String() != "2.5.29.17" {
			continue
		}
		fields, err := pkFields(ext.Value, 0x30)
		if err != nil {
			return err
		}
		for _, field := range fields {
			if field[0] != 0xa0 {
				continue
			}
			other, err := pkFields(field, 0xa0)
			if err != nil || len(other) != 2 {
				return errors.New("invalid PKINIT otherName SAN")
			}
			if !bytes.Equal(other[0], pkOID("1.3.6.1.5.2.2")) {
				continue
			}
			v, err := pkValue(other[1], 0xa0)
			if err != nil {
				return err
			}
			principal, err := pkFields(v.Bytes, 0x30)
			if err != nil || len(principal) != 2 {
				return errors.New("invalid PKINIT principal SAN")
			}
			r, err := pkValue(principal[0], 0xa0)
			if err != nil {
				return err
			}
			rs, err := pkValue(r.Bytes, 0x1b)
			if err != nil {
				return err
			}
			n, err := pkValue(principal[1], 0xa1)
			if err != nil {
				return err
			}
			nf, err := pkFields(n.Bytes, 0x30)
			if err != nil || len(nf) != 2 {
				return errors.New("invalid PKINIT principal name")
			}
			typ, err := pkExplicitNumber(nf[0], 0xa0)
			if err != nil || typ.BitLen() > 31 {
				return errors.New("invalid PKINIT principal name type")
			}
			names, err := pkValue(nf[1], 0xa1)
			if err != nil {
				return err
			}
			parts, err := pkFields(names.Bytes, 0x30)
			if err != nil || len(parts) == 0 {
				return errors.New("invalid PKINIT principal components")
			}
			var components []string
			for _, part := range parts {
				s, err := pkValue(part, 0x1b)
				if err != nil || len(s.Bytes) == 0 || len(s.Bytes) > 256 {
					return errors.New("invalid PKINIT principal component")
				}
				components = append(components, string(s.Bytes))
			}
			if string(rs.Bytes) != realm || !slices.Equal(components, name) {
				return errors.New("PKINIT certificate principal/realm mismatch")
			}
			if found {
				return errors.New("ambiguous PKINIT principal SAN")
			}
			found = true
		}
	}
	if !found {
		return errors.New("missing PKINIT principal SAN")
	}
	return nil
}
