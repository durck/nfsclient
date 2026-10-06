package client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

const pkAuthData = "1.3.6.1.5.2.3.1"
const pkDHData = "1.3.6.1.5.2.3.2"
const pkSignedData = "1.2.840.113549.1.7.2"
const pkContentType = "1.2.840.113549.1.9.3"
const pkMessageDigest = "1.2.840.113549.1.9.4"
const pkSHA256 = "2.16.840.1.101.3.4.2.1"
const pkSHA1 = "1.3.14.3.2.26"
const pkRSA = "1.2.840.113549.1.1.1"
const pkRSA256 = "1.2.840.113549.1.1.11"
const pkRSA1 = "1.2.840.113549.1.1.5"
const pkECDSA256 = "1.2.840.10045.4.3.2"

func pkAlgorithm(oid string) []byte { return pkSeq(pkOID(oid), []byte{5, 0}) }
func pkSignCMS(content []byte, certs []*x509.Certificate, signer crypto.Signer) ([]byte, error) {
	sum := sha256.Sum256(content)
	attrs := pkSet(pkSeq(pkOID(pkContentType), pkSet(pkOID(pkAuthData))), pkSeq(pkOID(pkMessageDigest), pkSet(pkDER(4, sum[:]))))
	digest := sha256.Sum256(attrs)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	algorithm := pkAlgorithm(pkRSA256)
	if _, ok := signer.Public().(*ecdsa.PublicKey); ok {
		algorithm = pkSeq(pkOID(pkECDSA256))
	}
	v, _ := pkValue(attrs, 0x31)
	cert := certs[0]
	info := pkSeq(pkNumber(1), pkSeq(cert.RawIssuer, pkInt(cert.SerialNumber)), pkAlgorithm(pkSHA256), pkDER(0xa0, v.Bytes), algorithm, pkDER(4, sig))
	var chain []byte
	for _, c := range certs {
		chain = append(chain, c.Raw...)
	}
	signed := pkSeq(pkNumber(3), pkSet(pkAlgorithm(pkSHA256)), pkSeq(pkOID(pkAuthData), pkDER(0xa0, pkDER(4, content))), pkDER(0xa0, chain), pkSet(info))
	return pkSeq(pkOID(pkSignedData), pkDER(0xa0, signed)), nil
}

func pkDigest(algorithm []byte) (crypto.Hash, error) {
	f, err := pkFields(algorithm, 0x30)
	if err != nil || len(f) < 1 || len(f) > 2 || len(f) == 2 && !bytes.Equal(f[1], []byte{5, 0}) {
		return 0, errors.New("invalid PKINIT digest algorithm")
	}
	if bytes.Equal(f[0], pkOID(pkSHA256)) {
		return crypto.SHA256, nil
	}
	// RFC 4556's deployed MIT CMS profile uses SHA-1 for signed DH data.
	if bytes.Equal(f[0], pkOID(pkSHA1)) {
		return crypto.SHA1, nil
	}
	return 0, errors.New("unsupported PKINIT CMS digest")
}
func pkHash(h crypto.Hash, data []byte) []byte {
	if h == crypto.SHA256 {
		b := sha256.Sum256(data)
		return b[:]
	}
	b := sha1.Sum(data)
	return b[:]
}

// Verify the signed attributes structurally. Searching for a digest byte string
// inside a signed blob would not bind the digest to the messageDigest attribute.
func pkVerifyCMS(data []byte, trust *pkTrust) ([]byte, error) {
	outer, err := pkFields(data, 0x30)
	if err != nil || len(outer) != 2 || !bytes.Equal(outer[0], pkOID(pkSignedData)) {
		return nil, errors.New("invalid PKINIT CMS ContentInfo")
	}
	wrapped, err := pkValue(outer[1], 0xa0)
	if err != nil {
		return nil, err
	}
	f, err := pkFields(wrapped.Bytes, 0x30)
	if err != nil || len(f) != 5 || !bytes.Equal(f[0], pkNumber(3)) {
		return nil, errors.New("invalid PKINIT CMS SignedData")
	}
	digests, err := pkFields(f[1], 0x31)
	if err != nil || len(digests) != 1 {
		return nil, errors.New("invalid PKINIT CMS digest set")
	}
	h, err := pkDigest(digests[0])
	if err != nil {
		return nil, err
	}
	encap, err := pkFields(f[2], 0x30)
	if err != nil || len(encap) != 2 || !bytes.Equal(encap[0], pkOID(pkDHData)) {
		return nil, errors.New("PKINIT CMS content type mismatch")
	}
	explicit, err := pkValue(encap[1], 0xa0)
	if err != nil {
		return nil, err
	}
	content, err := pkValue(explicit.Bytes, 4)
	if err != nil {
		return nil, err
	}
	certDER, err := pkFields(f[3], 0xa0)
	if err != nil || len(certDER) < 1 || len(certDER) > 16 {
		return nil, errors.New("invalid PKINIT CMS certificates")
	}
	var certs []*x509.Certificate
	for _, der := range certDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("invalid PKINIT CMS certificate")
		}
		certs = append(certs, c)
	}
	infos, err := pkFields(f[4], 0x31)
	if err != nil || len(infos) != 1 {
		return nil, errors.New("PKINIT requires exactly one CMS signer")
	}
	si, err := pkFields(infos[0], 0x30)
	if err != nil || len(si) != 6 || !bytes.Equal(si[0], pkNumber(1)) {
		return nil, errors.New("invalid PKINIT CMS signer")
	}
	id, err := pkFields(si[1], 0x30)
	if err != nil || len(id) != 2 {
		return nil, errors.New("invalid PKINIT CMS issuer/serial")
	}
	serial, err := pkUnsigned(id[1])
	if err != nil {
		return nil, err
	}
	var cert *x509.Certificate
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, id[0]) && c.SerialNumber.Cmp(serial) == 0 {
			if cert != nil {
				return nil, errors.New("duplicate PKINIT signer certificate")
			}
			cert = c
		}
	}
	if cert == nil {
		return nil, errors.New("missing PKINIT signer certificate")
	}
	siHash, err := pkDigest(si[2])
	if err != nil || siHash != h {
		return nil, errors.New("PKINIT CMS digest mismatch")
	}
	attrs, err := pkFields(si[3], 0xa0)
	if err != nil {
		return nil, err
	}
	var gotType, gotDigest bool
	for i, a := range attrs {
		if i > 0 && bytes.Compare(attrs[i-1], a) >= 0 {
			return nil, errors.New("noncanonical PKINIT signed attributes")
		}
		pair, err := pkFields(a, 0x30)
		if err != nil || len(pair) != 2 {
			return nil, errors.New("invalid PKINIT signed attribute")
		}
		values, err := pkFields(pair[1], 0x31)
		if err != nil || len(values) != 1 {
			return nil, errors.New("invalid PKINIT attribute values")
		}
		switch {
		case bytes.Equal(pair[0], pkOID(pkContentType)):
			if gotType || !bytes.Equal(values[0], pkOID(pkDHData)) {
				return nil, errors.New("PKINIT signed content type mismatch")
			}
			gotType = true
		case bytes.Equal(pair[0], pkOID(pkMessageDigest)):
			if gotDigest || !bytes.Equal(values[0], pkDER(4, pkHash(h, content.Bytes))) {
				return nil, errors.New("PKINIT signed message digest mismatch")
			}
			gotDigest = true
		}
	}
	if !gotType || !gotDigest {
		return nil, errors.New("missing PKINIT signed attributes")
	}
	sig, err := pkValue(si[5], 4)
	if err != nil {
		return nil, err
	}
	algorithm, err := pkFields(si[4], 0x30)
	if err != nil || len(algorithm) < 1 || len(algorithm) > 2 || len(algorithm) == 2 && !bytes.Equal(algorithm[1], []byte{5, 0}) {
		return nil, errors.New("invalid PKINIT signature algorithm")
	}
	attrValue, _ := pkValue(si[3], 0xa0)
	digest := pkHash(h, pkDER(0x31, attrValue.Bytes))
	valid := false
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		allowed := bytes.Equal(algorithm[0], pkOID(pkRSA)) || h == crypto.SHA256 && bytes.Equal(algorithm[0], pkOID(pkRSA256)) || h == crypto.SHA1 && bytes.Equal(algorithm[0], pkOID(pkRSA1))
		valid = allowed && key.N.BitLen() >= 2048 && rsa.VerifyPKCS1v15(key, h, digest, sig.Bytes) == nil
	case *ecdsa.PublicKey:
		valid = h == crypto.SHA256 && bytes.Equal(algorithm[0], pkOID(pkECDSA256)) && key.Curve.Params().BitSize >= 256 && ecdsa.VerifyASN1(key, digest, sig.Bytes)
	}
	if !valid {
		return nil, errors.New("PKINIT CMS signature verification failed")
	}
	if err := trust.verify(cert, certs, true); err != nil {
		return nil, err
	}
	return content.Bytes, nil
}
