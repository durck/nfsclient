package client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func pkTestCertificate(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, ca bool, eku asn1.ObjectIdentifier) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: serial.String()}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if eku != nil {
		c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{eku}
	}
	if ca {
		c.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		name := pkSeq(pkDER(0xa0, pkNumber(2)), pkDER(0xa1, pkSeq(pkDER(0x1b, []byte("krbtgt")), pkDER(0x1b, []byte("NFS.TEST")))))
		principal := pkSeq(pkDER(0xa0, pkDER(0x1b, []byte("NFS.TEST"))), pkDER(0xa1, name))
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: pkSeq(pkJoin(0xa0, pkOID("1.3.6.1.5.2.2"), pkDER(0xa0, principal)))}}
	}
	if parent == nil {
		parent = c
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, c, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key
}

func pkTestCMS(t *testing.T, content []byte, cert *x509.Certificate, key crypto.Signer, mode string) []byte {
	t.Helper()
	sum := sha256.Sum256(content)
	contentType := pkOID(pkDHData)
	if mode == "content-type" {
		contentType = pkOID(pkAuthData)
	}
	attrs := [][]byte{pkSeq(pkOID(pkContentType), pkSet(contentType)), pkSeq(pkOID(pkMessageDigest), pkSet(pkDER(4, sum[:])))}
	if mode == "digest-substring" {
		attrs[1] = pkSeq(pkOID("1.2.3.4"), pkSet(pkDER(4, sum[:])))
	}
	if mode == "duplicate-digest" {
		attrs = append(attrs, attrs[1])
	}
	if mode == "wrong-digest" {
		sum[0] ^= 1
		attrs[1] = pkSeq(pkOID(pkMessageDigest), pkSet(pkDER(4, sum[:])))
	}
	encoded := pkSet(attrs...)
	hash := sha256.Sum256(encoded)
	sig, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "signature" {
		sig[len(sig)-1] ^= 1
	}
	v, _ := pkValue(encoded, 0x31)
	si := pkSeq(pkNumber(1), pkSeq(cert.RawIssuer, pkInt(cert.SerialNumber)), pkAlgorithm(pkSHA256), pkDER(0xa0, v.Bytes), pkSeq(pkOID(pkECDSA256)), pkDER(4, sig))
	infos := pkSet(si)
	if mode == "duplicate-signer" {
		infos = pkSet(si, si)
	}
	signed := pkSeq(pkNumber(3), pkSet(pkAlgorithm(pkSHA256)), pkSeq(pkOID(pkDHData), pkDER(0xa0, pkDER(4, content))), pkDER(0xa0, cert.Raw), infos)
	return pkSeq(pkOID(pkSignedData), pkDER(0xa0, signed))
}

func TestPKINITCMSAndDHRejectTampering(t *testing.T) {
	root, rkey := pkTestCertificate(t, nil, nil, true, nil)
	cert, key := pkTestCertificate(t, root, rkey, false, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5})
	trust := &pkTrust{roots: x509.NewCertPool(), realm: "NFS.TEST"}
	trust.roots.AddCert(root)
	for _, mode := range []string{"valid", "signature", "wrong-digest", "digest-substring", "duplicate-digest", "content-type", "duplicate-signer", "wrong-nonce", "zero", "one", "minus-one", "outside-subgroup", "trailing", "extra-dh-field", "small-group"} {
		t.Run(mode, func(t *testing.T) {
			y := new(big.Int).Exp(big.NewInt(2), big.NewInt(98765), pkDHPrime)
			nonce := int64(42)
			switch mode {
			case "wrong-nonce":
				nonce++
			case "zero":
				y.SetInt64(0)
			case "one":
				y.SetInt64(1)
			case "minus-one":
				y.Sub(pkDHPrime, big.NewInt(1))
			case "small-group":
				y.Set(new(big.Int).Lsh(big.NewInt(1), 4096))
			case "outside-subgroup":
				q := new(big.Int).Rsh(new(big.Int).Sub(pkDHPrime, big.NewInt(1)), 1)
				for y.SetInt64(2); new(big.Int).Exp(y, q, pkDHPrime).Cmp(big.NewInt(1)) == 0; y.Add(y, big.NewInt(1)) {
				}
			}
			content := pkSeq(pkDER(0xa0, pkDER(3, append([]byte{0}, pkInt(y)...))), pkDER(0xa1, pkNumber(nonce)))
			if mode == "extra-dh-field" {
				f, _ := pkFields(content, 0x30)
				content = pkSeq(f[0], f[1], pkDER(0xa2, pkDER(0x18, []byte("20990101000000Z"))))
			}
			cms := pkTestCMS(t, content, cert, key, mode)
			wire := pkDER(0xa0, pkSeq(pkDER(0x80, cms)))
			if mode == "trailing" {
				wire = append(wire, 0)
			}
			got, err := pkReplyKey(wire, trust, big.NewInt(12345).Bytes(), 42, 18)
			if mode == "valid" {
				if err != nil || len(got.KeyValue) != 32 {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unverified DH key accepted")
			}
		})
	}
	if pkDHPrime.BitLen() != 2048 || !pkDHPrime.ProbablyPrime(20) {
		t.Fatal("group14 constant changed")
	}
}

func TestPKINITTrustRejectsPurposeRealmAndCRLScope(t *testing.T) {
	root, rkey := pkTestCertificate(t, nil, nil, true, nil)
	for _, mode := range []string{"valid", "realm", "eku", "untrusted", "expired", "intermediate-eku", "revoked", "stale-crl", "delta-crl", "scoped-crl", "critical-crl", "critical-entry", "indirect-entry"} {
		t.Run(mode, func(t *testing.T) {
			issuer, issuerKey := root, rkey
			chain := []*x509.Certificate{}
			if mode == "intermediate-eku" {
				issuer, issuerKey = pkTestCertificate(t, root, rkey, true, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
				chain = append(chain, issuer)
			}
			cert, _ := pkTestCertificate(t, issuer, issuerKey, false, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5})
			chain = append(chain, cert)
			trust := &pkTrust{roots: x509.NewCertPool(), realm: "NFS.TEST"}
			if mode != "untrusted" {
				trust.roots.AddCert(root)
			}
			switch mode {
			case "realm":
				trust.realm = "OTHER.TEST"
			case "eku":
				cert.UnknownExtKeyUsage = nil
			case "expired":
				cert.NotAfter = time.Now().Add(-time.Minute)
			}
			if mode != "realm" && mode != "eku" && mode != "untrusted" && mode != "expired" && mode != "intermediate-eku" {
				crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
				switch mode {
				case "revoked":
					crl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: cert.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}}
				case "stale-crl":
					crl.NextUpdate = time.Now().Add(-time.Second)
				case "delta-crl":
					crl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Value: pkNumber(1)}}
				case "scoped-crl":
					crl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Value: pkSeq()}}
				case "critical-crl":
					crl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
				case "critical-entry", "indirect-entry":
					oid := asn1.ObjectIdentifier{1, 2, 3, 4}
					if mode == "indirect-entry" {
						oid = asn1.ObjectIdentifier{2, 5, 29, 29}
					}
					crl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: time.Now().Add(-time.Minute), ExtraExtensions: []pkix.Extension{{Id: oid, Critical: mode == "critical-entry", Value: pkSeq()}}}}
				}
				der, err := x509.CreateRevocationList(rand.Reader, crl, issuer, issuerKey)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := x509.ParseRevocationList(der)
				if err != nil {
					t.Fatal(err)
				}
				trust.crls = []*x509.RevocationList{parsed}
			}
			err := trust.verify(cert, chain, true)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid certificate trust accepted")
			}
		})
	}
}

func TestPKINITDERRejectsMalformed(t *testing.T) {
	for _, data := range [][]byte{{0x30, 0x80, 0, 0}, {0x30, 0x81, 0}, {0x30, 1}, {0x30, 0, 0}, bytes.Repeat([]byte{0}, (1<<20)+1)} {
		if _, err := pkFields(data, 0x30); err == nil {
			t.Fatal("malformed DER accepted")
		}
	}
	for _, data := range [][]byte{{2, 1, 0xff}, {2, 2, 0, 1}, {4, 1, 1}, {2, 0}} {
		if _, err := pkUnsigned(data); err == nil {
			t.Fatal("malformed INTEGER accepted")
		}
	}
}
