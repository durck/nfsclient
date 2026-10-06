package cli

import (
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/pkcs12"
)

// expandPFXToTempFiles reads a PKCS12/PFX file, extracts the leaf certificate
// and private key, writes them as PEM to temporary files, and returns their
// absolute paths plus a cleanup function.  Call cleanup() when the connection
// is closed to remove the temporary files.
func expandPFXToTempFiles(pfxPath, password string) (certFile, keyFile string, cleanup func(), err error) {
	data, err := os.ReadFile(pfxPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("read pfx: %w", err)
	}

	// ToPEM extracts all PEM blocks from a PKCS12 container.
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return "", "", nil, fmt.Errorf("decode pfx: %w", err)
	}

	var certPEM, keyPEM []byte
	for _, b := range blocks {
		switch b.Type {
		case "CERTIFICATE":
			if certPEM == nil { // use the first (leaf) certificate
				certPEM = pem.EncodeToMemory(b)
			}
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			keyPEM = pem.EncodeToMemory(b)
		}
	}
	if certPEM == nil {
		return "", "", nil, fmt.Errorf("pfx contains no certificate")
	}
	if keyPEM == nil {
		return "", "", nil, fmt.Errorf("pfx contains no private key")
	}

	cf, err := os.CreateTemp("", "nfs-viewer-pkinit-cert-*.pem")
	if err != nil {
		return "", "", nil, err
	}
	if _, err = cf.Write(certPEM); err != nil {
		cf.Close()
		os.Remove(cf.Name())
		return "", "", nil, err
	}
	cf.Close()

	kf, err := os.CreateTemp("", "nfs-viewer-pkinit-key-*.pem")
	if err != nil {
		os.Remove(cf.Name())
		return "", "", nil, err
	}
	if err = kf.Chmod(0o600); err != nil {
		kf.Close()
		os.Remove(cf.Name())
		os.Remove(kf.Name())
		return "", "", nil, err
	}
	if _, err = kf.Write(keyPEM); err != nil {
		kf.Close()
		os.Remove(cf.Name())
		os.Remove(kf.Name())
		return "", "", nil, err
	}
	kf.Close()

	return cf.Name(), kf.Name(), func() {
		os.Remove(cf.Name())
		os.Remove(kf.Name())
	}, nil
}
