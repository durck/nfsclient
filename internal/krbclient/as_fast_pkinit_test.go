package client

import (
	"bytes"
	"context"
	"crypto/x509"
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfs-viewer/internal/testutil/kdcfixture"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFASTPKINITRequiresArmoredFreshness(t *testing.T) {
	root, rkey := pkTestCertificate(t, nil, nil, true, nil)
	cert, key := pkTestCertificate(t, root, rkey, false, stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4})
	dir := t.TempDir()
	files := PKINITIdentity{Cert: filepath.Join(dir, "cert.pem"), Key: filepath.Join(dir, "key.pem"), CA: filepath.Join(dir, "ca.pem")}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for path, b := range map[string]*pem.Block{files.Cert: {Type: "CERTIFICATE", Bytes: cert.Raw}, files.Key: {Type: "PRIVATE KEY", Bytes: keyDER}, files.CA: {Type: "CERTIFICATE", Bytes: root.Raw}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"no-freshness", "wrong-error", "duplicate-error", "unarmored", "wrong-nonce"} {
		t.Run(mode, func(t *testing.T) {
			armor := &fastContext{key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x41}, 32)}, ap: []byte("synthetic armor AP_REQ")}
			peer := kdcfixture.Start(t, func(_ string, wire []byte) []byte {
				var req messages.ASReq
				if err := req.Unmarshal(wire); err != nil {
					t.Error(err)
					return nil
				}
				if len(req.PAData) != 1 || req.PAData[0].PADataType != 136 {
					t.Error("unarmored PKINIT request")
					return nil
				}
				failure := messages.KRBError{PVNO: 5, MsgType: 30, STime: time.Now().UTC(), ErrorCode: 25, Realm: "NFS.TEST", SName: types.NewPrincipalName(2, "krbtgt/NFS.TEST")}
				innerFailure := failure
				if mode == "wrong-error" {
					innerFailure.ErrorCode = 24
				}
				errorWire, err := innerFailure.Marshal()
				if err != nil {
					t.Error(err)
					return nil
				}
				pa := types.PADataSequence{{PADataType: 137, PADataValue: errorWire}, {PADataType: 16}}
				if mode == "duplicate-error" {
					pa = append(pa, pa[0])
				}
				response := fastResponse{Nonce: req.ReqBody.Nonce, PAData: pa}
				if mode == "wrong-nonce" {
					response.Nonce++
				}
				plain, err := asn1.Marshal(response)
				if err != nil {
					t.Error(err)
					return nil
				}
				enc, err := crypto.GetEncryptedData(plain, armor.key, 52, 0)
				if err != nil {
					t.Error(err)
					return nil
				}
				encoded, err := asn1.Marshal(fastArmoredResponse{Response: enc})
				if err != nil {
					t.Error(err)
					return nil
				}
				value, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: encoded})
				if err != nil {
					t.Error(err)
					return nil
				}
				outer := types.PADataSequence{{PADataType: 136, PADataValue: value}}
				if mode == "unarmored" {
					outer = types.PADataSequence{{PADataType: 16}, {PADataType: 150, PADataValue: []byte("untrusted fresh token")}}
				}
				failure.EData, err = asn1.Marshal(outer)
				if err != nil {
					t.Error(err)
					return nil
				}
				reply, err := failure.Marshal()
				if err != nil {
					t.Error(err)
				}
				return reply
			})
			cfg := config.New()
			cfg.LibDefaults.UDPPreferenceLimit = 1
			cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{peer.Address}}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cl := NewWithPassword("krbtgt/NFS.TEST", "NFS.TEST", "", cfg, NetworkContext(ctx))
			defer cl.Destroy()
			err := cl.loginPKINIT(files, armor)
			if err == nil {
				t.Fatal("unsafe freshness accepted")
			}
			if mode == "no-freshness" && !strings.Contains(err.Error(), "did not advertise PKINIT with freshness") {
				t.Fatal(err)
			}
			if peer.TCP.Load() != 1 {
				t.Fatalf("wanted exactly one armored freshness request, got %d: %v", peer.TCP.Load(), err)
			}
		})
	}
}
