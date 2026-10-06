package gssapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

func privacyPair(etype int32, subkeys bool) (*context, *context) {
	n := 16
	if etype == 18 {
		n = 32
	}
	key := types.EncryptionKey{KeyType: etype, KeyValue: bytes.Repeat([]byte{0x31}, n)}
	a := &context{key: key, established: true, flags: gssapi.ContextFlagConf}
	b := &context{key: key, established: true, flags: gssapi.ContextFlagConf, acceptor: true}
	if subkeys {
		initiatorKey := types.EncryptionKey{KeyType: etype, KeyValue: bytes.Repeat([]byte{0x42}, n)}
		acceptorKey := types.EncryptionKey{KeyType: etype, KeyValue: bytes.Repeat([]byte{0x53}, n)}
		a.subkey, b.peerSubkey = initiatorKey, initiatorKey
		a.peerSubkey, b.subkey = acceptorKey, acceptorKey
	}
	return a, b
}

func TestPrivacyRoundTrips(t *testing.T) {
	for _, etype := range []int32{17, 18} {
		for _, subkeys := range []bool{false, true} {
			t.Run(fmt.Sprintf("etype%d/subkeys%v", etype, subkeys), func(t *testing.T) {
				a, b := privacyPair(etype, subkeys)
				for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 32772} {
					payload := bytes.Repeat([]byte{0x77}, n)
					for _, pair := range [][2]*context{{a, b}, {b, a}} {
						token, err := pair[0].Seal(payload)
						if err != nil {
							t.Fatal(err)
						}
						got, err := pair[1].Unseal(token)
						if err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("size %d: %v", n, err)
						}
						if n >= 32 && bytes.Contains(token, payload) {
							t.Fatal("plaintext on wire")
						}
						// RRC is deliberately larger than the ciphertext; RFC 4121 uses modulo.
						rotation := (len(token)*3 + 7) % 65536
						body := append([]byte(nil), token[16:]...)
						r := rotation % len(body)
						copy(token[16:], append(body[len(body)-r:], body[:len(body)-r]...))
						binary.BigEndian.PutUint16(token[6:8], uint16(rotation))
						got, err = pair[1].Unseal(token)
						if err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("rotated size %d: %v", n, err)
						}
					}
				}
			})
		}
	}
}

func TestPrivacyRejectsAlteredTokens(t *testing.T) {
	a, b := privacyPair(18, true)
	payload := []byte("synthetic private content")
	token, err := a.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 1, 2, 3, 4, 5, 8, 15, 16, len(token) - 1} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			bad := append([]byte(nil), token...)
			bad[offset] ^= 1
			if got, err := b.Unseal(bad); err == nil || len(got) != 0 {
				t.Fatal("altered token accepted")
			}
		})
	}
	for n := 0; n < len(token); n++ {
		if got, err := b.Unseal(token[:n]); err == nil || len(got) != 0 {
			t.Fatalf("truncation %d accepted", n)
		}
	}
	if _, err := a.Unseal(token); err == nil {
		t.Fatal("reflection accepted")
	}
	wrong, _ := privacyPair(18, false)
	wrong.acceptor = true
	if _, err := wrong.Unseal(token); err == nil {
		t.Fatal("wrong subkey flag accepted")
	}
	b.subkey.KeyValue = bytes.Repeat([]byte{0x99}, 32)
	if _, err := b.Unseal(token); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestPrivacyEncryptedFillerAndConfounder(t *testing.T) {
	a, b := privacyPair(17, false)
	first, _ := a.Seal([]byte("body"))
	a.sequenceNumber = 0
	second, _ := a.Seal([]byte("body"))
	if bytes.Equal(first, second) {
		t.Fatal("confounder is not random")
	}
	// Independently build a token with EC filler, as permitted by RFC 4121.
	header := []byte{5, 4, 2, 255, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	key, _, cipher, err := a.sealingKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := append([]byte("body"), bytes.Repeat([]byte{0xff}, 7)...)
	plain = append(plain, header...)
	_, encrypted, err := cipher.EncryptMessage(key.KeyValue, plain, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Unseal(append(header, encrypted...))
	if err != nil || string(got) != "body" {
		t.Fatalf("filler: %v", err)
	}
}

func TestPrivacyContextAndBounds(t *testing.T) {
	a, b := privacyPair(17, false)
	if _, err := a.Seal(make([]byte, maxSealedToken)); err == nil {
		t.Fatal("oversized plaintext accepted")
	}
	if _, err := b.Unseal(make([]byte, maxSealedToken+1)); err == nil {
		t.Fatal("oversized token accepted")
	}
	a.sequenceNumber = math.MaxUint64
	if _, err := a.Seal(nil); err == nil {
		t.Fatal("sequence wrapped")
	}
	for _, mutate := range []func(*context){
		func(c *context) { c.established = false }, func(c *context) { c.flags = 0 },
		func(c *context) { c.key.KeyType = 23 }, func(c *context) { c.key.KeyValue = nil },
	} {
		c, _ := privacyPair(17, false)
		mutate(c)
		if c.CanSeal() == nil {
			t.Fatal("unsupported context accepted")
		}
		if _, err := c.Seal(nil); err == nil {
			t.Fatal("unsupported context encrypted")
		}
		if _, err := c.Unseal(make([]byte, 100)); err == nil {
			t.Fatal("unsupported context decrypted")
		}
	}
}
