package client

import (
	"crypto/aes"
	"crypto/sha1"
	"errors"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/types"
)

// RFC 6113 section 5.1 and appendix A. Restrict this profile to the existing
// AES128/AES256 SHA-1 Kerberos enctypes; their random-to-key is the identity.
func fastCF2(first, second types.EncryptionKey, pepper1, pepper2 string) (types.EncryptionKey, error) {
	size := 16
	if first.KeyType == 18 {
		size = 32
	}
	a, err := fastPRFPlus(first, pepper1, size)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	defer clear(a)
	b, err := fastPRFPlus(second, pepper2, size)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	defer clear(b)
	key := make([]byte, size)
	for i := range key {
		key[i] = a[i] ^ b[i]
	}
	return types.EncryptionKey{KeyType: first.KeyType, KeyValue: key}, nil
}

func fastPRFPlus(key types.EncryptionKey, pepper string, size int) ([]byte, error) {
	if key.KeyType != 17 && key.KeyType != 18 || len(pepper) > 128 || size < 1 || size > 32 {
		return nil, errors.New("FAST requires bounded AES128/AES256 key derivation")
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil || len(key.KeyValue) != et.GetKeyByteSize() {
		return nil, errors.New("invalid FAST key length")
	}
	derived, err := et.DeriveKey(key.KeyValue, []byte("prf"))
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size+aes.BlockSize)
	for counter := byte(1); len(out) < size; counter++ {
		input := append([]byte{counter}, pepper...)
		digest := sha1.Sum(input) // RFC 3961 AES PRF mandates SHA-1.
		var encrypted [aes.BlockSize]byte
		block.Encrypt(encrypted[:], digest[:aes.BlockSize])
		out = append(out, encrypted[:]...)
	}
	return out[:size], nil
}
