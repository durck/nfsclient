package gssapi

import "github.com/jcmturner/gokrb5/v8/crypto"

// TokenSizes reports RFC 4121 token overhead without consuming a sequence
// number. Seal uses AES CTS with no padding: an outer header, confounder,
// encrypted header copy and checksum. MIC has a header and checksum only.
func (ctx *context) TokenSizes() (mic, sealOverhead int, err error) {
	key := ctx.key
	if ctx.hasSubkey() {
		key = ctx.subkey
	} else if ctx.hasPeerSubkey() {
		key = ctx.peerSubkey
	}
	cipher, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return 0, 0, err
	}
	mic = 16 + cipher.GetHMACBitLength()/8
	// This is the same AES-only policy as Seal; authentication/integrity
	// callers can still use the MIC size for other supported key types.
	if _, _, sealingCipher, sealErr := ctx.sealingKey(); sealErr == nil {
		sealOverhead = 32 + sealingCipher.GetConfounderByteSize() + sealingCipher.GetHMACBitLength()/8
	}
	return mic, sealOverhead, nil
}
