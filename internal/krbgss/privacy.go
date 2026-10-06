package gssapi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

const maxSealedToken = 8 << 20

// sealingKey applies RFC 4121 section 2's acceptor/initiator/ticket priority.
// Keep privacy limited to the AES profiles verified by the local MIT fixture.
func (ctx *context) sealingKey() (types.EncryptionKey, bool, etype.EType, error) {
	key, acceptorSubkey := ctx.key, false
	if ctx.acceptor {
		if ctx.hasSubkey() {
			key, acceptorSubkey = ctx.subkey, true
		} else if ctx.hasPeerSubkey() {
			key = ctx.peerSubkey
		}
	} else {
		if ctx.hasPeerSubkey() {
			key, acceptorSubkey = ctx.peerSubkey, true
		} else if ctx.hasSubkey() {
			key = ctx.subkey
		}
	}
	if !ctx.established || ctx.flags&gssapi.ContextFlagConf == 0 {
		return key, false, nil, errors.New("GSS confidentiality context is not established")
	}
	if key.KeyType != 17 && key.KeyType != 18 {
		return key, false, nil, errors.New("GSS privacy currently requires AES128/AES256 CTS HMAC-SHA1-96")
	}
	cipher, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return key, false, nil, err
	}
	if len(key.KeyValue) != cipher.GetKeyByteSize() {
		return key, false, nil, errors.New("invalid GSS privacy key length")
	}
	return key, acceptorSubkey, cipher, nil
}

// CanSeal validates privacy support without exposing any key material.
func (ctx *context) CanSeal() error { _, _, _, err := ctx.sealingKey(); return err }

// Seal emits a confidential RFC 4121 Wrap token (EC=RRC=0). Encryption,
// random confounders, key derivation and authentication use gokrb5's AES profile.
func (ctx *context) Seal(message []byte) ([]byte, error) {
	key, subkey, cipher, err := ctx.sealingKey()
	if err != nil {
		return nil, err
	}
	if len(message) > maxSealedToken-64 {
		return nil, errors.New("GSS privacy payload exceeds limit")
	}
	if ctx.sequenceNumber == math.MaxUint64 {
		return nil, errors.New("GSS sequence exhausted")
	}
	header := make([]byte, 16)
	header[0], header[1], header[2], header[3] = 5, 4, 2, 255
	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if ctx.acceptor {
		header[2] |= 1
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	if subkey {
		header[2] |= 4
	}
	binary.BigEndian.PutUint64(header[8:], ctx.sequenceNumber)
	plain := make([]byte, len(message)+16)
	copy(plain, message)
	copy(plain[len(message):], header)
	_, sealed, err := cipher.EncryptMessage(key.KeyValue, plain, usage)
	clear(plain)
	if err != nil {
		return nil, errors.New("GSS privacy encryption failed")
	}
	ctx.sequenceNumber++
	return append(header, sealed...), nil
}

// Unseal checks direction, confidentiality, key selection, ciphertext integrity
// and the encrypted header copy before returning plaintext. RRC is applied only
// to the ciphertext, modulo its length; EC counts encrypted trailing filler.
func (ctx *context) Unseal(token []byte) ([]byte, error) {
	key, subkey, cipher, err := ctx.sealingKey()
	if err != nil {
		return nil, err
	}
	if len(token) < 16+cipher.GetConfounderByteSize()+16+cipher.GetHMACBitLength()/8 || len(token) > maxSealedToken {
		return nil, errors.New("invalid GSS privacy token size")
	}
	header := append([]byte(nil), token[:16]...)
	if header[0] != 5 || header[1] != 4 || header[3] != 255 || header[2]&2 == 0 {
		return nil, errors.New("expected sealed GSS Wrap token")
	}
	fromAcceptor := header[2]&1 != 0
	if fromAcceptor == ctx.acceptor {
		return nil, errors.New("invalid GSS privacy sender direction")
	}
	if (header[2]&4 != 0) != subkey {
		return nil, errors.New("invalid GSS privacy subkey flag")
	}
	encrypted := token[16:]
	rotation := int(binary.BigEndian.Uint16(header[6:8])) % len(encrypted)
	ciphertext := make([]byte, len(encrypted))
	copy(ciphertext, encrypted[rotation:])
	copy(ciphertext[len(encrypted)-rotation:], encrypted[:rotation])
	header[6], header[7] = 0, 0
	usage := uint32(keyusage.GSSAPI_ACCEPTOR_SEAL)
	if ctx.acceptor {
		usage = keyusage.GSSAPI_INITIATOR_SEAL
	}
	plain, err := cipher.DecryptMessage(key.KeyValue, ciphertext, usage)
	clear(ciphertext)
	if err != nil {
		return nil, errors.New("GSS privacy authentication failed")
	}
	defer clear(plain)
	filler := int(binary.BigEndian.Uint16(header[4:6]))
	if len(plain) < 16+filler || !bytes.Equal(plain[len(plain)-16:], header) {
		return nil, errors.New("GSS privacy header mismatch")
	}
	if err := ctx.checkSequenceNumber(binary.BigEndian.Uint64(header[8:])); err != nil {
		return nil, err
	}
	return append([]byte(nil), plain[:len(plain)-16-filler]...), nil
}
