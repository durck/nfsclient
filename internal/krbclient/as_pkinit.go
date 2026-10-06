package client

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"filippo.io/bigmod"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// RFC 3526 group 14, the fixed 2048-bit MODP group. No peer-selected groups.
var pkDHPrime, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

func pkDHPublic(private []byte) []byte {
	q := new(big.Int).Rsh(new(big.Int).Sub(pkDHPrime, big.NewInt(1)), 1)
	params := pkSeq(pkInt(pkDHPrime), pkNumber(2), pkInt(q))
	modulus, _ := bigmod.NewModulus(pkDHPrime.Bytes())
	g, _ := bigmod.NewNat().SetBytes([]byte{2}, modulus)
	public := new(big.Int).SetBytes(bigmod.NewNat().Exp(g, private, modulus).Bytes(modulus))
	return pkSeq(pkSeq(pkOID("1.2.840.10046.2.1"), params), pkDER(3, append([]byte{0}, pkInt(public)...)))
}

func pkReplyKey(value []byte, trust *pkTrust, private []byte, nonce int, enctype int32) (types.EncryptionKey, error) {
	if enctype != 17 && enctype != 18 {
		return types.EncryptionKey{}, errors.New("PKINIT requires AES reply enctype")
	}
	v, err := pkValue(value, 0xa0)
	if err != nil {
		return types.EncryptionKey{}, errors.New("PKINIT requires signed DH reply")
	}
	info, err := pkFields(v.Bytes, 0x30)
	if err != nil || len(info) != 1 {
		return types.EncryptionKey{}, errors.New("PKINIT requires fresh DH parameters without key reuse or unrequested KDF")
	}
	signed, err := pkValue(info[0], 0x80)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	content, err := pkVerifyCMS(signed.Bytes, trust)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	f, err := pkFields(content, 0x30)
	if err != nil || len(f) != 2 {
		return types.EncryptionKey{}, errors.New("PKINIT requires fresh KDCDHKeyInfo")
	}
	bits, err := pkValue(f[0], 0xa0)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	public, err := pkValue(bits.Bytes, 3)
	if err != nil || len(public.Bytes) < 2 || public.Bytes[0] != 0 {
		return types.EncryptionKey{}, errors.New("invalid PKINIT DH bit string")
	}
	y, err := pkUnsigned(public.Bytes[1:])
	if err != nil || y.BitLen() > 2048 || y.Cmp(big.NewInt(2)) < 0 || y.Cmp(new(big.Int).Sub(pkDHPrime, big.NewInt(2))) > 0 {
		return types.EncryptionKey{}, errors.New("invalid PKINIT DH public value")
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(pkDHPrime, big.NewInt(1)), 1)
	if new(big.Int).Exp(y, q, pkDHPrime).Cmp(big.NewInt(1)) != 0 {
		return types.EncryptionKey{}, errors.New("PKINIT DH public value is outside subgroup")
	}
	n, err := pkExplicitNumber(f[1], 0xa1)
	if err != nil || n.BitLen() > 32 || n.Int64() != int64(nonce) {
		return types.EncryptionKey{}, errors.New("PKINIT DH nonce mismatch")
	}
	// bigmod.Exp uses constant-time arithmetic for the private exponent. The
	// math/big operations above only validate the public group and peer value.
	modulus, _ := bigmod.NewModulus(pkDHPrime.Bytes())
	peer, err := bigmod.NewNat().SetBytes(y.Bytes(), modulus)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	shared := bigmod.NewNat().Exp(peer, private, modulus)
	defer clear(shared.Bits())
	secret := shared.Bytes(modulus)
	defer clear(secret)
	length := 16
	if enctype == 18 {
		length = 32
	}
	out := make([]byte, 0, 40)
	for counter := byte(0); len(out) < length; counter++ {
		h := sha1.New()
		h.Write([]byte{counter})
		h.Write(secret)
		out = append(out, h.Sum(nil)...)
	}
	return types.EncryptionKey{KeyType: enctype, KeyValue: out[:length]}, nil
}

// LoginPKINIT uses an explicit certificate and pinned CA, RFC 8070 freshness,
// and a fresh RFC 4556 DH exchange. It never falls back to another AS mechanism.
func (cl *Client) LoginPKINIT(files PKINITIdentity) error {
	return cl.loginPKINIT(files, nil)
}

// LoginFASTPKINIT runs certificate preauthentication inside mandatory FAST.
// Both freshness discovery and the signed certificate exchange are armored.
func (cl *Client) LoginFASTPKINIT(files PKINITIdentity, cache *credentials.CCache) error {
	if cl == nil || cl.Config == nil || cl.Credentials.HasPassword() || cl.Credentials.HasKeytab() {
		return errors.New("FAST PKINIT requires an exclusive certificate identity")
	}
	f, err := newFASTArmor(cache, cl.Credentials.Realm())
	if err != nil {
		return err
	}
	defer clear(f.key.KeyValue)
	return cl.loginPKINIT(files, f)
}

func (cl *Client) loginPKINIT(files PKINITIdentity, armor *fastContext) error {
	if cl == nil || cl.Config == nil || cl.Credentials.HasPassword() || cl.Credentials.HasKeytab() {
		return errors.New("PKINIT requires an exclusive certificate identity")
	}
	certs, signer, trust, err := pkLoadIdentity(files, cl.Credentials.Realm(), cl.Credentials.CName().NameString)
	if err != nil {
		return err
	}
	req, err := messages.NewASReqForTGT(cl.Credentials.Realm(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return err
	}
	req.ReqBody.EType = slices.DeleteFunc(req.ReqBody.EType, func(e int32) bool { return e != 17 && e != 18 })
	if len(req.ReqBody.EType) == 0 {
		return errors.New("PKINIT requires an AES ticket enctype")
	}
	// Request a freshness token before disclosing the certificate. Only one
	// preauth round is allowed; errors/referrals never change the pinned identity.
	req.PAData = types.PADataSequence{{PADataType: 150, PADataValue: []byte{}}}
	wire, err := pkMarshalRequest(req, armor)
	if err != nil {
		return err
	}
	_, err = cl.sendToKDC(wire, cl.Credentials.Realm())
	var failure messages.KRBError
	if !errors.As(err, &failure) || failure.ErrorCode != 25 {
		return fmt.Errorf("PKINIT freshness challenge required: %v", err)
	}
	var pa types.PADataSequence
	if rest, err := asn1.Unmarshal(failure.EData, &pa); err != nil || len(rest) != 0 {
		return errors.New("invalid PKINIT challenge padata")
	}
	if armor != nil {
		response, err := armor.unwrap(pa, req.ReqBody.Nonce, nil)
		if err != nil {
			return err
		}
		if err := pkFASTChallengeError(response.PAData); err != nil {
			return err
		}
		pa = response.PAData
	}
	var freshness, cookie []byte
	var supported bool
	for _, p := range pa {
		switch p.PADataType {
		case 16:
			supported = true
		case 150:
			if freshness != nil || len(p.PADataValue) == 0 || len(p.PADataValue) > 65536 {
				return errors.New("invalid PKINIT freshness token")
			}
			freshness = p.PADataValue
		case 133:
			if cookie != nil || len(p.PADataValue) > 65536 {
				return errors.New("invalid PKINIT cookie")
			}
			cookie = p.PADataValue
		}
	}
	if !supported || len(freshness) == 0 {
		return errors.New("KDC did not advertise PKINIT with freshness; no authentication fallback")
	}
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return err
	}
	privateBytes[0] |= 0x80
	defer clear(privateBytes)
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return err
	}
	checksum := sha1.Sum(body)
	now := time.Now().UTC()
	auth := pkSeq(pkDER(0xa0, pkNumber(int64(now.Nanosecond()/1000))), pkDER(0xa1, pkDER(0x18, []byte(now.Format("20060102150405Z")))), pkDER(0xa2, pkNumber(int64(req.ReqBody.Nonce))), pkDER(0xa3, pkDER(4, checksum[:])), pkDER(0xa4, pkDER(4, freshness)))
	pack := pkSeq(pkDER(0xa0, auth), pkDER(0xa1, pkDHPublic(privateBytes)))
	cms, err := pkSignCMS(pack, certs, signer)
	if err != nil {
		return err
	}
	req.PAData = types.PADataSequence{{PADataType: 16, PADataValue: pkSeq(pkDER(0x80, cms))}}
	if cookie != nil {
		req.PAData = append(req.PAData, types.PAData{PADataType: 133, PADataValue: cookie})
	}
	wire, err = pkMarshalRequest(req, armor)
	if err != nil {
		return err
	}
	reply, err := cl.sendToKDC(wire, cl.Credentials.Realm())
	if err != nil {
		return fmt.Errorf("required PKINIT exchange: %w", err)
	}
	var rep messages.ASRep
	if err := rep.Unmarshal(reply); err != nil {
		return errors.New("invalid PKINIT AS reply")
	}
	if !slices.Contains(req.ReqBody.EType, rep.EncPart.EType) {
		return errors.New("PKINIT reply used an unrequested enctype")
	}
	replyPA := rep.PAData
	var fastReply *fastResponse
	if armor != nil {
		ticket, err := rep.Ticket.Marshal()
		if err != nil {
			return err
		}
		fastReply, err = armor.unwrap(rep.PAData, req.ReqBody.Nonce, ticket)
		if err != nil {
			return err
		}
		defer clear(fastReply.Strengthen.KeyValue)
		if fastReply.Finished.Realm != cl.Credentials.Realm() || !fastReply.Finished.Name.Equal(cl.Credentials.CName()) || time.Since(fastReply.Finished.Time).Abs() > cl.Config.LibDefaults.Clockskew {
			return errors.New("FAST PKINIT finished identity/time mismatch")
		}
		replyPA = fastReply.PAData
	}
	var value []byte
	for _, p := range replyPA {
		if p.PADataType == 17 {
			if value != nil || len(p.PADataValue) == 0 {
				return errors.New("duplicate/empty PKINIT reply")
			}
			value = p.PADataValue
		}
	}
	key, err := pkReplyKey(value, trust, privateBytes, req.ReqBody.Nonce, rep.EncPart.EType)
	if err != nil {
		return err
	}
	defer clear(key.KeyValue)
	if fastReply != nil && fastReply.Strengthen.KeyType != 0 {
		if fastReply.Strengthen.KeyType != key.KeyType {
			return errors.New("FAST PKINIT strengthen key enctype mismatch")
		}
		key, err = fastCF2(fastReply.Strengthen, key, "strengthenkey", "replykey")
		if err != nil {
			return err
		}
		defer clear(key.KeyValue)
	}
	if err := cl.verifyPreauthenticatedAS(&rep, req, key); err != nil {
		return err
	}
	cl.addSession(rep.Ticket, rep.DecryptedEncPart)
	return nil
}

func pkMarshalRequest(req messages.ASReq, armor *fastContext) ([]byte, error) {
	if armor != nil {
		wrapped, err := armor.wrap(req, req.PAData)
		if err != nil {
			return nil, err
		}
		return wrapped.Marshal()
	}
	return req.Marshal()
}

func pkFASTChallengeError(pa types.PADataSequence) error {
	count := 0
	for _, p := range pa {
		if p.PADataType != 137 {
			continue
		}
		count++
		var failure messages.KRBError
		if err := failure.Unmarshal(p.PADataValue); err != nil || failure.ErrorCode != 25 {
			return errors.New("FAST PKINIT authenticated challenge error mismatch")
		}
	}
	if count != 1 {
		return errors.New("FAST PKINIT requires one authenticated preauthentication challenge")
	}
	return nil
}
