package client

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const fastPA = 136

type fastArmor struct {
	Type  int    `asn1:"explicit,tag:0"`
	Value []byte `asn1:"explicit,tag:1"`
}
type fastArmoredRequest struct {
	Armor    fastArmor           `asn1:"explicit,tag:0"`
	Checksum types.Checksum      `asn1:"explicit,tag:1"`
	Request  types.EncryptedData `asn1:"explicit,tag:2"`
}
type fastRequest struct {
	Options asn1.BitString       `asn1:"explicit,tag:0"`
	PAData  types.PADataSequence `asn1:"explicit,tag:1"`
	Body    asn1.RawValue        `asn1:"explicit,tag:2"`
}
type fastArmoredResponse struct {
	Response types.EncryptedData `asn1:"explicit,tag:0"`
}
type fastFinished struct {
	Time     time.Time           `asn1:"generalized,explicit,tag:0"`
	Usec     int                 `asn1:"explicit,tag:1"`
	Realm    string              `asn1:"generalstring,explicit,tag:2"`
	Name     types.PrincipalName `asn1:"explicit,tag:3"`
	Checksum types.Checksum      `asn1:"explicit,tag:4"`
}
type fastResponse struct {
	PAData     types.PADataSequence `asn1:"explicit,tag:0"`
	Strengthen types.EncryptionKey  `asn1:"explicit,optional,tag:1"`
	Finished   fastFinished         `asn1:"explicit,optional,tag:2"`
	Nonce      int                  `asn1:"explicit,tag:3"`
}
type fastContext struct {
	key types.EncryptionKey
	ap  []byte
}

func newFASTArmor(cache *credentials.CCache, realm string) (*fastContext, error) {
	if cache == nil || cache.DefaultPrincipal.Realm != realm {
		return nil, errors.New("FAST armor must contain an explicit home-realm TGT")
	}
	// Reuse the strict cache identity/lifetime checks, which copy key material.
	checked, err := NewFromCCache(cache, config.New())
	if checked != nil {
		defer checked.Destroy()
	}
	if err != nil {
		return nil, err
	}
	cred, ok := cache.GetEntry(types.NewPrincipalName(2, "krbtgt/"+realm))
	if !ok || cred.Key.KeyType != 17 && cred.Key.KeyType != 18 {
		return nil, errors.New("FAST armor requires an AES home TGT")
	}
	et, _ := crypto.GetEtype(cred.Key.KeyType)
	if len(cred.Key.KeyValue) != et.GetKeyByteSize() {
		return nil, errors.New("invalid FAST armor session key")
	}
	var ticket messages.Ticket
	if err := ticket.Unmarshal(cred.Ticket); err != nil {
		return nil, errors.New("invalid FAST armor ticket")
	}
	subkey := types.EncryptionKey{KeyType: cred.Key.KeyType, KeyValue: make([]byte, et.GetKeyByteSize())}
	if _, err := rand.Read(subkey.KeyValue); err != nil {
		return nil, err
	}
	defer clear(subkey.KeyValue)
	now := time.Now().UTC()
	auth := types.Authenticator{AVNO: 5, CRealm: realm, CName: cache.DefaultPrincipal.PrincipalName, CTime: now, Cusec: now.Nanosecond() / 1000, SubKey: subkey}
	plain, err := auth.Marshal()
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	// Armor uses AP-REQ usage 11, including when its service is krbtgt.
	enc, err := crypto.GetEncryptedData(plain, cred.Key, 11, 0)
	if err != nil {
		return nil, err
	}
	ap := messages.APReq{PVNO: 5, MsgType: 14, APOptions: types.NewKrbFlags(), Ticket: ticket, EncryptedAuthenticator: enc}
	wire, err := ap.Marshal()
	if err != nil {
		return nil, err
	}
	key, err := fastCF2(subkey, cred.Key, "subkeyarmor", "ticketarmor")
	if err != nil {
		return nil, err
	}
	return &fastContext{key: key, ap: wire}, nil
}

func (f *fastContext) wrap(req messages.ASReq, inner types.PADataSequence) (messages.ASReq, error) {
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return req, err
	}
	et, _ := crypto.GetEtype(f.key.KeyType)
	sum, err := et.GetChecksumHash(f.key.KeyValue, body, 50)
	if err != nil {
		return req, err
	}
	if inner == nil {
		inner = types.PADataSequence{}
	}
	plain, err := asn1.Marshal(fastRequest{Options: types.NewKrbFlags(), PAData: inner, Body: asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: body}})
	if err != nil {
		return req, err
	}
	defer clear(plain)
	enc, err := crypto.GetEncryptedData(plain, f.key, 51, 0)
	if err != nil {
		return req, err
	}
	armored, err := asn1.Marshal(fastArmoredRequest{Armor: fastArmor{Type: 1, Value: f.ap}, Checksum: types.Checksum{CksumType: et.GetHashID(), Checksum: sum}, Request: enc})
	if err != nil {
		return req, err
	}
	value, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: armored})
	if err != nil {
		return req, err
	}
	req.PAData = types.PADataSequence{{PADataType: fastPA, PADataValue: value}}
	return req, nil
}

func (f *fastContext) unwrap(pa types.PADataSequence, nonce int, ticket []byte) (*fastResponse, error) {
	var value []byte
	for _, p := range pa {
		if p.PADataType == fastPA {
			if value != nil || len(p.PADataValue) == 0 || len(p.PADataValue) > 1<<20 {
				return nil, errors.New("duplicated/invalid FAST response")
			}
			value = p.PADataValue
		}
	}
	var armored fastArmoredResponse
	if rest, err := asn1.UnmarshalWithParams(value, &armored, "explicit,tag:0"); err != nil || len(rest) != 0 || armored.Response.EType != f.key.KeyType {
		return nil, errors.New("missing or malformed FAST response; no unarmored fallback")
	}
	plain, err := crypto.DecryptEncPart(armored.Response, f.key, 52)
	if err != nil {
		return nil, errors.New("FAST response integrity failed")
	}
	defer clear(plain)
	var response fastResponse
	if rest, err := asn1.Unmarshal(plain, &response); err != nil || len(rest) != 0 || response.Nonce != nonce {
		return nil, errors.New("FAST response framing/nonce mismatch")
	}
	if ticket == nil {
		if response.Finished.Realm != "" || response.Strengthen.KeyType != 0 {
			return nil, errors.New("unexpected finished/strengthen key in FAST error")
		}
		return &response, nil
	}
	et, _ := crypto.GetEtype(f.key.KeyType)
	if response.Finished.Realm == "" || response.Finished.Usec < 0 || response.Finished.Usec >= 1000000 || response.Finished.Checksum.CksumType != et.GetHashID() || !et.VerifyChecksum(f.key.KeyValue, ticket, response.Finished.Checksum.Checksum, 53) {
		return nil, errors.New("FAST finished ticket binding failed")
	}
	return &response, nil
}

// LoginFAST performs a required armored AS conversation with an explicit
// keytab and armor TGT. Both requests, including preauthentication, are armored.
func (cl *Client) LoginFAST(cache *credentials.CCache) error {
	if cl == nil || cl.Config == nil || !cl.Credentials.HasKeytab() || cl.Credentials.HasPassword() {
		return errors.New("required FAST needs explicit keytab and configuration")
	}
	f, err := newFASTArmor(cache, cl.Credentials.Realm())
	if err != nil {
		return err
	}
	defer clear(f.key.KeyValue)
	req, err := messages.NewASReqForTGT(cl.Credentials.Realm(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return err
	}
	req.ReqBody.EType, err = cl.asRequestEnctypes(req.ReqBody.EType)
	if err != nil {
		return err
	}
	req.ReqBody.EType = slices.DeleteFunc(req.ReqBody.EType, func(id int32) bool { return id != 17 && id != 18 })
	if len(req.ReqBody.EType) == 0 {
		return errors.New("FAST requires an available AES128/AES256 key")
	}
	var inner types.PADataSequence
	for round := 0; round < 2; round++ {
		wrapped, err := f.wrap(req, inner)
		if err != nil {
			return err
		}
		wire, err := wrapped.Marshal()
		if err != nil {
			return err
		}
		reply, err := cl.sendToKDC(wire, cl.Credentials.Realm())
		if err != nil {
			var failure messages.KRBError
			if round != 0 || !errors.As(err, &failure) || failure.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
				return fmt.Errorf("required FAST exchange: %w", err)
			}
			var data types.PADataSequence
			if rest, err := asn1.Unmarshal(failure.EData, &data); err != nil || len(rest) != 0 {
				return errors.New("invalid FAST challenge padata")
			}
			challenge, err := f.unwrap(data, req.ReqBody.Nonce, nil)
			if err != nil {
				return err
			}
			inner, err = cl.fastPreauth(f, req, challenge.PAData)
			if err != nil {
				return err
			}
			continue
		}
		var rep messages.ASRep
		if err := rep.Unmarshal(reply); err != nil {
			return errors.New("invalid FAST AS reply")
		}
		ticket, err := rep.Ticket.Marshal()
		if err != nil {
			return err
		}
		response, err := f.unwrap(rep.PAData, req.ReqBody.Nonce, ticket)
		if err != nil {
			return err
		}
		if response.Finished.Realm != cl.Credentials.Realm() || !response.Finished.Name.Equal(cl.Credentials.CName()) || time.Since(response.Finished.Time).Abs() > cl.Config.LibDefaults.Clockskew {
			return errors.New("FAST finished identity/time mismatch")
		}
		if !slices.Contains(req.ReqBody.EType, rep.EncPart.EType) {
			return errors.New("FAST reply used an unrequested enctype")
		}
		key, _, err := cl.Credentials.Keytab().GetEncryptionKey(cl.Credentials.CName(), cl.Credentials.Realm(), rep.EncPart.KVNO, rep.EncPart.EType)
		if err != nil {
			return err
		}
		if inner.Contains(138) {
			if response.Strengthen.KeyType == 0 {
				return errors.New("FAST encrypted challenge requires reply-key strengthening")
			}
			if err := f.verifyChallenge(response.PAData, key, cl.Config.LibDefaults.Clockskew); err != nil {
				return err
			}
		}
		if response.Strengthen.KeyType != 0 {
			defer clear(response.Strengthen.KeyValue)
			if response.Strengthen.KeyType != key.KeyType {
				return errors.New("FAST strengthen key enctype mismatch")
			}
			key, err = fastCF2(response.Strengthen, key, "strengthenkey", "replykey")
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
	return errors.New("required FAST did not complete")
}

func (f *fastContext) verifyChallenge(pa types.PADataSequence, longterm types.EncryptionKey, skew time.Duration) error {
	key, err := fastCF2(f.key, longterm, "kdcchallengearmor", "challengelongterm")
	if err != nil {
		return err
	}
	defer clear(key.KeyValue)
	var value []byte
	for _, p := range pa {
		if p.PADataType != 138 {
			continue
		}
		if value != nil || len(p.PADataValue) == 0 || len(p.PADataValue) > 1024 {
			return errors.New("invalid FAST KDC challenge")
		}
		value = p.PADataValue
	}
	var encrypted types.EncryptedData
	if rest, err := asn1.Unmarshal(value, &encrypted); err != nil || len(rest) != 0 || encrypted.EType != key.KeyType {
		return errors.New("missing/malformed FAST KDC challenge")
	}
	plain, err := crypto.DecryptEncPart(encrypted, key, 55)
	if err != nil {
		return errors.New("FAST KDC challenge integrity failed")
	}
	defer clear(plain)
	var timestamp types.PAEncTSEnc
	if rest, err := asn1.Unmarshal(plain, &timestamp); err != nil || len(rest) != 0 || timestamp.PAUSec < 0 || timestamp.PAUSec >= 1000000 || time.Since(timestamp.PATimestamp).Abs() > skew {
		return errors.New("invalid/stale FAST KDC challenge timestamp")
	}
	return nil
}

func (cl *Client) fastPreauth(f *fastContext, req messages.ASReq, pa types.PADataSequence) (types.PADataSequence, error) {
	var encryptedChallenge, timestamp, authenticatedError bool
	var cookie []byte
	for _, p := range pa {
		switch p.PADataType {
		case 138:
			encryptedChallenge = true
		case 2:
			timestamp = true
		case 133:
			if cookie != nil || len(p.PADataValue) > 65536 {
				return nil, errors.New("invalid FAST cookie")
			}
			cookie = p.PADataValue
		case 137:
			var failure messages.KRBError
			if authenticatedError || failure.Unmarshal(p.PADataValue) != nil || failure.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
				return nil, errors.New("FAST authenticated error differs from preauth challenge")
			}
			authenticatedError = true
		}
	}
	if !authenticatedError || !encryptedChallenge && !timestamp {
		return nil, errors.New("FAST challenge lacks an authenticated supported preauth factor")
	}
	hints, err := asn1.Marshal(pa)
	if err != nil {
		return nil, err
	}
	_, key, _, err := cl.preAuthKey(req.ReqBody.EType, &messages.KRBError{EData: hints})
	if err != nil {
		return nil, err
	}
	usage, kind := uint32(1), int32(2)
	if encryptedChallenge {
		key, err = fastCF2(f.key, key, "clientchallengearmor", "challengelongterm")
		if err != nil {
			return nil, err
		}
		defer clear(key.KeyValue)
		usage, kind = 54, 138
	}
	plain, err := types.GetPAEncTSEncAsnMarshalled()
	if err != nil {
		return nil, err
	}
	enc, err := crypto.GetEncryptedData(plain, key, usage, 0)
	if err != nil {
		return nil, err
	}
	value, err := asn1.Marshal(enc)
	if err != nil {
		return nil, err
	}
	result := types.PADataSequence{{PADataType: kind, PADataValue: value}}
	if cookie != nil {
		result = append(result, types.PAData{PADataType: 133, PADataValue: cookie})
	}
	return result, nil
}

func (cl *Client) verifyPreauthenticatedAS(rep *messages.ASRep, req messages.ASReq, key types.EncryptionKey) error {
	if rep.PVNO != 5 || rep.MsgType != 11 || rep.EncPart.EType != key.KeyType {
		return errors.New("preauthenticated AS reply header/enctype mismatch")
	}
	plain, err := crypto.DecryptEncPart(rep.EncPart, key, 3)
	if err != nil {
		return errors.New("preauthenticated AS reply integrity failed")
	}
	defer clear(plain)
	if err := rep.DecryptedEncPart.Unmarshal(plain); err != nil {
		return errors.New("invalid preauthenticated AS encrypted reply")
	}
	p := rep.DecryptedEncPart
	if p.Flags.BitLength != 32 || len(p.Flags.Bytes) != 4 || types.IsFlagSet(&p.Flags, flags.Invalid) || types.IsFlagSet(&p.Flags, flags.PostDated) {
		return errors.New("preauthenticated AS reply has invalid/postdated ticket flags")
	}
	if types.IsFlagSet(&p.Flags, flags.Renewable) && (p.RenewTill.Before(p.EndTime) || req.ReqBody.RTime.IsZero() || p.RenewTill.After(req.ReqBody.RTime.Add(cl.Config.LibDefaults.Clockskew))) {
		return errors.New("preauthenticated AS reply renewal bounds mismatch")
	}
	if p.Nonce != req.ReqBody.Nonce || p.SRealm != req.ReqBody.Realm || !p.SName.Equal(req.ReqBody.SName) || !slices.Contains(req.ReqBody.EType, p.Key.KeyType) {
		return errors.New("preauthenticated AS nonce/service/session enctype mismatch")
	}
	et, err := crypto.GetEtype(p.Key.KeyType)
	if err != nil || len(p.Key.KeyValue) != et.GetKeyByteSize() {
		return errors.New("preauthenticated AS session key length mismatch")
	}
	if err := cl.verifyASIdentity(*rep); err != nil {
		return err
	}
	now, skew := time.Now().UTC(), cl.Config.LibDefaults.Clockskew
	start := p.StartTime
	if start.IsZero() {
		start = p.AuthTime
	}
	if p.AuthTime.IsZero() || p.AuthTime.Before(now.Add(-skew)) || p.AuthTime.After(now.Add(skew)) || start.After(now.Add(skew)) || !p.EndTime.After(now) || p.EndTime.Before(start) || p.EndTime.After(req.ReqBody.Till.Add(skew)) {
		return errors.New("preauthenticated AS reply ticket lifetime mismatch")
	}
	if len(req.ReqBody.Addresses) > 0 && !types.HostAddressesEqual(p.CAddr, req.ReqBody.Addresses) {
		return errors.New("preauthenticated AS reply addresses mismatch")
	}
	return nil
}
