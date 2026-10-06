package client

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ValidateASAlias is also used by the pre-network NFS configuration gate.
func ValidateASAlias(alias, realm string) (types.PrincipalName, error) {
	name, r, ok := strings.Cut(alias, "@")
	if !ok || name == "" || r != realm || len(alias) > 1024 || !utf8.ValidString(alias) || strings.ContainsAny(alias, "\x00\r\n\\") {
		return types.PrincipalName{}, errors.New("--as-alias requires a bounded NAME@REALM in the selected canonical principal's realm")
	}
	p := strings.Split(name, "/")
	if len(p) > 16 || p[0] == "krbtgt" {
		return types.PrincipalName{}, errors.New("AS alias cannot be a TGT name or exceed 16 components")
	}
	for _, s := range p {
		if s == "" || len(s) > 256 {
			return types.PrincipalName{}, errors.New("AS alias has an empty/oversized component")
		}
	}
	return types.NewPrincipalName(1, name), nil
}

// RFC 6806 section 11: require the reply-key checksum of the actual AS wire
// request, even when the alias happens to equal the selected canonical name.
// FAST negotiation is not equivalent to FAST armoring and is not required here.
func (cl *Client) verifyProtectedAS(rep *messages.ASRep, req messages.ASReq, wire []byte) error {
	fail := func(s string) error { return fmt.Errorf("protected AS canonicalization: %s", s) }
	if !cl.Credentials.HasKeytab() || cl.Credentials.HasPassword() {
		return fail("canonical keytab required")
	}
	if rep.PVNO != 5 || rep.MsgType != 11 || rep.CRealm != cl.Credentials.Realm() || !rep.CName.Equal(cl.Credentials.CName()) {
		return fail("reply does not match pinned canonical principal")
	}
	if rep.EncPart.EType != 17 && rep.EncPart.EType != 18 {
		return fail("AES128/AES256 reply key required")
	}
	key, _, err := cl.Credentials.Keytab().GetEncryptionKey(cl.Credentials.CName(), cl.Credentials.Realm(), rep.EncPart.KVNO, rep.EncPart.EType)
	if err != nil {
		return err
	}
	plain, err := crypto.DecryptEncPart(rep.EncPart, key, keyusage.AS_REP_ENCPART)
	if err != nil {
		return fail("reply decryption/integrity failed")
	}
	defer clear(plain)
	if err := rep.DecryptedEncPart.Unmarshal(plain); err != nil {
		return fail("invalid encrypted reply")
	}
	part := rep.DecryptedEncPart
	if part.Nonce != req.ReqBody.Nonce || part.SRealm != req.ReqBody.Realm || !part.SName.Equal(req.ReqBody.SName) {
		return fail("nonce or authenticated home-TGT identity differs from request")
	}
	if err := cl.verifyASIdentity(*rep); err != nil {
		return err
	}
	if len(req.ReqBody.Addresses) > 0 && !types.HostAddressesEqual(part.CAddr, req.ReqBody.Addresses) {
		return fail("reply addresses differ from request")
	}
	now := time.Now().UTC()
	skew := cl.Config.LibDefaults.Clockskew
	start := part.StartTime
	if start.IsZero() {
		start = part.AuthTime
	}
	if part.AuthTime.IsZero() || part.AuthTime.Before(now.Add(-skew)) || part.AuthTime.After(now.Add(skew)) || start.After(now.Add(skew)) || !part.EndTime.After(now) || part.EndTime.Before(start) || !req.ReqBody.Till.IsZero() && part.EndTime.After(req.ReqBody.Till.Add(skew)) {
		return fail("invalid reply ticket times")
	}
	if !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Canonicalize) || !types.IsFlagSet(&part.Flags, flags.EncPARep) {
		return fail("required request/reply protection flags are absent")
	}
	requestCount := 0
	for _, pa := range req.PAData {
		if pa.PADataType == patype.PA_REQ_ENC_PA_REP {
			requestCount++
			if len(pa.PADataValue) != 0 {
				return fail("request protection padata must be empty")
			}
		}
	}
	if requestCount != 1 {
		return fail("request requires exactly one protection padata")
	}
	count := 0
	var checksum types.PAReqEncPARep
	for _, pa := range part.EncPAData {
		if pa.PADataType != patype.PA_REQ_ENC_PA_REP {
			continue
		}
		count++
		if len(pa.PADataValue) > 256 {
			return fail("oversized protected request checksum")
		}
		rest, err := asn1.Unmarshal(pa.PADataValue, &checksum)
		if err != nil || len(rest) != 0 {
			return fail("malformed protected request checksum")
		}
	}
	if count != 1 {
		return fail("required protected request checksum is missing or duplicated")
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}
	if checksum.ChksumType != et.GetHashID() || len(checksum.Chksum) != et.GetHMACBitLength()/8 || !et.VerifyChecksum(key.KeyValue, wire, checksum.Chksum, keyusage.KEY_USAGE_AS_REQ) {
		return fail("protected request checksum does not match exact AS request")
	}
	return nil
}
