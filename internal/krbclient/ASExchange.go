// Adapted from github.com/jcmturner/gokrb5/v8 v8.4.4 (Apache-2.0).
// Local changes are documented in README.md.
package client

import (
	"fmt"
	"slices"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, ASReq messages.ASReq) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}
	if cl.settings.enterpriseUPN != "" || cl.settings.asStartRealm != "" || len(cl.settings.asReferralRealms) > 0 {
		return cl.enterpriseASExchange(ASReq)
	}

	// Set PAData if required
	err := setPAData(cl, nil, &ASReq)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
	}

	b, err := ASReq.Marshal()
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
	}
	var ASRep messages.ASRep

	rb, err := cl.sendToKDC(b, realm)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok {
			switch e.ErrorCode {
			case errorcode.KDC_ERR_PREAUTH_REQUIRED, errorcode.KDC_ERR_PREAUTH_FAILED:
				// From now on assume this client will need to do this pre-auth and set the PAData
				cl.settings.assumePreAuthentication = true
				err = setPAData(cl, &e, &ASReq)
				if err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
				}
				b, err = ASReq.Marshal()
				if err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ with PAData")
				}
				rb, err = cl.sendToKDC(b, realm)
				if err != nil {
					if e, ok := err.(messages.KRBError); ok {
						if e.ErrorCode == errorcode.KDC_ERR_WRONG_REALM {
							return messages.ASRep{}, rejectASClientReferral(e)
						}
						return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
					}
					return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
				}
			case errorcode.KDC_ERR_WRONG_REALM:
				return messages.ASRep{}, rejectASClientReferral(e)
			default:
				return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
			}
		} else {
			return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}
	if cl.settings.asAlias != "" {
		if err := cl.verifyProtectedAS(&ASRep, ASReq, b); err != nil {
			return messages.ASRep{}, err
		}
	} else {
		if ok, err := ASRep.Verify(cl.Config, cl.Credentials, ASReq); !ok {
			return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
		}
	}
	if err := cl.verifyASIdentity(ASRep); err != nil {
		return messages.ASRep{}, err
	}
	return ASRep, nil
}

func rejectASClientReferral(err messages.KRBError) error {
	// RFC 6806 sections 7/13: WRONG_REALM is not authenticated. This client
	// Default and same-realm alias profiles do not enable realm routing.
	return krberror.Errorf(err, krberror.KDCError, "AS client referral is unsupported; use a canonical --principal NAME@REALM with matching credentials and KDC configuration")
}

func (cl *Client) verifyASIdentity(rep messages.ASRep) error {
	if rep.CRealm != cl.Credentials.Realm() || !rep.CName.Equal(cl.Credentials.CName()) {
		return fmt.Errorf("AS reply identity: client does not match selected principal")
	}
	name := rep.DecryptedEncPart.SName
	if len(name.NameString) != 2 || name.NameString[0] != "krbtgt" || name.NameString[1] != cl.Credentials.Realm() {
		return fmt.Errorf("AS reply identity: expected home-realm TGT")
	}
	if rep.Ticket.Realm != rep.DecryptedEncPart.SRealm || rep.Ticket.Realm != cl.Credentials.Realm() {
		return fmt.Errorf("AS reply identity: ticket realm differs from authenticated home realm")
	}
	if !rep.Ticket.SName.Equal(name) {
		return fmt.Errorf("AS reply identity: ticket name differs from authenticated reply")
	}
	return nil
}

// setPAData adds pre-authentication data to the AS_REQ.
func setPAData(cl *Client, krberr *messages.KRBError, ASReq *messages.ASReq) error {
	enctypes, err := cl.asRequestEnctypes(ASReq.ReqBody.EType)
	if err != nil {
		return err
	}
	ASReq.ReqBody.EType = enctypes
	if !cl.settings.DisablePAFXFAST() || cl.settings.asAlias != "" || cl.settings.enterpriseUPN != "" {
		// A preauthentication retry must not duplicate negotiation padata.
		filtered := ASReq.PAData[:0]
		for _, pa := range ASReq.PAData {
			if pa.PADataType != patype.PA_REQ_ENC_PA_REP {
				filtered = append(filtered, pa)
			}
		}
		ASReq.PAData = filtered
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	if cl.settings.AssumePreAuthentication() && (cl.settings.enterpriseUPN == "" || ASReq.ReqBody.Realm == cl.Credentials.Realm()) {
		et, key, kvno, err := cl.preAuthKey(enctypes, krberr)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "error selecting permitted pre-authentication key")
		}
		cl.settings.preAuthEType = et.GetETypeID()
		// Generate the PA data
		paTSb, err := types.GetPAEncTSEncAsnMarshalled()
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "error creating PAEncTSEnc for Pre-Authentication")
		}
		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, kvno)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "error encrypting pre-authentication timestamp")
		}
		pb, err := paEncTS.Marshal()
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error marshaling the PAEncTSEnc encrypted data")
		}
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		// Look for and delete any exiting patype.PA_ENC_TIMESTAMP
		for i, pa := range ASReq.PAData {
			if pa.PADataType == patype.PA_ENC_TIMESTAMP {
				ASReq.PAData[i] = ASReq.PAData[len(ASReq.PAData)-1]
				ASReq.PAData = ASReq.PAData[:len(ASReq.PAData)-1]
			}
		}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	return nil
}

// Advertise only permitted algorithms for which this credential can supply an
// AS reply key. A keytab can contain a subset of the configured algorithms.
func (cl *Client) asRequestEnctypes(requested []int32) ([]int32, error) {
	var result []int32
	for _, id := range requested {
		if !slices.Contains(cl.Config.LibDefaults.PermittedEnctypeIDs, id) || slices.Contains(result, id) {
			continue
		}
		et, err := crypto.GetEtype(id)
		if err != nil {
			continue
		}
		if cl.Credentials.HasKeytab() {
			key, _, err := cl.Key(et, 0, nil)
			if err != nil || len(key.KeyValue) != et.GetKeyByteSize() {
				continue
			}
		}
		result = append(result, id)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("AS request has no permitted encryption type with an available credential key")
	}
	return result, nil
}

func (cl *Client) preAuthKey(requested []int32, challenge *messages.KRBError) (etype.EType, types.EncryptionKey, int, error) {
	candidates := slices.Clone(requested)
	var hints []preAuthHint
	if challenge != nil {
		var err error
		hints, err = preAuthHints(challenge)
		if err != nil {
			return nil, types.EncryptionKey{}, 0, err
		}
		candidates = slices.DeleteFunc(candidates, func(id int32) bool {
			return !slices.ContainsFunc(hints, func(hint preAuthHint) bool { return hint.enctype == id })
		})
	} else if id := cl.settings.preAuthEType; slices.Contains(candidates, id) {
		// Reuse an earlier choice only while the current request policy permits it.
		candidates = append([]int32{id}, slices.DeleteFunc(candidates, func(v int32) bool { return v == id })...)
	}
	for _, id := range candidates {
		et, err := crypto.GetEtype(id)
		if err != nil {
			continue
		}
		selected := challenge
		if challenge != nil {
			// Upstream password derivation uses the first entry it sees, even
			// when asked for a different enctype. Pass only the selected hint.
			filtered := *challenge
			filtered.CName, filtered.CRealm = cl.Credentials.CName(), cl.Credentials.Domain()
			for _, hint := range hints {
				if hint.enctype == id {
					filtered.EData, err = asn1.Marshal(types.PADataSequence{hint.pa})
					break
				}
			}
			if err != nil {
				return nil, types.EncryptionKey{}, 0, err
			}
			selected = &filtered
		}
		key, kvno, err := cl.Key(et, 0, selected)
		if err == nil && len(key.KeyValue) == et.GetKeyByteSize() {
			return et, key, kvno, nil
		}
	}
	return nil, types.EncryptionKey{}, 0, fmt.Errorf("preauthentication has no requested, permitted and available encryption type")
}

// RFC 4120 5.2.7.5 gives INFO2 precedence regardless of padata order. Hints are
// unauthenticated: they cannot add algorithms to the client's request policy.
type preAuthHint struct {
	enctype int32
	pa      types.PAData
}

func preAuthHints(krberr *messages.KRBError) ([]preAuthHint, error) {
	var pas types.PADataSequence
	if err := pas.Unmarshal(krberr.EData); err != nil {
		return nil, fmt.Errorf("invalid preauthentication data")
	}
	for _, kind := range []int32{patype.PA_ETYPE_INFO2, patype.PA_ETYPE_INFO} {
		var result []preAuthHint
		found := false
		for _, pa := range pas {
			if pa.PADataType != kind {
				continue
			}
			found = true
			if kind == patype.PA_ETYPE_INFO2 {
				info, err := pa.GetETypeInfo2()
				if err != nil || len(info) == 0 {
					return nil, fmt.Errorf("empty ETYPE-INFO2 or malformed entry in preauthentication reply")
				}
				for _, entry := range info {
					value, err := asn1.Marshal(types.ETypeInfo2{entry})
					if err != nil {
						return nil, err
					}
					result = append(result, preAuthHint{entry.EType, types.PAData{PADataType: kind, PADataValue: value}})
				}
			} else {
				info, err := pa.GetETypeInfo()
				if err != nil || len(info) == 0 {
					return nil, fmt.Errorf("empty ETYPE-INFO or malformed entry in preauthentication reply")
				}
				for _, entry := range info {
					value, err := asn1.Marshal(types.ETypeInfo{entry})
					if err != nil {
						return nil, err
					}
					result = append(result, preAuthHint{entry.EType, types.PAData{PADataType: kind, PADataValue: value}})
				}
			}
		}
		if found {
			return result, nil
		}
	}
	return nil, fmt.Errorf("preauthentication reply has no encryption-type hints")
}
