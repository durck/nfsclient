package client

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func ValidateEnterpriseAS(upn, start, home string, realms []string) error {
	u, suffix, ok := strings.Cut(upn, "@")
	if !ok || u == "" || suffix == "" || len(upn) > 512 || !utf8.ValidString(upn) || strings.ContainsAny(upn, "\x00\r\n\\/") || strings.Contains(suffix, "@") {
		return errors.New("enterprise AS requires an explicit bounded USER@SUFFIX UPN")
	}
	for _, c := range upn {
		if unicode.IsControl(c) || unicode.IsSpace(c) {
			return errors.New("enterprise AS UPN cannot contain whitespace or control characters")
		}
	}
	if len(realms) == 0 || len(realms) > 6 {
		return errors.New("enterprise AS requires 1..6 explicit --as-referral-realms")
	}
	seen := map[string]bool{}
	for _, r := range realms {
		if r == "" || len(r) > 256 || !utf8.ValidString(r) || strings.ContainsAny(r, "\x00\r\n\\/@, ") || seen[r] {
			return errors.New("enterprise AS realms must be nonempty, bounded and unique")
		}
		for _, c := range r {
			if unicode.IsControl(c) || unicode.IsSpace(c) {
				return errors.New("enterprise AS realms cannot contain whitespace or control characters")
			}
		}
		seen[r] = true
	}
	if !seen[start] || !seen[home] {
		return errors.New("enterprise AS start and canonical home realm must be explicitly permitted")
	}
	return nil
}

func (cl *Client) enterpriseASExchange(original messages.ASReq) (messages.ASRep, error) {
	fail := func(s string) (messages.ASRep, error) {
		return messages.ASRep{}, fmt.Errorf("enterprise AS routing: %s", s)
	}
	if err := ValidateEnterpriseAS(cl.settings.enterpriseUPN, cl.settings.asStartRealm, cl.Credentials.Realm(), cl.settings.asReferralRealms); err != nil {
		return messages.ASRep{}, err
	}
	if !cl.Credentials.HasKeytab() || cl.Credentials.HasPassword() || cl.settings.asAlias != "" {
		return fail("one explicit canonical keytab/enterprise policy required")
	}
	allowed := map[string]bool{}
	for _, realm := range cl.settings.asReferralRealms {
		configured := false
		for _, r := range cl.Config.Realms {
			if r.Realm == realm && len(r.KDC) > 0 {
				configured = true
			}
		}
		if !configured {
			return fail("every permitted realm needs explicit KDC endpoints in krb5.conf")
		}
		allowed[realm] = true
	}
	if original.ReqBody.CName.NameType != nametype.KRB_NT_ENTERPRISE || len(original.ReqBody.CName.NameString) != 1 || original.ReqBody.CName.NameString[0] != cl.settings.enterpriseUPN {
		return fail("original enterprise name is inconsistent")
	}
	visited := map[string]bool{}
	realm := cl.settings.asStartRealm
	for hops := 0; hops < 6; hops++ {
		if !allowed[realm] || visited[realm] {
			return fail("unapproved or cyclic referral")
		}
		visited[realm] = true
		req, err := messages.NewASReqForTGT(realm, cl.Config, original.ReqBody.CName)
		if err != nil {
			return messages.ASRep{}, err
		}
		types.SetFlag(&req.ReqBody.KDCOptions, flags.Canonicalize)
		if err := setPAData(cl, nil, &req); err != nil {
			return messages.ASRep{}, err
		}
		wire, err := req.Marshal()
		if err != nil {
			return messages.ASRep{}, err
		}
		reply, err := cl.sendToKDC(wire, realm)
		if e, ok := err.(messages.KRBError); ok && (e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED || e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED) {
			// An unauthenticated mapping KDC gets the name only. Never encrypt a
			// timestamp with the home key for an intermediate realm's challenge.
			if realm != cl.Credentials.Realm() {
				return fail("preauthentication requested outside pinned canonical home realm")
			}
			cl.settings.assumePreAuthentication = true
			if err := setPAData(cl, &e, &req); err != nil {
				return messages.ASRep{}, err
			}
			wire, err = req.Marshal()
			if err != nil {
				return messages.ASRep{}, err
			}
			reply, err = cl.sendToKDC(wire, realm)
		}
		if e, ok := err.(messages.KRBError); ok && e.ErrorCode == errorcode.KDC_ERR_WRONG_REALM {
			if realm == cl.Credentials.Realm() {
				return fail("pinned home realm cannot redirect credentials")
			}
			// CName in WRONG_REALM is unauthenticated and must never be used.
			realm = e.CRealm
			continue
		}
		if err != nil {
			return messages.ASRep{}, err
		}
		if realm != cl.Credentials.Realm() {
			return fail("AS reply arrived outside pinned canonical home realm")
		}
		var rep messages.ASRep
		if err := rep.Unmarshal(reply); err != nil {
			return messages.ASRep{}, err
		}
		if err := cl.verifyProtectedAS(&rep, req, wire); err != nil {
			return messages.ASRep{}, err
		}
		return rep, nil
	}
	return fail("more than five referrals")
}
