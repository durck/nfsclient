// Adapted from github.com/jcmturner/gokrb5/v8 v8.4.4 (Apache-2.0).
// Local changes are documented in README.md.
package client

import (
	"fmt"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// TGSREQGenerateAndExchange generates the TGS_REQ and performs a TGS exchange to retrieve a ticket to the specified SPN.
func (cl *Client) TGSREQGenerateAndExchange(spn types.PrincipalName, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, renewal bool) (tgsReq messages.TGSReq, tgsRep messages.TGSRep, err error) {
	tgsReq, err = messages.NewTGSReq(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, spn, renewal)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: failed to generate a new TGS_REQ")
	}
	return cl.TGSExchange(tgsReq, kdcRealm, tgt, sessionKey, 0)
}

// TGSExchange exchanges the provided TGS_REQ with the KDC to retrieve a TGS_REP.
// Referrals are automatically handled.
// The client's cache is updated with the ticket received.
func (cl *Client) TGSExchange(tgsReq messages.TGSReq, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, referral int) (messages.TGSReq, messages.TGSRep, error) {
	var tgsRep messages.TGSRep
	if err := cl.setTGSAuthentication(&tgsReq, tgt, sessionKey); err != nil {
		return tgsReq, tgsRep, fmt.Errorf("TGS authenticator: %w", err)
	}
	b, err := tgsReq.Marshal()
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to marshal TGS_REQ")
	}
	r, err := cl.sendToKDC(b, kdcRealm)
	if err != nil {
		if _, ok := err.(messages.KRBError); ok {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KDCError, "TGS Exchange Error: kerberos error response from KDC when requesting for %s", tgsReq.ReqBody.SName.PrincipalNameString())
		}
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.NetworkingError, "TGS Exchange Error: issue sending TGS_REQ to KDC")
	}
	err = tgsRep.Unmarshal(r)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	err = tgsRep.DecryptEncPart(sessionKey)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	if ok, err := tgsRep.Verify(cl.Config, tgsReq); !ok {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: TGS_REP is not valid")
	}
	// Upstream permits service-name changes for referrals. Bind the clear ticket
	// name to the authenticated reply and permit only a well-formed TGT referral.
	isReferral, err := cl.verifyTGSIdentity(tgsReq, tgsRep, kdcRealm)
	if err != nil {
		return tgsReq, tgsRep, err
	}

	if isReferral {
		if tgsReq.Renewal {
			return tgsReq, tgsRep, fmt.Errorf("TGT renewal must not follow a service referral")
		}
		if cl.settings.paths != nil {
			return tgsReq, tgsRep, fmt.Errorf("capaths policy: unexpected referral from %s to %s while requesting %s", kdcRealm, tgsRep.Ticket.SName.PrincipalNameString(), tgsReq.ReqBody.SName.PrincipalNameString())
		}
		if referral >= 5 {
			return tgsReq, tgsRep, fmt.Errorf("TGS Exchange Error: maximum number of referrals exceeded")
		}
		// Server referral https://tools.ietf.org/html/rfc6806.html#section-8
		// The TGS Rep contains a TGT for another domain as the service resides in that domain.
		cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)
		realm := tgsRep.Ticket.SName.NameString[len(tgsRep.Ticket.SName.NameString)-1]
		referral++
		if types.IsFlagSet(&tgsReq.ReqBody.KDCOptions, flags.EncTktInSkey) && len(tgsReq.ReqBody.AdditionalTickets) > 0 {
			tgsReq, err = messages.NewUser2UserTGSReq(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, tgsReq.ReqBody.SName, tgsReq.Renewal, tgsReq.ReqBody.AdditionalTickets[0])
			if err != nil {
				return tgsReq, tgsRep, err
			}
		}
		tgsReq, err = messages.NewTGSReq(cl.Credentials.CName(), realm, cl.Config, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, tgsReq.ReqBody.SName, tgsReq.Renewal)
		if err != nil {
			return tgsReq, tgsRep, err
		}
		return cl.TGSExchange(tgsReq, realm, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, referral)
	}
	cl.cache.addEntry(
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Key,
	)
	cl.Log("ticket added to cache for %s (EndTime: %v)", tgsRep.Ticket.SName.PrincipalNameString(), tgsRep.DecryptedEncPart.EndTime)
	return tgsReq, tgsRep, err
}

func (cl *Client) verifyTGSIdentity(req messages.TGSReq, rep messages.TGSRep, realm string) (bool, error) {
	if rep.CRealm != cl.Credentials.Realm() {
		return false, fmt.Errorf("TGS reply identity: client realm does not match selected principal")
	}
	if rep.Ticket.Realm != rep.DecryptedEncPart.SRealm || rep.Ticket.Realm != realm {
		return false, fmt.Errorf("TGS reply identity: ticket realm differs from authenticated issuing realm")
	}
	name := rep.DecryptedEncPart.SName
	if len(name.NameString) == 0 {
		return false, fmt.Errorf("TGS reply identity: empty service name")
	}
	for _, component := range name.NameString {
		if component == "" {
			return false, fmt.Errorf("TGS reply identity: empty service name component")
		}
	}
	if !rep.Ticket.SName.Equal(name) {
		return false, fmt.Errorf("TGS reply identity: ticket name differs from authenticated reply")
	}
	if name.Equal(req.ReqBody.SName) {
		return false, nil
	}
	if len(name.NameString) != 2 || name.NameString[0] != "krbtgt" || name.NameString[1] == realm {
		return false, fmt.Errorf("TGS reply identity: unexpected service name or invalid referral")
	}
	return true, nil
}

// GetServiceTicket makes a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache
func (cl *Client) GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	var tkt messages.Ticket
	var skey types.EncryptionKey
	princ := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	realm := cl.spnRealm(princ)

	// if we don't know the SPN's realm, ask the client realm's KDC
	if realm == "" {
		realm = cl.Credentials.Realm()
	}
	if cl.settings.paths != nil {
		return cl.serviceTicketViaPath(princ, realm)
	}
	if tkt, skey, ok := cl.GetCachedTicket(spn); ok {
		return tkt, skey, nil
	}

	tgt, skey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, skey, err
	}
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(princ, realm, tgt, skey, false)
	if err != nil {
		return tkt, skey, err
	}
	return tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}
