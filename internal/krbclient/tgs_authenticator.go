// Adapted from github.com/jcmturner/gokrb5/v8 v8.4.4 messages/KDCReq.go (Apache-2.0).
// Local changes are documented in README.md.
package client

import (
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Rebuild PA-TGS-REQ using the selected client's realm, not the ticket issuer.
// After an intermediate hop these differ (RFC 4120 sections 1.2/3.3/5.5.1).
// Keep the ticket, destination realm, options and body checksum intact.
func (cl *Client) setTGSAuthentication(req *messages.TGSReq, tgt messages.Ticket, key types.EncryptionKey) error {
	if !req.ReqBody.CName.Equal(cl.Credentials.CName()) {
		return fmt.Errorf("request client differs from selected principal")
	}
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return err
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}
	checksum, err := et.GetChecksumHash(key.KeyValue, body, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return err
	}
	auth, err := types.NewAuthenticator(cl.Credentials.Realm(), cl.Credentials.CName())
	if err != nil {
		return err
	}
	auth.Cksum = types.Checksum{CksumType: et.GetHashID(), Checksum: checksum}
	ap, err := messages.NewAPReq(tgt, key, auth)
	if err != nil {
		return err
	}
	wire, err := ap.Marshal()
	if err != nil {
		return err
	}
	pa := make(types.PADataSequence, 0, len(req.PAData)+1)
	for _, entry := range req.PAData {
		if entry.PADataType != patype.PA_TGS_REQ {
			pa = append(pa, entry)
		}
	}
	req.PAData = append(pa, types.PAData{PADataType: patype.PA_TGS_REQ, PADataValue: wire})
	return nil
}
