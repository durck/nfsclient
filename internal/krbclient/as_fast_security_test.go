package client

import (
	"bytes"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestFASTResponseRejectsTampering(t *testing.T) {
	f := &fastContext{key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}}
	et, _ := crypto.GetEtype(18)
	ticket := []byte("independently bound ticket bytes")
	for _, mode := range []string{"valid", "missing", "duplicate", "trailing", "truncated", "wrong-key", "enctype", "cipher", "nonce", "ticket", "checksum-type", "finished-missing", "usec", "error-finished", "error-strengthen"} {
		t.Run(mode, func(t *testing.T) {
			sum, err := et.GetChecksumHash(f.key.KeyValue, ticket, 53)
			if err != nil {
				t.Fatal(err)
			}
			response := fastResponse{Nonce: 42, PAData: types.PADataSequence{}, Finished: fastFinished{Time: time.Now().UTC(), Realm: "NFS.TEST", Name: types.NewPrincipalName(1, "alice"), Checksum: types.Checksum{CksumType: et.GetHashID(), Checksum: sum}}}
			inputTicket := ticket
			switch mode {
			case "nonce":
				response.Nonce++
			case "ticket":
				inputTicket = []byte("another ticket")
			case "checksum-type":
				response.Finished.Checksum.CksumType++
			case "finished-missing":
				response.Finished = fastFinished{}
			case "usec":
				response.Finished.Usec = 1000000
			case "error-finished":
				inputTicket = nil
			case "error-strengthen":
				inputTicket = nil
				response.Finished = fastFinished{}
				response.Strengthen = types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
			}
			plain, err := asn1.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			key := f.key
			if mode == "wrong-key" {
				key.KeyValue = bytes.Repeat([]byte{0x43}, 32)
			}
			enc, err := crypto.GetEncryptedData(plain, key, 52, 0)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "enctype" {
				enc.EType = 17
			}
			if mode == "cipher" {
				enc.Cipher[0] ^= 1
			}
			encoded, err := asn1.Marshal(fastArmoredResponse{Response: enc})
			if err != nil {
				t.Fatal(err)
			}
			value, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: encoded})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "trailing" {
				value = append(value, 0)
			}
			if mode == "truncated" {
				value = value[:len(value)-1]
			}
			pa := types.PADataSequence{{PADataType: 136, PADataValue: value}}
			if mode == "missing" {
				pa = nil
			}
			if mode == "duplicate" {
				pa = append(pa, pa[0])
			}
			_, err = f.unwrap(pa, 42, inputTicket)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid FAST response accepted")
			}
		})
	}
}

func TestFASTKDCChallengeRejectsTampering(t *testing.T) {
	f := &fastContext{key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x31}, 32)}}
	longterm := types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x32}, 16)}
	for _, mode := range []string{"valid", "missing", "duplicate", "cipher", "client-usage", "enctype", "trailing", "stale", "microseconds"} {
		t.Run(mode, func(t *testing.T) {
			key, err := fastCF2(f.key, longterm, "kdcchallengearmor", "challengelongterm")
			if err != nil {
				t.Fatal(err)
			}
			ts := types.PAEncTSEnc{PATimestamp: time.Now().UTC(), PAUSec: 1}
			if mode == "stale" {
				ts.PATimestamp = ts.PATimestamp.Add(-time.Hour)
			}
			if mode == "microseconds" {
				ts.PAUSec = 1000000
			}
			plain, err := asn1.Marshal(ts)
			if err != nil {
				t.Fatal(err)
			}
			usage := uint32(55)
			if mode == "client-usage" {
				usage = 54
			}
			enc, err := crypto.GetEncryptedData(plain, key, usage, 0)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "enctype" {
				enc.EType = 17
			}
			if mode == "cipher" {
				enc.Cipher[0] ^= 1
			}
			wire, err := asn1.Marshal(enc)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "trailing" {
				wire = append(wire, 0)
			}
			pa := types.PADataSequence{{PADataType: 138, PADataValue: wire}}
			if mode == "missing" {
				pa = nil
			}
			if mode == "duplicate" {
				pa = append(pa, pa[0])
			}
			err = f.verifyChallenge(pa, longterm, 5*time.Minute)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid KDC challenge accepted")
			}
		})
	}
}

func TestPreauthenticatedASRejectsUnboundReply(t *testing.T) {
	cl := NewWithPassword("alice", "NFS.TEST", "", config.New())
	defer cl.Destroy()
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x52}, 32)}
	req, err := messages.NewASReqForTGT("NFS.TEST", cl.Config, cl.Credentials.CName())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "nonce", "client", "realm", "service", "ticket-service", "expired", "future", "session-key", "session-enctype", "invalid", "postdated", "renew-bounds", "cipher"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			part := messages.EncKDCRepPart{Key: key, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Minute), SRealm: "NFS.TEST", SName: types.NewPrincipalName(2, "krbtgt/NFS.TEST")}
			rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 11, CRealm: "NFS.TEST", CName: cl.Credentials.CName(), Ticket: messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: part.SName, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("ticket")}}}}
			switch mode {
			case "nonce":
				part.Nonce++
			case "client":
				rep.CName = types.NewPrincipalName(1, "bob")
			case "realm":
				rep.CRealm = "OTHER.TEST"
			case "service":
				part.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
			case "ticket-service":
				rep.Ticket.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
			case "expired":
				part.EndTime = now.Add(-time.Second)
			case "future":
				part.StartTime = now.Add(time.Hour)
			case "session-key":
				part.Key.KeyValue = nil
			case "session-enctype":
				part.Key.KeyType = 23
			case "invalid":
				types.SetFlag(&part.Flags, flags.Invalid)
			case "postdated":
				types.SetFlag(&part.Flags, flags.PostDated)
			case "renew-bounds":
				types.SetFlag(&part.Flags, flags.Renewable)
				part.RenewTill = req.ReqBody.RTime.Add(time.Hour)
			}
			plain, err := part.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			rep.EncPart, err = crypto.GetEncryptedData(plain, key, 3, 0)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cipher" {
				rep.EncPart.Cipher[0] ^= 1
			}
			err = cl.verifyPreauthenticatedAS(&rep, req, key)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unbound AS reply accepted")
			}
		})
	}
}
