package nfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

func gssCallbackCall(t *testing.T, g *gssBackchannel, r *layoutRecall, rpcSeq, callbackSeq uint32) encoder {
	t.Helper()
	plain := callbackCall(r, callbackSeq, true)
	if r.layoutType != 0 {
		binary.BigEndian.PutUint32(plain[len(callbackCall(r, callbackSeq, false))+4:], r.layoutType)
	}
	if r.minor != 0 {
		binary.BigEndian.PutUint32(plain[44:48], r.minor)
	}
	return gssProtectCallback(t, g, plain, rpcSeq)
}

func gssProtectCallback(t *testing.T, g *gssBackchannel, plain encoder, rpcSeq uint32) encoder {
	t.Helper()
	var cred encoder
	version := uint32(1)
	if g.rpcVersion == 3 {
		version = 3
	}
	cred.u32(version)
	cred.u32(0)
	cred.u32(rpcSeq)
	cred.u32(g.service)
	cred.opaque(g.handle)
	raw := append(encoder(nil), plain[:24]...)
	raw.u32(6)
	raw.opaque(cred)
	mic, err := g.context.MakeSignature(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw.u32(6)
	raw.opaque(mic)
	protected := rpcGSS{context: g.context, seq: rpcSeq, service: g.service}
	body, err := protected.protect(plain[40:])
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, body...)
}

func TestGSSBackchannelAuthentication(t *testing.T) {
	for _, service := range []uint32{1, 2, 3} {
		for _, mode := range []string{"ok", "header", "body", "wrong-handle", "wrong-service", "expired", "downgrade", "replay", "new-rpc-retry", "stale-window", "zero-sequence"} {
			t.Run(fmt.Sprintf("service=%d/%s", service, mode), func(t *testing.T) {
				fore := &rpcGSS{context: callbackTestPrivacy{}, handle: []byte("fore"), service: service, window: 16, established: true, expiry: time.Now().Add(time.Hour)}
				g, err := newGSSBackchannel(fore)
				if err != nil {
					t.Fatal(err)
				}
				r := &layoutRecall{minor: 1, session: bytes.Repeat([]byte{3}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{4}, 16)}
				seq := uint32(1)
				if mode == "zero-sequence" {
					seq = 0
				}
				call := gssCallbackCall(t, g, r, seq, 1)
				switch mode {
				case "header":
					call[0] ^= 1
				case "body":
					call[len(call)-1] ^= 1
				case "wrong-handle":
					g.handle = []byte("other")
				case "wrong-service":
					g.service = 4
				case "expired":
					g.expiry = time.Now().Add(-time.Second)
				case "downgrade":
					call = callbackCall(r, 1, true)
				case "stale-window":
					g.highest = 18
				}
				reply, err := g.callback(call, r)
				ok := mode == "ok" || mode == "replay" || mode == "new-rpc-retry"
				if !ok {
					if err == nil || r.recalled || r.sequence != 0 {
						t.Fatal("unauthenticated mutation", mode, err, r.sequence)
					}
					return
				}
				if err != nil || !r.recalled || r.sequence != 1 {
					t.Fatal("valid recall", err, r.sequence)
				}
				d := &decoder{b: reply}
				d.take(12)
				d.verifierFlavor = d.u32()
				d.verifier = d.opaque(400)
				if d.u32() != 0 {
					t.Fatal("RPC status")
				}
				verifier := rpcGSS{context: g.context, seq: 1, service: g.service}
				if err := verifier.verify(d, 1); err != nil {
					t.Fatal(err)
				}
				if err := verifier.unprotect(d); err != nil || binary.BigEndian.Uint32(d.b) != 0 {
					t.Fatal("protected reply", err)
				}
				if mode == "replay" {
					if _, err := g.callback(call, r); err == nil {
						t.Fatal("RPC replay accepted")
					}
				}
				if mode == "new-rpc-retry" {
					if _, err := g.callback(gssCallbackCall(t, g, r, 2, 1), r); err != nil || r.sequence != 1 {
						t.Fatal("valid NFS retry under fresh RPC sequence", err)
					}
				}
			})
		}
	}
}

// AES-GCM isolates authenticated callback framing from Kerberos ticket setup.
// The existing krbgss/MIT tests separately exercise the Kerberos mechanism.
type callbackTestPrivacy struct{ testMIC }

func TestGSSBackchannelNegotiatedSizes(t *testing.T) {
	for _, service := range []uint32{2, 3} {
		for _, mode := range []string{"request", "response", "cache"} {
			t.Run(fmt.Sprintf("%d/%s", service, mode), func(t *testing.T) {
				g, err := newGSSBackchannel(&rpcGSS{context: callbackTestPrivacy{}, handle: []byte("fore"), service: service, window: 16, established: true})
				if err != nil {
					t.Fatal(err)
				}
				r := &layoutRecall{minor: 1, session: bytes.Repeat([]byte{3}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{4}, 16), requestLimit: 4096, responseLimit: 4096, cacheLimit: 4096}
				call := gssCallbackCall(t, g, r, 1, 1)
				if mode == "request" {
					r.requestLimit = uint32(len(call) - 1)
				}
				if mode == "response" {
					r.responseLimit = 1024
				}
				if mode == "cache" {
					r.cacheLimit = 1024
				}
				reply, err := g.callback(call, r)
				if err != nil {
					if mode != "response" {
						t.Fatal(err)
					}
				} else {
					d := &decoder{b: reply}
					d.take(12)
					d.verifierFlavor = d.u32()
					d.verifier = d.opaque(400)
					d.u32()
					check := rpcGSS{context: g.context, seq: 1, service: service}
					if err = check.verify(d, 1); err != nil {
						t.Fatal(err)
					}
					if err = check.unprotect(d); err != nil {
						t.Fatal(err)
					}
					if d.u32() == 0 {
						t.Fatal("oversized callback succeeded")
					}
				}
				if r.recalled {
					t.Fatal("oversized callback applied recall")
				}
				if mode == "request" && r.sequence != 0 {
					t.Fatal("oversized request consumed slot")
				}
			})
		}
	}
}

func (callbackTestPrivacy) Seal(b []byte) ([]byte, error) {
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, b, nil), nil
}
func (callbackTestPrivacy) Unseal(b []byte) ([]byte, error) {
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	if len(b) < gcm.NonceSize() {
		return nil, errors.New("truncated test ciphertext")
	}
	return gcm.Open(nil, b[:gcm.NonceSize()], b[gcm.NonceSize():], nil)
}
