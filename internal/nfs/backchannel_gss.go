package nfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// The fore/back RPC streams have independent RPC sequence windows but share
// one GSS context, whose cryptographic token counters must be serialized.
type sharedGSSContext struct {
	mu      sync.Mutex
	context micContext
}

func (s *sharedGSSContext) MakeSignature(b []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.context.MakeSignature(b)
}
func (s *sharedGSSContext) VerifySignature(b, m []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.context.VerifySignature(b, m)
}
func (s *sharedGSSContext) Seal(b []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.context.(interface{ Seal([]byte) ([]byte, error) })
	if !ok {
		return nil, errors.New("GSS privacy unavailable")
	}
	return v.Seal(b)
}
func (s *sharedGSSContext) Unseal(b []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.context.(interface{ Unseal([]byte) ([]byte, error) })
	if !ok {
		return nil, errors.New("GSS privacy unavailable")
	}
	return v.Unseal(b)
}

type gssBackchannel struct {
	mu                       sync.Mutex
	context                  micContext
	handle, foreHandle       []byte
	service, window, highest uint32
	rpcVersion               uint32
	seen                     map[uint32]bool
	expiry                   time.Time
}

func newGSSBackchannel(fore *rpcGSS) (*gssBackchannel, error) {
	if fore == nil || fore.context == nil || !fore.established || len(fore.handle) == 0 || len(fore.handle) > 380 || fore.window == 0 || fore.window > 4096 {
		return nil, errors.New("unsupported backchannel GSS context/window")
	}
	if err := fore.checkExpiry(time.Now()); err != nil {
		return nil, err
	}
	shared, ok := fore.context.(*sharedGSSContext)
	if !ok {
		shared = &sharedGSSContext{context: fore.context}
		fore.context = shared
	}
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return nil, err
	}
	// Even a krb5 (authentication-only) fore channel requires integrity on
	// callback bodies, which carry layout recalls and state transitions.
	service := max(uint32(2), fore.service)
	if service > 3 {
		return nil, errors.New("invalid GSS backchannel service")
	}
	return &gssBackchannel{context: shared, handle: handle, foreHandle: append([]byte(nil), fore.handle...), service: service, window: fore.window, seen: map[uint32]bool{}, expiry: fore.expiry, rpcVersion: fore.protocolVersion()}, nil
}

func (g *gssBackchannel) callback(raw []byte, r *layoutRecall) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.expiry.IsZero() && !time.Now().Before(g.expiry) {
		return nil, errors.New("backchannel GSS context expired")
	}
	r.mu.Lock()
	responseLimit := r.responseLimit
	r.mu.Unlock()
	if responseLimit == 0 {
		responseLimit = pnfsCallbackSize
	}
	if len(raw) > pnfsCallbackSize {
		return nil, errors.New("protected callback exceeds request limit")
	}
	d := &decoder{b: raw}
	d.take(24)
	if d.u32() != 6 {
		return nil, errors.New("backchannel requires RPCSEC_GSS")
	}
	credential := d.opaque(400)
	signedSize := len(raw) - len(d.b)
	a := &decoder{b: credential}
	version, procedure, sequence, service := a.u32(), a.u32(), a.u32(), a.u32()
	handle := a.opaque(380)
	wantVersion := uint32(1)
	if g.rpcVersion == 3 {
		wantVersion = 3
	}
	if a.err != nil || len(a.b) != 0 || version != wantVersion || procedure != 0 || sequence == 0 || sequence >= 0x80000000 || service != g.service || !bytes.Equal(handle, g.handle) {
		return nil, errors.New("invalid backchannel GSS credential")
	}
	flavor := d.u32()
	mic := d.opaque(400)
	if d.err != nil || flavor != 6 || g.context.VerifySignature(raw[:signedSize], mic) != nil {
		return nil, errors.New("backchannel GSS header authentication failed")
	}
	protected := rpcGSS{context: g.context, seq: sequence, service: service, established: true, expiry: g.expiry}
	if err := protected.unprotect(d); err != nil {
		return nil, errors.New("backchannel GSS body authentication failed")
	}
	if g.seen[sequence] || sequence <= g.highest && g.highest-sequence >= g.window {
		return nil, errors.New("backchannel GSS replay or stale sequence")
	}
	// Authenticate before feeding the existing atomic callback decoder. The
	// normalized header is internal only; no AUTH_NONE reply goes on the wire.
	plain := append(encoder(nil), raw[:24]...)
	for range 4 {
		plain.u32(0)
	}
	plain = append(plain, d.b...)
	reply, err := r.callbackFramed(plain, 1024, len(raw))
	if err != nil {
		return nil, err
	}
	if len(reply) < 24 {
		return nil, errors.New("invalid internal callback reply")
	}
	signedReply := binary.BigEndian.AppendUint32(nil, sequence)
	if wantVersion == 3 {
		signedReply = bytes.Clone(raw[:signedSize])
		binary.BigEndian.PutUint32(signedReply[4:8], 1)
	}
	sequenceMIC, err := g.context.MakeSignature(signedReply)
	if err != nil || len(sequenceMIC) > 400 {
		return nil, errors.New("backchannel GSS reply signature failed")
	}
	body, err := protected.protect(reply[24:])
	if err != nil {
		return nil, errors.New("backchannel GSS reply protection failed")
	}
	out := append(encoder(nil), reply[:12]...)
	out.u32(6)
	out.opaque(sequenceMIC)
	out.u32(0)
	out = append(out, body...)
	if len(out) > int(responseLimit) {
		return nil, errors.New("protected callback exceeds reply limit")
	}
	g.highest = max(g.highest, sequence)
	g.seen[sequence] = true
	for old := range g.seen {
		if g.highest-old >= g.window {
			delete(g.seen, old)
		}
	}
	return out, nil
}
