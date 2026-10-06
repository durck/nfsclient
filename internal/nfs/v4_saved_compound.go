package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
)

// SavedCompound is the exact NFS payload of a cachethis=true session request.
// RPC/GSS credentials and cryptographic tokens are deliberately excluded.
// An enclosing durable journal must bind it to the protected connection profile,
// original client/server identity and lease. Inner may contain file data: the
// journal must be private, bounded and synchronized before transmission.
type SavedCompound struct {
	Minor, Sequence uint32
	Session         []byte
	Auth            Auth
	Inner           []byte
	Digest          [32]byte
	Operations      []SavedCompoundOperation
}

type savedCompoundExactKey struct{}

// The caller must first authenticate and BIND the original session. It supplies
// operation-specific result decoders; absent cached replies and malformed
// results never count as recovered state. Normal slot quarantine still applies.
func (v *v4Client) replaySavedCompound(ctx context.Context, saved SavedCompound, ops ...v4Op) error {
	if err := saved.Validate(); err != nil {
		return err
	}
	if v.stateLost.Load() || v.leaseMoved.Load() || v.reclaimForbidden.Load() {
		return errors.New("saved compound cannot bypass uncertain or revoked session state")
	}
	if v.minor != saved.Minor || v.sequence != saved.Sequence || !bytes.Equal(v.session, saved.Session) || v.c.Auth.UID != saved.Auth.UID || v.c.Auth.GID != saved.Auth.GID || !slices.Equal(v.c.Auth.Groups, saved.Auth.Groups) || len(ops) != len(saved.Operations) {
		return errors.New("saved compound does not belong to the bound original session and credentials")
	}
	for i, op := range ops {
		if op.code != saved.Operations[i].Code || !bytes.Equal(op.args, saved.Operations[i].Args) {
			return errors.New("saved compound replay changed an operation")
		}
	}
	ctx = context.WithValue(ctx, savedCompoundExactKey{}, bytes.Clone(saved.Inner))
	return v.compoundAuth(ctx, saved.Auth, ops...)
}

type SavedCompoundOperation struct {
	Code uint32
	Args []byte
}

func saveCompound(v *v4Client, auth Auth, inner encoder, ops []v4Op) SavedCompound {
	s := SavedCompound{Minor: v.minor, Sequence: v.sequence, Session: bytes.Clone(v.session), Auth: auth, Inner: bytes.Clone(inner), Digest: sha256.Sum256(inner)}
	s.Auth.Groups = append([]uint32(nil), auth.Groups...)
	for _, op := range ops[1:] {
		s.Operations = append(s.Operations, SavedCompoundOperation{op.code, bytes.Clone(op.args)})
	}
	return s
}

// Validate proves that redundant journal fields describe exactly the recorded
// request, including its session/slot/sequence and mandatory cachethis=true.
// It does not authorize an endpoint or prove that a server retained this slot.
func (s SavedCompound) Validate() error {
	if (s.Minor != 1 && s.Minor != 2) || len(s.Session) != 16 || len(s.Inner) > 1<<20 || len(s.Inner) < 48 || len(s.Operations) > 1024 || sha256.Sum256(s.Inner) != s.Digest {
		return errors.New("invalid saved NFSv4 compound identity or digest")
	}
	var e encoder
	e.str("")
	e.u32(s.Minor)
	e.u32(uint32(len(s.Operations) + 1))
	e.u32(53)
	e = append(e, s.Session...)
	e.u32(s.Sequence)
	e.u32(0)
	e.u32(0)
	e.u32(1)
	for _, op := range s.Operations {
		if op.Code == 53 || len(op.Args) > 1<<20 || len(e) > 1<<20-len(op.Args)-4 {
			return errors.New("invalid saved NFSv4 operation")
		}
		e.u32(op.Code)
		e = append(e, op.Args...)
	}
	if !bytes.Equal(e, s.Inner) {
		return errors.New("saved NFSv4 compound fields differ from exact request")
	}
	return nil
}
