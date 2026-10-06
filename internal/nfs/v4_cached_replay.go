package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
)

// A ticket exists only inside the original serialized compound call, after a
// transport-only failure. The callback may bind a protected approved endpoint;
// it must not issue another SEQUENCE, allocate a replacement session, or edit
// the immutable request. RPC/GSS wrappers are fresh; NFS session bytes are exact.
type v4ReplayRequest struct {
	Owner    *v4Client
	Session  []byte
	Sequence uint32
	Auth     Auth
	Inner    []byte
	Digest   [32]byte
}

func cachedDataCompound(ops []v4Op) bool {
	return len(ops) == 3 && ops[0].code == 53 && ops[1].code == 22 && (ops[2].code == 38 || ops[2].code == 5)
}

func (v *v4Client) replayCached(ctx context.Context, auth Auth, original *rpcClient, args encoder, ops []v4Op, cause error) (*decoder, *rpcClient, func(bool), error) {
	if v.recoverCached == nil || ctx.Err() != nil || !retryablePNFSRead(cause) || (!v.recoverStateful && !cachedDataCompound(ops)) || len(v.session) != 16 || v.stateLost.Load() || v.reclaimForbidden.Load() || v.leaseMoved.Load() {
		return nil, original, nil, cause
	}
	ticket := &v4ReplayRequest{Owner: v, Session: bytes.Clone(v.session), Sequence: v.sequence, Auth: auth, Inner: bytes.Clone(args), Digest: sha256.Sum256(args)}
	ticket.Auth.Groups = append([]uint32(nil), auth.Groups...)
	// EXCHANGE_ID/BIND_CONN_TO_SESSION are sessionless control compounds.
	// The original channel budget applies again to the exact retransmission.
	next, finish, err := v.recoverCached(context.WithValue(ctx, sessionWireBudgetKey{}, nil), ticket)
	if err != nil {
		if finish != nil {
			finish(false)
		}
		return nil, original, nil, errors.Join(cause, err)
	}
	if next == nil || next == original || finish == nil || ticket.Owner != v || ticket.Sequence != v.sequence || !bytes.Equal(ticket.Session, v.session) || ticket.Digest != sha256.Sum256(args) || !bytes.Equal(ticket.Inner, args) {
		if finish != nil {
			finish(false)
		}
		return nil, original, nil, errors.New("invalid cached-session recovery admission")
	}
	d, err := next.call(ctx, nfsProgram, 4, 1, &auth, args)
	return d, next, finish, err
}

func cachedReplayConfirmed(err error, initial, current uint32, lost bool) bool {
	if lost || current != initial+1 {
		return false
	}
	if err == nil {
		return true
	}
	var status Status
	if !errors.As(err, &status) {
		return false
	}
	// These statuses are absence of a usable cached outcome, not a known
	// WRITE/COMMIT refusal. Never make held state usable based on them.
	switch status {
	case 10011, 10022, 10023, 10025, 10026, 10047, 10052, 10053, 10054, 10055, 10063, 10068, 10076, 10078:
		return false
	}
	return true
}
