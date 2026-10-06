package nfs

import (
	"context"
	"errors"
)

// CREATE_SESSION has a client-ID reply slot independent of session slots.
// Keep it for the lifetime of the incarnation, including temporary DS clients.
// Server minor IDs and network endpoints are deliberately not keys: servers
// with equal scope/major ID/client ID may support client-ID trunking.
type createSessionKey struct {
	nonce, owner, scope string
	clientID            uint64
	minor               uint32
}

type createSessionSequence struct {
	next      uint32
	uncertain bool
}

type createSessionSequences struct {
	gate    chan struct{}
	entries map[createSessionKey]createSessionSequence
}

func (v *v4Client) sessionSequences() *createSessionSequences {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.creates == nil {
		v.creates = &createSessionSequences{
			gate: make(chan struct{}, 1), entries: make(map[createSessionKey]createSessionSequence),
		}
	}
	return v.creates
}

func (s *createSessionSequences) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *createSessionSequences) sequence(key createSessionKey, confirmed bool, offered uint32) (uint32, error) {
	previous, exists := s.entries[key]
	if confirmed {
		// RFC 8881 18.35: a confirmed EXCHANGE_ID sequence is ignored.
		if !exists || previous.uncertain {
			return 0, errors.New("confirmed NFSv4 client CREATE_SESSION sequence is unknown; explicit reconnect with a new incarnation required")
		}
		return previous.next, nil
	}
	// Never evict an old identity: a later confirmed reply would lose its slot.
	if !exists && len(s.entries) >= 256 {
		return 0, errors.New("NFSv4 CREATE_SESSION identity limit reached; reconnect required")
	}
	s.entries[key] = createSessionSequence{next: offered}
	return offered, nil
}
