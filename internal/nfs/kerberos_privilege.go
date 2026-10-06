package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Two child DESTROYs, grant cancellation and two OPEN closes each have a
// three-second cleanup deadline. Reserve another deadline for scheduling.
const copyGSSCleanupBudget = 18 * time.Second

// A copy pins the parent before opening files or creating privileges. Lease
// traffic keeps using that parent; each child is selected for exactly one RPC.
func (c *rpcClient) pinCopyParent(ctx context.Context) (*rpcGSS, func(), error) {
	if c == nil {
		return nil, nil, errors.New("secure COPY requires an authenticated parent connection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.gss
	deadline, bounded := ctx.Deadline()
	if c.closed || c.backchannelRenewing || g == nil || g.context == nil || g.parent != nil || g.protocolVersion() != 3 || g.service != 3 || !g.established || g.seq >= 0x7ffffffe || !bounded || g.renewAt.IsZero() || g.expiry.IsZero() || !deadline.Add(copyGSSCleanupBudget).Before(g.renewAt) || !deadline.Add(copyGSSCleanupBudget).Before(g.expiry) {
		return nil, nil, errors.New("secure COPY requires a live RPCSEC_GSS v3 privacy parent lasting through the wait and cleanup")
	}
	if _, ok := g.context.(*sharedGSSContext); !ok {
		g.context = &sharedGSSContext{context: g.context}
	}
	if c.copyParentPins == 0 {
		c.copyOriginalPin = c.pinnedBackchannelGSS
	}
	c.pinnedBackchannelGSS = true
	c.copyParentPins++
	var once sync.Once
	return g, func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.copyParentPins--
			if c.copyParentPins == 0 {
				c.pinnedBackchannelGSS = c.copyOriginalPin
			}
		})
	}, nil
}

func (c *rpcClient) callGSSChild(ctx context.Context, child *rpcGSS, prog, vers, proc uint32, auth *Auth, args encoder) (*decoder, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrConnectionLost
	}
	if child == nil || child.parent != c.gss || !c.pinnedBackchannelGSS || child.protocolVersion() != 3 || !child.established {
		return nil, errors.New("COPY privilege no longer belongs to the pinned parent")
	}
	parent := c.gss
	c.gss = child
	defer func() { c.gss = parent }()
	return c.callLocked(ctx, prog, vers, proc, auth, args, 0)
}

func (c *rpcClient) destroyGSSChildLocked(ctx context.Context, child *rpcGSS) error {
	if c.closed {
		return errors.New("COPY privilege revocation unconfirmed; parent transport is closed")
	}
	if child == nil || child.parent != c.gss || !child.established {
		return errors.New("COPY privilege parent changed")
	}
	parent := c.gss
	c.gss = child
	defer func() { c.gss = parent; child.established = false }()
	d, err := c.callLocked(ctx, nfsProgram, child.nfsVersion, 0, nil, nil, 3)
	if err == nil && (d.err != nil || len(d.b) != 0) {
		err = errors.New("invalid COPY privilege destruction result")
	}
	if err != nil {
		c.closeLocked()
	}
	return err
}

func (c *rpcClient) destroyGSSChild(child *rpcGSS) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.destroyGSSChildLocked(ctx, child); err != nil {
		return fmt.Errorf("COPY privilege revocation unconfirmed; no replay: %w", err)
	}
	return nil
}

// RFC 7861 CREATE is protected by the parent and returns no child window.
// This client serializes a single outstanding child request and requires the
// exact requested privilege; server-side assertion mapping is not accepted.
func (c *rpcClient) createCopyPrivilege(ctx context.Context, parent *rpcGSS, name string, privilege []byte) (*rpcGSS, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || parent == nil || c.gss != parent || parent.parent != nil || parent.protocolVersion() != 3 || parent.service != 3 || !c.pinnedBackchannelGSS {
		return nil, errors.New("COPY privilege needs the original pinned v3 privacy parent")
	}
	if name != "copy_from_auth" && name != "copy_to_auth" || len(privilege) == 0 || len(privilege) > 32768 {
		return nil, errors.New("invalid COPY privilege request")
	}
	var args encoder
	args.u32(0) // No multi-principal assertion.
	args.u32(0) // TLS bindings remain in the underlying GSS mechanism.
	args.u32(1)
	args.u32(1) // PRIVS
	args.str(name)
	args.opaque(privilege)
	defer clear(args)
	d, err := c.callLocked(ctx, nfsProgram, parent.nfsVersion, 0, nil, args, 5)
	if err != nil {
		return nil, fmt.Errorf("COPY privilege creation unconfirmed; parent revocation may remain unverified; no replay: %w", err)
	}
	handle := bytes.Clone(d.opaque(380))
	child := &rpcGSS{context: parent.context, handle: handle, window: 1, service: 3, established: true, expiry: parent.expiry, renewAt: parent.renewAt, nfsVersion: parent.nfsVersion, rpcVersion: 3, parent: parent}
	validHandle := len(handle) != 0 && !bytes.Equal(handle, parent.handle)
	valid := validHandle && d.u32() == 0 && d.u32() == 0 && d.u32() == 1 && d.u32() == 1 && d.str() == name && bytes.Equal(d.opaque(32768), privilege) && d.err == nil && len(d.b) == 0
	if !valid {
		var cleanupErr error
		if validHandle {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			cleanupErr = c.destroyGSSChildLocked(cleanupCtx, child)
			cancel()
		} else {
			c.closeLocked()
			cleanupErr = errors.New("COPY privilege handle unconfirmed; parent transport closed; revocation unverified")
		}
		return nil, errors.Join(errors.New("server did not grant the exact requested COPY privilege"), cleanupErr)
	}
	return child, nil
}
