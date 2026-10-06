package nfs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
)

// Install once per DS session. Different stripe workers own distinct clients;
// the session mutex serializes this callback and its single recovery attempt.
func (c *Client) enablePNFSWriteRecovery(ds *Client, paths []string, endpoint string, policies map[string]*tls.Config, authConfigs map[string]Config, usable func() error) error {
	if ds.v4 == nil || ds.v4.serverIdentity == nil {
		return errors.New("write failover requires a confirmed NFSv4 DS session")
	}
	if ds.v4.recoverCached != nil {
		return nil
	}
	original, ok := authConfigs[endpoint]
	if !ok || original.Kerberos.SPN == "" || original.Security != "krb5i" && original.Security != "krb5p" {
		return errors.New("write failover requires a protected explicit DS identity")
	}
	approved := slices.Clone(paths)
	credentials := make(map[string]Config, len(approved))
	transport := make(map[string]*tls.Config, len(approved))
	for _, path := range approved {
		candidate, ok := authConfigs[path]
		if !ok || candidate.Security != original.Security || candidate.Kerberos.Principal != original.Kerberos.Principal || candidate.Kerberos.SPN != original.Kerberos.SPN {
			return errors.New("write failover paths require the original principal, service and SPN")
		}
		credentials[path] = candidate
		if policy := policies[path]; policy != nil {
			transport[path] = policy.Clone()
		}
	}
	used := false
	ds.v4.recoverCached = func(ctx context.Context, ticket *v4ReplayRequest) (*rpcClient, func(bool), error) {
		if used {
			return nil, nil, errors.New("pNFS write failover already used for this DS session")
		}
		used = true
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return nil, nil, err
		}
		var failures []error
		for _, target := range approved {
			if target == endpoint {
				continue
			}
			host, port, err := net.SplitHostPort(target)
			if err != nil {
				return nil, nil, err
			}
			p, err := strconv.Atoi(port)
			if err != nil {
				return nil, nil, err
			}
			rpc, err := dialRPC(ctx, host, p, c.config.Timeout, c.config.ReservedPort)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			next := &Client{nfs: rpc, Auth: ticket.Auth, version: ds.version, ReadSize: ds.ReadSize, WriteSize: ds.WriteSize}
			fail := func(err error) (*rpcClient, func(bool), error) { next.Close(); return nil, nil, err }
			if policy := transport[target]; policy != nil {
				if err := rpc.startTLS(ctx, nfsProgram, 4, policy); err != nil {
					return fail(err)
				}
			}
			if err := next.authenticateKerberos(ctx, credentials[target]); err != nil {
				return fail(err)
			}
			owner := ticket.Owner
			// owner.mu is held by compoundContext: sessionSequences would
			// relock it. The established session already owns this ledger.
			next.v4 = &v4Client{c: next, minor: owner.minor, exchangeRole: 0x40000, clientNonce: slices.Clone(owner.clientNonce), creates: owner.creates, replayFrom: ticket}
			if err := next.v4.initializeSession(ctx, owner.serverIdentity, nil); err != nil {
				return fail(err)
			}
			if err := errors.Join(ctx.Err(), usable()); err != nil {
				return fail(err)
			}
			return rpc, func(confirmed bool) {
				if !confirmed {
					next.Close()
					return
				}
				// Old RPC is already closed by transport-loss handling. Replace
				// only the connection and credential lifecycle, retaining session,
				// slot, limits, verifier identity and every caller's *Client.
				if ds.closeKerberos != nil {
					ds.closeKerberos()
				}
				ds.nfs, ds.closeKerberos = rpc, next.closeKerberos
				ds.cancelKerberos.Store(next.cancelKerberos.Swap(nil))
				next.closeKerberos = nil
			}, nil
		}
		return nil, nil, fmt.Errorf("no approved alternate pNFS write path: %w", errors.Join(failures...))
	}
	return nil
}
