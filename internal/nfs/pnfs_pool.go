package nfs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// One pool owns the approved paths and sessions for one layout transfer.
func (c *Client) pnfsDataServers(ctx context.Context, tlsConfigs map[string]*tls.Config, authConfigs map[string]Config, usable func() error, trunking bool) (func([]string) (*Client, string, error), func(*pnfsRead) error, func()) {
	v := c.v4
	clients := map[string]*Client{}
	failedPaths := map[string]error{}
	closePool := func() {
		for _, ds := range clients {
			ds.Close()
		}
	}
	dataServer := func(paths []string, expected *createSessionKey, shared *v4Client) (*Client, string, error) {
		var failures []error
		for _, endpoint := range paths {
			if err := ctx.Err(); err != nil {
				return nil, "", err
			}
			if err := usable(); err != nil {
				return nil, "", err
			}
			if ds := clients[endpoint]; ds != nil {
				if shared != nil && ds.v4.sessionOwner() != shared {
					return nil, "", errors.New("pNFS path already belongs to another session")
				}
				if expected != nil && (ds.v4.serverIdentity == nil || *ds.v4.serverIdentity != *expected) {
					return nil, "", errors.New("pNFS cached alternate has a different server identity")
				}
				return ds, endpoint, nil
			}
			if err := failedPaths[endpoint]; err != nil {
				failures = append(failures, err)
				continue
			}
			host, port, _ := net.SplitHostPort(endpoint)
			p, _ := strconv.Atoi(port)
			rpc, err := dialRPC(ctx, host, p, c.config.Timeout, c.config.ReservedPort)
			if err != nil {
				// No RPC has been sent. A later approved address may be used.
				failedPaths[endpoint] = err
				failures = append(failures, err)
				continue
			}
			ds := &Client{nfs: rpc, Auth: c.Auth, version: c.Version(), ReadSize: c.ReadSize, WriteSize: c.WriteSize}
			if err := errors.Join(ctx.Err(), usable()); err != nil {
				ds.Close()
				return nil, "", err
			}
			// RFC 8881 13.1: identify the same client incarnation to the DS.
			if policy := tlsConfigs[endpoint]; policy != nil {
				if err := rpc.startTLS(ctx, nfsProgram, 4, policy); err != nil {
					ds.Close()
					return nil, "", fmt.Errorf("pNFS data server %s TLS: %w", endpoint, err)
				}
			}
			if auth, ok := authConfigs[endpoint]; ok {
				if err := ds.authenticateKerberos(ctx, auth); err != nil {
					ds.Close()
					return nil, "", fmt.Errorf("pNFS DS %s Kerberos: %w", endpoint, err)
				}
			}
			ds.v4 = &v4Client{c: ds, minor: v.minor, exchangeRole: 0x40000, clientNonce: append([]byte(nil), v.clientNonce...), creates: v.sessionSequences()}
			if err := ds.v4.initializeSession(ctx, expected, shared); err != nil {
				ds.Close()
				// EXCHANGE_ID/CREATE_SESSION may have reached the peer.
				// Never move to another path after protocol exchange begins.
				return nil, "", err
			}
			clients[endpoint] = ds
			return ds, endpoint, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("all approved pNFS data-server paths failed: %w", errors.Join(failures...))
	}
	usedRecovery := map[createSessionKey]bool{}
	recoverRead := func(r *pnfsRead) error {
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return err
		}
		identity := r.ds.v4.serverIdentity
		original, ok := authConfigs[r.endpoint]
		if identity == nil || !ok || (original.Security != "krb5i" && original.Security != "krb5p") || original.Kerberos.SPN == "" {
			return errors.New("pNFS failed DS has no authenticated server identity")
		}
		if usedRecovery[*identity] {
			return errors.New("pNFS read failover already used for this DS identity")
		}
		usedRecovery[*identity] = true
		delete(clients, r.endpoint)
		failedPaths[r.endpoint] = errors.New("pNFS DS transport failed during READ")
		r.ds.Close()
		var alternates []string
		for _, endpoint := range r.paths {
			if failedPaths[endpoint] != nil {
				continue
			}
			candidate, ok := authConfigs[endpoint]
			if !ok || candidate.Security != original.Security || candidate.Kerberos.SPN != original.Kerberos.SPN || candidate.Kerberos.Principal != original.Kerberos.Principal {
				return errors.New("pNFS alternate requires the original protected Kerberos identity and SPN")
			}
			alternates = append(alternates, endpoint)
		}
		ds, endpoint, err := dataServer(alternates, identity, nil)
		if err != nil {
			return err
		}
		if err := errors.Join(ctx.Err(), usable()); err != nil {
			return err
		}
		r.ds, r.endpoint = ds, endpoint
		return nil
	}
	groups := map[string]uint64{}
	get := func(paths []string) (*Client, string, error) {
		if !trunking {
			return dataServer(paths, nil, nil)
		}
		if len(paths) < 1 || len(paths) > 8 {
			return nil, "", errors.New("pNFS trunk requires 1..8 approved paths")
		}
		original, ok := authConfigs[paths[0]]
		if !ok || original.Kerberos.SPN == "" || original.Security != "krb5i" && original.Security != "krb5p" {
			return nil, "", errors.New("pNFS trunk requires a protected explicit DS identity")
		}
		for _, path := range paths {
			auth, ok := authConfigs[path]
			if !ok || auth.Security != original.Security || auth.Kerberos.SPN != original.Kerberos.SPN || auth.Kerberos.Principal != original.Kerberos.Principal {
				return nil, "", errors.New("pNFS trunk paths require the original user, GSS service and SPN")
			}
		}
		first, _, err := dataServer(paths[:1], nil, nil)
		if err != nil {
			return nil, "", err
		}
		owner := first.v4.sessionOwner()
		for _, path := range paths[1:] {
			if _, _, err := dataServer([]string{path}, owner.serverIdentity, owner); err != nil {
				return nil, "", err
			}
		}
		key := strings.Join(paths, "\x00")
		next := groups[key]
		groups[key] = next + 1
		path := paths[next%uint64(len(paths))]
		return clients[path], path, nil
	}
	return get, recoverRead, closePool
}
