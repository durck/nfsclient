package nfs

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
)

// StatefulFailoverStatus distinguishes an unused approval from its consumed
// attempt. A failed attempt never authorizes another endpoint or a new owner.
type StatefulFailoverStatus struct {
	Target          ReadReplica
	Armed, Consumed bool
}

func (c *Client) StatefulFailoverStatus() StatefulFailoverStatus {
	if c.v4 == nil {
		return StatefulFailoverStatus{}
	}
	c.v4.mu.Lock()
	defer c.v4.mu.Unlock()
	if c.v4.statefulFailover == nil {
		return StatefulFailoverStatus{}
	}
	return *c.v4.statefulFailover
}

// EnableStatefulFailover approves one automatic transport transition. It never
// allocates a replacement session or owner: the original cached request must
// be resolved on the same server incarnation before any new slot is consumed.
func (c *Client) EnableStatefulFailover(target ReadReplica) error {
	if err := c.ValidateReadReplica(target); err != nil {
		return err
	}
	v := c.v4
	if v == nil || v.minor == 0 {
		return errors.New("automatic stateful failover requires NFSv4.1/4.2")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.journal != nil || v.beforeCached != nil || v.afterCached != nil {
		return errors.New("automatic endpoint changes cannot share an endpoint-bound durable journal")
	}
	if v.stateLost.Load() || v.leaseMoved.Load() || v.reclaimForbidden.Load() || v.sharedSession != nil || v.trunked || v.serverIdentity == nil || len(v.session) != 16 || v.statefulFailover != nil && v.statefulFailover.Armed {
		return errors.New("stateful failover requires a healthy confirmed unarmed session")
	}
	if c.Security() != "sys" && target.SPN != c.config.Kerberos.SPN {
		return errors.New("stateful failover must retain the original Kerberos SPN")
	}
	if _, err := v.saveSession(); err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(target.Address)
	n, _ := strconv.Atoi(port)
	oldPort := c.config.NFSPort
	if oldPort == 0 {
		oldPort = 2049
	}
	if host == c.config.Host && n == oldPort {
		return errors.New("stateful failover requires a distinct approved endpoint")
	}
	cfg := *c.config
	cfg.Host, cfg.NFSPort = host, n
	cfg.Auth = c.Auth
	cfg.Auth.Groups = slices.Clone(c.Auth.Groups)
	cfg.Version, cfg.Security = c.Version(), c.Security()
	cfg.Kerberos.SPN, cfg.TLS.ServerName = target.SPN, target.TLSName
	state := &StatefulFailoverStatus{Target: target, Armed: true}
	v.statefulFailover = state
	v.requireCached, v.recoverStateful = true, true
	v.recoverCached = func(ctx context.Context, ticket *v4ReplayRequest) (*rpcClient, func(bool), error) {
		if !state.Armed || state.Consumed {
			return nil, nil, errors.New("stateful failover approval was already consumed")
		}
		state.Armed, state.Consumed = false, true
		if ticket.Auth.UID != cfg.Auth.UID || ticket.Auth.GID != cfg.Auth.GID || !slices.Equal(ticket.Auth.Groups, cfg.Auth.Groups) {
			return nil, nil, errors.New("stateful failover credentials changed after approval")
		}
		saved, err := v.saveSession()
		if err != nil {
			return nil, nil, err
		}
		next, err := connectSavedSession(ctx, cfg, saved)
		if err != nil {
			return nil, nil, err
		}
		return next.nfs, func(confirmed bool) {
			if !confirmed {
				next.Close()
				return
			}
			if c.closeKerberos != nil {
				c.closeKerberos()
			}
			c.nfs, c.closeKerberos, c.config = next.nfs, next.closeKerberos, &cfg
			c.cancelKerberos.Store(next.cancelKerberos.Swap(nil))
			next.closeKerberos = nil
			// Consumed approvals do not silently remain an automatic retry policy.
			v.recoverCached = nil
			v.requireCached, v.recoverStateful = false, false
		}, nil
	}
	return nil
}
