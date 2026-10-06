package nfs

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
)

// ReadReplica explicitly approves a fresh read connection, not shared server
// state. Address is HOST:PORT; protected identities are selected per endpoint.
type ReadReplica struct {
	Address, SPN, TLSName string
}

func (c *Client) ValidateReadReplica(target ReadReplica) error {
	if c == nil || c.config == nil || !strings.HasPrefix(c.Version(), "4.") || c.config.Transport != "" && c.config.Transport != "tcp" || c.config.PNFS || c.config.Offload {
		return errors.New("read failover requires ordinary NFSv4/TCP without pNFS/offload callbacks")
	}
	host, port, err := net.SplitHostPort(target.Address)
	value, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host == "" || strings.ContainsAny(host, " /\\\t\r\n\x00") || value < 1 || value > 65535 {
		return errors.New("read failover needs an explicit valid HOST:PORT")
	}
	security := c.Security()
	if security != "sys" && security != "krb5i" && security != "krb5p" {
		return errors.New("read failover needs integrity/privacy protection or authenticated TLS")
	}
	if security == "sys" && !c.config.TLS.Enabled || c.config.TLS.InsecureSkipVerify {
		return errors.New("read failover requires authenticated target connections; insecure TLS is refused")
	}
	if security == "sys" && target.SPN != "" || security != "sys" && (!strings.HasPrefix(target.SPN, "nfs/") || len(target.SPN) <= 4 || len(target.SPN) > 1024 || strings.ContainsAny(target.SPN, "@ \t\x00\r\n")) {
		return errors.New("read failover requires an explicit SPN for each Kerberos target, and none for AUTH_SYS")
	}
	if c.config.TLS.Enabled && (target.TLSName == "" || len(target.TLSName) > 1024 || strings.ContainsAny(target.TLSName, " /\\\t\x00\r\n")) || !c.config.TLS.Enabled && target.TLSName != "" {
		return errors.New("read failover requires an explicit certificate name exactly when TLS is enabled")
	}
	return nil
}

// ConnectReadReplica creates entirely fresh state. No owner, session, handle,
// stateid or failed RPC is transferred. The caller validates namespace/content
// before using the returned client and owns its lifetime.
func (c *Client) ConnectReadReplica(ctx context.Context, target ReadReplica) (*Client, error) {
	if err := c.ValidateReadReplica(target); err != nil {
		return nil, err
	}
	if len(c.Locks()) != 0 {
		return nil, ErrLocksHeld
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(target.Address)
	value, _ := strconv.Atoi(port)
	cfg := *c.config
	cfg.Host, cfg.NFSPort = host, value
	cfg.Version, cfg.Security = c.Version(), c.Security()
	cfg.Auth = c.Auth
	cfg.Auth.Groups = append([]uint32(nil), c.Auth.Groups...)
	cfg.Kerberos.SPN, cfg.TLS.ServerName = target.SPN, target.TLSName
	fresh, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if fresh.Identity() != c.Identity() || fresh.Version() != c.Version() || fresh.Transport() != c.Transport() {
		fresh.Close()
		return nil, errors.New("read failover changed identity or negotiated protocol")
	}
	return fresh, nil
}
