package nfs

import "context"

// ServerImplementation is an unauthenticated implementation claim, not a
// verified vendor fingerprint or a basis for authentication/routing decisions.
type ServerImplementation struct {
	Domain      string `json:"domain"`
	Name        string `json:"name"`
	DateSeconds int64  `json:"date_seconds"`
	DateNanos   uint32 `json:"date_nanos"`
}

type ConnectionInfo struct {
	Hostname             string                 `json:"hostname"`
	Peer                 string                 `json:"peer"`
	IP                   string                 `json:"ip"`
	Version              string                 `json:"version"`
	Transport            string                 `json:"transport"`
	Security             string                 `json:"security"`
	Principal            string                 `json:"principal,omitempty"`
	UID                  uint32                 `json:"uid"`
	GID                  uint32                 `json:"gid"`
	Groups               []uint32               `json:"groups"`
	TLS                  bool                   `json:"tls"`
	TLSVerified          bool                   `json:"tls_verified"`
	TLSInsecureRequested bool                   `json:"tls_insecure_requested"`
	ImplementationClaims []ServerImplementation `json:"server_implementation_claims,omitempty"`
}

func (c *Client) ConnectionInfo(ctx context.Context) ConnectionInfo {
	name, ip := c.ServerInfo(ctx)
	r := ConnectionInfo{Hostname: name, IP: ip, Version: c.Version(), Security: c.Security(), Principal: c.principal, UID: c.Auth.UID, GID: c.Auth.GID, TLS: c.TLSActive(), TLSVerified: c.TLSCertificateVerified()}
	r.Groups = append([]uint32{}, c.Auth.Groups...)
	if c.config != nil {
		r.TLSInsecureRequested = c.config.TLS.InsecureSkipVerify
	}
	if c.nfs != nil && c.nfs.conn != nil {
		r.Peer = c.nfs.conn.RemoteAddr().String()
		r.Transport = "tcp"
		if c.nfs.udp {
			r.Transport = "udp"
		}
		if c.nfs.iwarp != nil {
			r.Transport = "rdma"
		}
	}
	if c.v4 != nil {
		c.v4.mu.Lock()
		r.ImplementationClaims = append([]ServerImplementation(nil), c.v4.implementationClaims...)
		c.v4.mu.Unlock()
	}
	return r
}
