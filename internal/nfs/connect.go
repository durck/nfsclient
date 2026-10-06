package nfs

import (
	"context"
	"errors"
	"fmt"
	"nfs-viewer/internal/krbconfig"
	"path/filepath"
)

func (c *Client) Version() string {
	if c.version == "" {
		return "3"
	}
	return c.version
}

func (c *Client) Transport() string {
	if c.nfs != nil && c.nfs.iwarp != nil {
		return "iwarp"
	}
	if c.nfs != nil && c.nfs.udp {
		return "udp"
	}
	return "tcp"
}

func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.OffloadSessionRecovery {
		if !cfg.Offload || cfg.OffloadJournal == "" {
			return nil, errors.New("offload session recovery requires offload and a journal")
		}
		if _, err := offloadRecoveryProfile(cfg); err != nil {
			return nil, err
		}
	}
	return connectProfile(ctx, cfg, nil)
}

func connectProfile(ctx context.Context, cfg Config, reclaimFrom *v4Client) (*Client, error) {
	return connectStateProfile(ctx, cfg, reclaimFrom, nil)
}

func connectStateProfile(ctx context.Context, cfg Config, reclaimFrom, migrateFrom *v4Client) (*Client, error) {
	if err := validateNLMConfig(cfg); err != nil {
		return nil, err
	}
	if err := cfg.DNS.Validate(); err != nil {
		return nil, err
	}
	cfg.Kerberos.DNS = cfg.DNS
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	if cfg.Transport != "tcp" && cfg.Transport != "udp" && cfg.Transport != "iwarp" {
		return nil, errors.New("transport must be tcp, udp or iwarp")
	}
	if cfg.PNFS && (cfg.Transport != "tcp" || cfg.Version != "4.1" && cfg.Version != "4.2") {
		return nil, errors.New("pNFS requires explicit NFSv4.1/4.2 and TCP")
	}
	if cfg.Offload && (cfg.Transport != "tcp" || cfg.Version != "4.2") {
		return nil, errors.New("offload requires explicit NFSv4.2 and TCP")
	}
	if cfg.OffloadJournal != "" && (!cfg.Offload || !filepath.IsAbs(cfg.OffloadJournal)) {
		return nil, errors.New("offload journal requires --offload and an absolute file path")
	}
	if cfg.OffloadReconcile && (!cfg.Offload || cfg.OffloadJournal == "") {
		return nil, errors.New("offload reconciliation recording requires offload and an absolute journal")
	}
	if cfg.Transport == "iwarp" {
		if cfg.Version != "4.0" && cfg.Version != "4.1" && cfg.Version != "4.2" {
			return nil, errors.New("software iWARP requires explicit NFSv4.0, v4.1 or v4.2")
		}
		if cfg.Security != "" && cfg.Security != "sys" {
			return nil, errors.New("software iWARP currently supports AUTH_SYS only")
		}
	}
	if cfg.UDPSize != 0 && (cfg.Transport != "udp" || cfg.UDPSize < 512 || cfg.UDPSize > udpTransferMax) {
		return nil, errors.New("udp-size requires UDP and a value from 512 to 4096 bytes")
	}
	if _, err := cfg.tlsConfig(); err != nil {
		return nil, err
	}
	if err := validateSecurity(&cfg); err != nil {
		return nil, err
	}
	if cfg.Transport == "udp" && cfg.Version != "" && cfg.Version != "auto" && cfg.Version != "2" && cfg.Version != "3" {
		return nil, errors.New("UDP supports only NFSv2/v3; use TCP for NFSv4")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if len(cfg.Auth.Groups) > 16 {
		return nil, errors.New("AUTH_SYS supports at most 16 supplementary groups")
	}
	if cfg.Security != "sys" && cfg.Kerberos.Provider != "sspi" {
		if cfg.Kerberos.configSnapshot == nil {
			var err error
			cfg.Kerberos.configSnapshot, err = krbconfig.Load(cfg.Kerberos.ConfigFile)
			if err != nil {
				return nil, err
			}
		} else if err := cfg.Kerberos.configSnapshot.Verify(); err != nil {
			return nil, err
		}
	}
	versions := []string{cfg.Version}
	if cfg.Version == "" {
		versions = []string{"3"}
	}
	if cfg.Version == "auto" {
		versions = []string{"4.2", "4.1", "4.0", "3", "2"}
		if cfg.Transport == "udp" {
			versions = []string{"3", "2"}
		}
	}
	autoVersion := cfg.Version == "auto"
	failures := []error{}
	for _, version := range versions {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var c *Client
		var err error
		canNegotiate := true
		switch version {
		case "2", "3":
			cfg.Version = version
			c, err = connectLegacy(ctx, cfg)
		case "4", "4.0", "4.1", "4.2":
			minor := uint32(0)
			if version == "4.1" {
				minor = 1
			}
			if version == "4.2" {
				minor = 2
			}
			port := cfg.NFSPort
			if port == 0 {
				port = 2049
				if cfg.Transport == "iwarp" {
					port = 20049
				}
			}
			c = &Client{Auth: cfg.Auth, version: fmt.Sprintf("4.%d", minor), ReadSize: 32768, WriteSize: 32768}
			c.nfs, err = dialConfiguredRPC(ctx, cfg, port, nfsProgram, 4)
			if err == nil {
				err = c.authenticateKerberos(ctx, cfg)
				if err == nil {
					c.v4 = &v4Client{c: c, minor: minor, parents: make(map[string]v4Name)}
					if autoVersion {
						// An empty COMPOUND probes the minor version without
						// allocating client/session state or replaying mutations.
						err = c.v4.compound(ctx)
						if err != nil {
							c.Close()
							break
						}
					}
					canNegotiate = false
					if cfg.PNFS {
						c.v4.exchangeRole = 0x20000
					}
					if cfg.PNFS || cfg.Offload {
						c.v4.recall = &layoutRecall{offloadEnabled: cfg.Offload}
						callback := c.v4.recall.callback
						if c.nfs.gss != nil {
							c.v4.recall.gss, err = newGSSBackchannel(c.nfs.gss)
							if err != nil {
								c.Close()
								return nil, err
							}
							c.nfs.pinnedBackchannelGSS = true
							c.nfs.backchannel = newGSSBackchannelSet(c.v4.recall.gss, c.v4.recall)
							callback = c.nfs.backchannel.callback
						}
						c.nfs.duplex = startDuplex(c.nfs, callback)
					}
					if reclaimFrom != nil {
						c.v4.clientNonce = append([]byte(nil), reclaimFrom.clientNonce...)
						c.v4.creates = reclaimFrom.sessionSequences()
						c.v4.reclaiming = true
					}
					if migrateFrom != nil {
						c.v4.clientNonce = append([]byte(nil), migrateFrom.clientNonce...)
						c.v4.creates = migrateFrom.sessionSequences()
						c.v4.migrationFrom = migrateFrom
						c.v4.migrationBorrowed = true
					}
					if c.nfs.iwarp != nil {
						c.ReadSize, c.WriteSize = iwarpRPCSize-1024, iwarpRPCSize-1024
						c.v4.maxReplyPayload, c.v4.maxRequestPayload = iwarpRPCSize-1024, iwarpRPCSize-1024
					}
					err = c.v4.initialize(ctx)
				}
				if err == nil && reclaimFrom == nil && migrateFrom == nil {
					canNegotiate = false
					err = c.v4.keepAlive(ctx)
				}
				if err != nil {
					c.Close()
				}
			}
		default:
			return nil, fmt.Errorf("invalid NFS version %q; choose auto, 2, 3, 4.0, 4.1, or 4.2", version)
		}
		if err == nil {
			// Reconnection pins the negotiated profile; never redo auto downgrade.
			saved := cfg
			saved.Version, saved.Security = c.Version(), c.Security()
			saved.Auth.Groups = append([]uint32(nil), cfg.Auth.Groups...)
			if c.nfs != nil && c.nfs.kerberos != nil {
				saved.Kerberos = c.nfs.kerberos.config
			}
			c.config = &saved
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		failures = append(failures, fmt.Errorf("v%s: %w", version, err))
		if !canNegotiate || (!errors.Is(err, RPCStatus(2)) && !errors.Is(err, Status(10021))) {
			break
		} // Only an explicit program/minor-version mismatch permits downgrade.
	}
	return nil, fmt.Errorf("NFS connection failed: %w", errors.Join(failures...))
}

// Reconnect creates fresh transport, GSS and NFSv4 state. It never replays a
// previous RPC or reuses file handles/state IDs. The caller owns both clients.
func (c *Client) Reconnect(ctx context.Context) (*Client, error) {
	if len(c.Locks()) != 0 {
		return nil, ErrLocksHeld
	}
	if c.config == nil {
		return nil, errors.New("connection configuration is unavailable")
	}
	cfg := *c.config
	cfg.Auth = c.Auth
	cfg.Auth.Groups = append([]uint32(nil), c.Auth.Groups...)
	fresh, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if fresh.Identity() != c.Identity() || fresh.Version() != c.Version() || fresh.Transport() != c.Transport() {
		fresh.Close()
		return nil, errors.New("reconnection changed identity or protocol")
	}
	return fresh, nil
}

func (c *Client) nfsVersion() uint32 {
	switch c.Version() {
	case "4", "4.0", "4.1", "4.2":
		return 4
	}
	if c.Version() == "2" {
		return 2
	}
	return 3
}
func (c *Client) mountVersion() uint32 {
	if c.Version() == "2" {
		return 1
	}
	return 3
}
