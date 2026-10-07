package nfs

import (
	"context"
	"errors"
	"time"

	"nfsclient/internal/sspi"
)

type kerberosInitiator interface {
	micContext
	Initiate(string, int, []byte) ([]byte, bool, error)
	Established() bool
	Expiry() time.Time
	CanSeal() error
	Close() error
}

func validateSSPIProfile(cfg *Config) error {
	k := cfg.Kerberos
	if !sspi.Available() {
		return sspi.ErrUnsupported
	}
	if cfg.Security != "krb5" && cfg.Security != "krb5i" && cfg.Security != "krb5p" {
		return errors.New("SSPI requires explicit krb5, krb5i or krb5p security")
	}
	if err := sspi.ValidateNames(k.Principal, k.SPN); err != nil {
		return err
	}
	if k.ConfigFile != "" || k.Keytab != "" || k.CCache != "" || k.Password != "" || k.KCMSocket != "" || k.ASAlias != "" || k.EnterpriseUPN != "" || k.ASStartRealm != "" || len(k.ASReferralRealms) != 0 || k.ASHelper != "" || k.FASTArmor != "" || k.RequireFAST || k.PKINIT.Selected() {
		return errors.New("SSPI selects only the current Windows logon; explicit Kerberos files, caches and AS options cannot be mixed")
	}
	if cfg.TLS.Enabled || cfg.PNFS || cfg.Offload || k.RPCVersion != 0 && k.RPCVersion != 1 {
		return errors.New("SSPI TLS channel binding, callbacks and RPCSEC_GSS v3 are not supported; profile refused before network")
	}
	if cfg.Transport != "" && cfg.Transport != "tcp" && cfg.Transport != "udp" {
		return errors.New("SSPI requires TCP or NFSv2/v3 UDP")
	}
	switch cfg.Version {
	case "":
		cfg.Version = "3"
	case "auto", "2", "3", "4", "4.0", "4.1", "4.2":
	default:
		return errors.New("SSPI requires a supported NFS version")
	}
	return nil
}

func newSSPIInitiator(ctx context.Context, k KerberosConfig) (kerberosInitiator, error) {
	return sspi.New(ctx, k.Principal, k.SPN)
}
