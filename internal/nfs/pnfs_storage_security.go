package nfs

import (
	"errors"
	"nfs-viewer/internal/iscsi"
)

func validateStorageSecurity(policies map[string]iscsi.Security, targets []string) (map[string]iscsi.Security, error) {
	if len(policies) > len(targets) {
		return nil, errors.New("storage security policy requires an approved target")
	}
	if len(policies) == 0 {
		return nil, nil
	}
	approved := map[string]bool{}
	for _, target := range targets {
		approved[target] = true
	}
	out := make(map[string]iscsi.Security, len(policies))
	for target, policy := range policies {
		if !approved[target] {
			return nil, errors.New("storage security policy does not match an approved canonical target URL")
		}
		if err := policy.Validate(); err != nil {
			return nil, err
		}
		out[target] = policy
	}
	return out, nil
}
