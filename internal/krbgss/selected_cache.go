package gssapi

import (
	"errors"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	client "nfsclient/internal/krbclient"
)

// All explicit cache backends share the same principal and TGT lifetime gates.
// Only FILE caches opt into this client's in-memory TGT renewal; OS caches are
// selected again on context replacement and remain managed by their owner.
func (ctx *Initiator) newSelectedCacheClient(cache *credentials.CCache, cfg *config.Config, settings []func(*client.Settings)) (*client.Client, error) {
	if cache == nil || cache.DefaultPrincipal.Realm != ctx.domain || cache.DefaultPrincipal.PrincipalName.PrincipalNameString() != ctx.username {
		return nil, errors.New("ccache principal does not match --principal")
	}
	if ctx.fileRenewal != nil && fileCacheSelected(ctx.ccache) {
		defer clearNativeCache(cache)
		var err error
		cache, err = ctx.fileRenewal.load(ctx.networkContext, ctx.ccache, ctx.username+"@"+ctx.domain, cache, cfg, settings)
		if err != nil {
			return nil, err
		}
	}
	return client.NewFromCCache(cache, cfg, settings...)
}
