package gssapi

import (
	"bytes"
	stdcontext "context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/types"
	client "nfs-viewer/internal/krbclient"
)

// FileCacheRenewal owns renewable credentials for one live NFS connection.
// Renewal stays in memory: the selected cache remains an externally owned input.
// Closing the connection cancels and joins all KDC work. GSS replacements share
// this owner, so replacing an RPC context cannot discard a renewed TGT.
type FileCacheRenewal struct {
	mu              sync.Mutex
	ctx             stdcontext.Context
	cancel          stdcontext.CancelFunc
	done            chan struct{}
	wake            chan struct{}
	cache           *credentials.CCache
	source          [32]byte
	path, principal string
	cfg             *config.Config
	settings        []func(*client.Settings)
	retry           bool
	failure         error
}

func NewFileCacheRenewal() *FileCacheRenewal {
	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	m := &FileCacheRenewal{ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	go m.run()
	return m
}

// Cancel interrupts owner KDC work without waiting or destroying credentials.
// Connection shutdown calls this before waiting for a foreground RPC to finish.
func (m *FileCacheRenewal) Cancel() {
	if m != nil {
		m.cancel()
	}
}

func (m *FileCacheRenewal) Close() {
	if m == nil {
		return
	}
	m.Cancel()
	<-m.done
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cache != nil {
		clearNativeCache(m.cache)
		m.cache = nil
	}
}

func WithFileCacheRenewal(m *FileCacheRenewal) Option[Initiator] {
	return func(c *Initiator) error { c.fileRenewal = m; return nil }
}

func fileCacheSelected(name string) bool {
	return name != "" && !strings.HasPrefix(name, "KCM:") && !strings.HasPrefix(name, "KEYRING:") && !strings.HasPrefix(name, "MSLSA:") && !strings.HasPrefix(name, "DIR:") && !strings.HasPrefix(name, "API:")
}

// JSON is used only as an in-memory deep copy/fingerprint of parsed credentials;
// no secret serialization is logged or written to disk.
func copyRenewalCache(c *credentials.CCache) (*credentials.CCache, [32]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, [32]byte{}, errors.New("cannot copy credential cache")
	}
	defer clear(b)
	var next credentials.CCache
	if err := json.Unmarshal(b, &next); err != nil {
		return nil, [32]byte{}, errors.New("cannot copy credential cache")
	}
	// gokrb5 deliberately omits KeyValue from JSON. Copy and fingerprint it
	// explicitly; a metadata-only copy is not a usable authentication cache.
	h := sha256.New()
	h.Write(b)
	for i, e := range c.Credentials {
		next.Credentials[i].Key.KeyValue = bytes.Clone(e.Key.KeyValue)
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(e.Key.KeyValue))))
		h.Write(e.Key.KeyValue)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return &next, digest, nil
}

func (m *FileCacheRenewal) importLocked(path, principal string, cache *credentials.CCache) error {
	if cache.DefaultPrincipal.PrincipalName.PrincipalNameString()+"@"+cache.DefaultPrincipal.Realm != principal {
		return errors.New("ccache principal does not match --principal")
	}
	next, digest, err := copyRenewalCache(cache)
	if err != nil {
		return err
	}
	if m.cache != nil && m.source == digest && m.path == path && m.principal == principal {
		clearNativeCache(next)
		return nil
	}
	cl, err := client.NewFromCCache(next, m.cfg, m.settings...)
	if cl != nil {
		cl.Destroy()
	}
	if err != nil {
		clearNativeCache(next)
		return err
	}
	if m.cache != nil {
		clearNativeCache(m.cache)
	}
	m.cache, m.source, m.path, m.principal, m.retry = next, digest, path, principal, false
	return nil
}

func (m *FileCacheRenewal) load(ctx stdcontext.Context, path, principal string, cache *credentials.CCache, cfg *config.Config, settings []func(*client.Settings)) (*credentials.CCache, error) {
	if ctx == nil {
		ctx = stdcontext.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctx.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.cfg, m.settings = cfg, append([]func(*client.Settings){}, settings...)
	if err := m.importLocked(path, principal, cache); err != nil {
		return nil, err
	}
	if delay, active := m.delayLocked(); active && delay <= 0 {
		if err := m.renewLocked(ctx); err != nil {
			return nil, err
		}
	}
	next, _, err := copyRenewalCache(m.cache)
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return next, err
}

func (m *FileCacheRenewal) homeLocked() *credentials.Credential {
	if m.cache == nil {
		return nil
	}
	e, ok := m.cache.GetEntry(types.NewPrincipalName(2, "krbtgt/"+m.cache.DefaultPrincipal.Realm))
	if !ok {
		return nil
	}
	return e
}

func (m *FileCacheRenewal) delayLocked() (time.Duration, bool) {
	e := m.homeLocked()
	if e == nil || !types.IsFlagSet(&e.TicketFlags, flags.Renewable) || !e.EndTime.Before(e.RenewTill) || !time.Now().Before(e.EndTime) {
		return 0, false
	}
	if m.retry {
		return min(time.Second, max(time.Millisecond, time.Until(e.EndTime)/4)), true
	}
	start := e.StartTime
	if start.IsZero() || start.Unix() == 0 {
		start = e.AuthTime
	}
	margin := min(5*time.Minute, max(time.Second, e.EndTime.Sub(start)/5))
	return time.Until(e.EndTime.Add(-margin)), true
}

func (m *FileCacheRenewal) renewLocked(ctx stdcontext.Context) error {
	ctx, cancel := stdcontext.WithTimeout(ctx, 5*time.Second)
	stop := stdcontext.AfterFunc(m.ctx, cancel)
	defer func() { stop(); cancel() }()
	settings := append(append([]func(*client.Settings){}, m.settings...), client.NetworkContext(ctx))
	next, err := client.RenewCCacheTGT(m.cache, m.cfg, settings...)
	if err != nil {
		m.retry = true
		return err
	}
	old := m.homeLocked()
	for i, e := range m.cache.Credentials {
		if e == old {
			m.cache.Credentials[i] = next
			break
		}
	}
	// RenewCCacheTGT leaves some immutable metadata slices shared with old.
	clear(old.Key.KeyValue)
	clear(old.Ticket)
	m.retry = false
	m.failure = nil
	return nil
}

func (m *FileCacheRenewal) run() {
	defer close(m.done)
	for {
		m.mu.Lock()
		delay, active := m.delayLocked()
		m.mu.Unlock()
		var timer *time.Timer
		var tick <-chan time.Time
		if active {
			timer = time.NewTimer(max(delay, 0))
			tick = timer.C
		}
		select {
		case <-m.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-m.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-tick:
		}
		ctx, cancel := stdcontext.WithTimeout(m.ctx, 5*time.Second)
		m.mu.Lock()
		// An externally replaced cache is authoritative; never renew a revoked or
		// removed selection merely because a previous TGT remains in memory.
		source, err := readCCache(m.path)
		if err == nil {
			err = m.importLocked(m.path, m.principal, source)
			clearNativeCache(source)
		}
		if err == nil {
			if delay, active := m.delayLocked(); active && (delay <= 0 || m.retry) {
				err = m.renewLocked(ctx)
			}
		}
		if err != nil {
			m.retry = true
			m.failure = err
		}
		m.mu.Unlock()
		cancel()
	}
}
