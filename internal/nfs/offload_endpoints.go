package nfs

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// Each endpoint retains its own session slot and resource ownership. Config
// contains explicit credential paths and trust settings, never credential data.
type OffloadEndpoint struct {
	Config    Config
	Recovery  *OffloadSessionEvidence
	Resources *OffloadResources
}

type offloadResourceContext struct {
	v       *v4Client
	journal *offloadJournal
}
type offloadResourceContextKey struct{}

func endpointRecord(r OffloadRecord, key string) OffloadRecord {
	e := r.Endpoints[key]
	r.Recovery, r.Resources = e.Recovery, e.Resources
	r.Endpoints = nil
	r.Pending, r.Outcome, r.Error = true, "", ""
	return r
}

func validateOffloadEndpoints(r, previous OffloadRecord) error {
	if previous.ID != r.ID {
		previous.Endpoints = nil
	}
	for key := range previous.Endpoints {
		if _, ok := r.Endpoints[key]; !ok {
			return errors.New("offload endpoint evidence removed")
		}
	}
	for key, e := range r.Endpoints {
		if key != "source" && key != "verification" || e.Resources == nil || e.Resources.Role != key {
			return errors.New("invalid offload endpoint")
		}
		if key == "source" && r.Operation != "copyfrom" {
			return errors.New("source endpoint outside inter-server COPY")
		}
		profile, err := offloadRecoveryProfile(e.Config)
		if err != nil {
			return err
		}
		if e.Recovery != nil && e.Recovery.Profile != profile {
			return errors.New("offload endpoint profile differs from credentials")
		}
		if old, ok := previous.Endpoints[key]; ok && !reflect.DeepEqual(old.Config, e.Config) {
			return errors.New("offload endpoint credentials changed")
		}
		current, prior := endpointRecord(r, key), endpointRecord(previous, key)
		if err := validateOffloadResources(current, prior); err != nil {
			return err
		}
		if err := validateOffloadSession(current, prior); err != nil {
			return err
		}
	}
	return nil
}

func endpointJournal(parent *offloadJournal, key string) *offloadJournal {
	return &offloadJournal{file: parent.file, record: endpointRecord(parent.record, key), parent: parent, endpoint: key, checkpoint: parent.checkpoint, guard: parent.guard}
}

func (v *v4Client) trackOffloadEndpoint(ctx context.Context, other *v4Client, key string) (context.Context, func(), error) {
	if v.recall == nil {
		return ctx, func() {}, nil
	}
	other.mu.Lock()
	session, saveErr := other.saveSession()
	other.mu.Unlock()
	v.recall.mu.Lock()
	var j *offloadJournal
	if v.recall.offload != nil {
		j = v.recall.offload.journal
	}
	if j == nil || j.record.Resources == nil {
		v.recall.mu.Unlock()
		return ctx, func() {}, nil
	}
	if saveErr != nil {
		v.recall.mu.Unlock()
		return ctx, nil, saveErr
	}
	cfg := *other.c.config
	cfg.Offload, cfg.OffloadJournal, cfg.OffloadSessionRecovery, cfg.OffloadReconcile = false, "", false, false
	profile, err := offloadRecoveryProfile(cfg)
	if err != nil {
		v.recall.mu.Unlock()
		return ctx, nil, err
	}
	r := j.record
	r.Endpoints = cloneOffloadEndpoints(r.Endpoints)
	if _, ok := r.Endpoints[key]; ok {
		v.recall.mu.Unlock()
		return ctx, nil, errors.New("offload endpoint already tracked")
	}
	r.Endpoints[key] = OffloadEndpoint{Config: cfg, Resources: &OffloadResources{Version: 1, Complete: true, Role: key}, Recovery: &OffloadSessionEvidence{Profile: profile, Session: session}}
	err = j.append(r)
	v.recall.mu.Unlock()
	if err != nil {
		return ctx, nil, err
	}
	view := endpointJournal(j, key)
	restore, err := other.installOffloadRecovery(view)
	return context.WithValue(ctx, offloadResourceContextKey{}, offloadResourceContext{other, view}), restore, err
}

func cloneOffloadEndpoints(in map[string]OffloadEndpoint) map[string]OffloadEndpoint {
	out := make(map[string]OffloadEndpoint, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func recoverOffloadEndpoint(ctx context.Context, parent *offloadJournal, key string) error {
	e, ok := parent.record.Endpoints[key]
	if !ok {
		return nil
	}
	view := endpointJournal(parent, key)
	if err := view.cancelUnsentResource(); err != nil {
		return err
	}
	e = parent.record.Endpoints[key]
	if offloadOwnResourcesReleased(view.record) && (e.Recovery == nil || e.Recovery.Request == nil) && (key != "source" || sourceGrantClosed(parent.record, time.Now())) {
		return nil
	}
	if e.Recovery == nil {
		return errors.New("offload endpoint lacks original session evidence")
	}
	if key == "source" && e.Config.Kerberos.RPCVersion == 3 && e.Recovery.Request != nil {
		for _, op := range e.Recovery.Request.Operations {
			if op.Code == 61 || op.Code == 66 {
				return errors.New("source grant request requires original GSS child privilege")
			}
		}
	}
	c, err := connectSavedSession(ctx, e.Config, e.Recovery.Session)
	if err != nil {
		return err
	}
	defer c.Close()
	v := c.v4
	if err := v.replayOffloadRequest(ctx, view); err != nil {
		return err
	}
	if key == "source" && parent.record.SourceGrant != nil && !sourceGrantClosed(parent.record, time.Now()) {
		if e.Config.Kerberos.RPCVersion == 3 {
			return errors.New("source grant needs original child revocation or checked expiration")
		}
		installRecoveryJournal(v, view)
		if err := v.compound(ctx, fh4(parent.record.Source), op4(66, encoder(parent.record.SourceGrant.ID), nil)); err != nil {
			return err
		}
	}
	return v.cleanupOffloadResources(ctx, view)
}

func connectOffloadVerifier(ctx context.Context, cfg Config, j *offloadJournal) (context.Context, *Client, func(), error) {
	if j.record.Resources == nil {
		c, err := Connect(ctx, cfg)
		return ctx, c, func() {}, err
	}
	var c *Client
	var err error
	if e, ok := j.record.Endpoints["verification"]; ok {
		if e.Recovery == nil {
			if !offloadOwnResourcesReleased(endpointRecord(j.record, "verification")) {
				return ctx, nil, nil, errors.New("verification endpoint has no checked session")
			}
			c, err = Connect(ctx, e.Config)
		} else {
			c, err = connectSavedSession(ctx, e.Config, e.Recovery.Session)
		}
	} else {
		c, err = Connect(ctx, cfg)
		if err == nil {
			// Verification owns a single foreground slot. Its READ/COMMIT/state
			// requests renew the lease; no background RPC may race the terminal
			// checkpoint or consume a slot between cleanup and that receipt.
			if c.v4.stop != nil {
				c.v4.stop()
				if c.v4.done != nil {
					<-c.v4.done
				}
				c.v4.stop = nil
				c.v4.done = nil
			}
			r := j.record
			r.Endpoints = cloneOffloadEndpoints(r.Endpoints)
			c.v4.mu.Lock()
			session, saveErr := c.v4.saveSession()
			c.v4.mu.Unlock()
			profile, profileErr := offloadRecoveryProfile(cfg)
			if saveErr != nil || profileErr != nil {
				c.Close()
				return ctx, nil, nil, errors.Join(saveErr, profileErr)
			}
			r.Endpoints["verification"] = OffloadEndpoint{Config: cfg, Resources: &OffloadResources{Version: 1, Role: "verification", Complete: true}, Recovery: &OffloadSessionEvidence{Profile: profile, Session: session}}
			err = j.append(r)
		}
	}
	if err != nil {
		if c != nil {
			c.Close()
		}
		return ctx, nil, nil, err
	}
	c.v4.migrationBorrowed = true
	view := endpointJournal(j, "verification")
	if view.record.Recovery != nil {
		if err = c.v4.replayOffloadRequest(ctx, view); err == nil {
			err = c.v4.cleanupOffloadResources(ctx, view)
		}
		if err != nil {
			c.Close()
			return ctx, nil, nil, err
		}
		c.v4.beforeCached, c.v4.afterCached, c.v4.afterCachedError = nil, nil, nil
	}
	restore, err := c.v4.installOffloadRecovery(view)
	if err != nil {
		c.Close()
		return ctx, nil, nil, err
	}
	finish := func() {
		restore()
		if !j.record.Pending {
			c.v4.migrationBorrowed = false
		}
	}
	return context.WithValue(ctx, offloadResourceContextKey{}, offloadResourceContext{c.v4, view}), c, finish, nil
}
