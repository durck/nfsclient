package iscsi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

func targetURL(t Target) string {
	return "iscsi://" + t.Endpoint + "/" + t.Name + "/" + strconv.Itoa(int(t.LUN))
}

type readRecovery struct {
	portals  []Target
	next     int
	guard    func() error
	failed   bool
	validate func(io.ReaderAt) error
}

// EnableReadRecovery permits at most one fresh session per supplied alternate,
// or one reconnect to the original portal when the list is empty. The guard
// must revalidate the enclosing read's lease/layout/lock without calling Volume.
// Writable volumes never acquire this policy, even before their first write.
func (v *Volume) EnableReadRecovery(alternates []Target, guard func() error, validate func(io.ReaderAt) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.write || v.lost != nil || v.recovery != nil || guard == nil || len(alternates) > 8 {
		return errors.New("read recovery requires a live read-only volume, a consistency guard and at most eight approved portals")
	}
	seen := map[string]bool{}
	portals := append([]Target(nil), alternates...)
	if len(portals) == 0 {
		portals = []Target{v.target}
	}
	for _, p := range portals {
		parsed, err := ParseTarget(targetURL(p))
		if err != nil || parsed != p || p.Name != v.target.Name || p.LUN != v.target.LUN || seen[p.Endpoint] {
			return errors.New("read recovery portal must preserve approved target and LUN without duplicates")
		}
		seen[p.Endpoint] = true
	}
	if err := guard(); err != nil {
		return err
	}
	v.recovery = &readRecovery{portals: portals, guard: guard, validate: validate}
	return nil
}

func transportReadFailure(err error) bool {
	var network *net.OpError
	return errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (v *Volume) recoverRead(cdb [16]byte, data []byte, cause error) (resultErr error) {
	r := v.recovery
	if r == nil || r.failed || v.write || v.ctx.Err() != nil || !transportReadFailure(cause) {
		return cause
	}
	defer func() {
		if resultErr != nil {
			r.failed = true
		}
	}()
	for r.next < len(r.portals) {
		if err := r.guard(); err != nil {
			return v.poison(err)
		}
		portal := r.portals[r.next]
		r.next++
		fresh, err := openSessionSecurityChecked(v.ctx, portal, v.initiator, v.timeout, false, v.policy, &v.securityProof)
		if err != nil {
			if v.ctx.Err() != nil || !transportReadFailure(err) {
				return err
			}
			continue
		}
		_, err = probeVolume(fresh)
		if err == nil && (!bytes.Equal(fresh.id, v.id) || fresh.size != v.size || fresh.sector != v.sector) {
			err = errors.New("read recovery target identity or geometry changed")
		}
		if err == nil {
			err = r.guard()
		}
		if err == nil && r.validate != nil {
			err = r.validate(fresh)
		}
		if err == nil {
			err = r.guard()
		}
		if err != nil {
			fresh.Close()
			return err
		}
		// Transfer the session only after all evidence agrees. Context cancellation
		// remains attached to the new connection; the old watcher is retired.
		v.stop()
		v.conn.Close()
		v.conn, v.stop = fresh.conn, fresh.stop
		v.cmd, v.stat, v.tag, v.maxCmd, v.expCmd, v.recv = fresh.cmd, fresh.stat, fresh.tag, fresh.maxCmd, fresh.expCmd, fresh.recv
		v.lost = nil
		clear(data)
		if _, err = v.command(cdb, data, nil, false); err == nil {
			if err = r.guard(); err != nil {
				return v.poison(err)
			}
			return nil
		}
		cause = err
		if v.ctx.Err() != nil || !transportReadFailure(err) {
			return err
		}
	}
	return cause
}

func securityProof(secret, targetSecret []byte) [32]byte {
	h := sha256.New()
	var n [8]byte
	for _, b := range [][]byte{secret, targetSecret} {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
