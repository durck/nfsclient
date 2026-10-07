package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
)

const nlmProgram = 100021

// NLMStatus is distinct from NFS status: NLM has its own status namespace.
type NLMStatus uint32

func (s NLMStatus) Error() string {
	names := [...]string{"granted", "denied", "no lock resources", "blocked", "server grace period", "deadlock", "read-only filesystem", "stale file handle", "file too large", "failed"}
	if uint32(s) < uint32(len(names)) {
		return fmt.Sprintf("NLM %d: %s", s, names[s])
	}
	return fmt.Sprintf("unknown NLM status %d", s)
}

// LockConflict is a momentary TEST/LOCKT observation, never a retained lock.
// SVID belongs only to NLM; NFSv4 returns an opaque owner and client ID.
type LockConflict struct {
	Protocol       string
	Write          bool
	SVID           int32
	ClientID       uint64
	Owner          []byte
	Offset, Length uint64 // LockToEOF means through future EOF.
}

func validateNLMRange(version uint32, offset, length uint64) error {
	limit := uint64(math.MaxInt64)
	if version == 1 {
		limit = math.MaxUint32
	}
	if length == 0 || offset > limit || length != LockToEOF && (length-1 > limit-offset || version == 1 && length > math.MaxUint32) {
		return fmt.Errorf("range is outside NLM v%d bounds; use a positive length or eof", version)
	}
	return nil
}

func encodeNLMRange(e *encoder, version uint32, offset, length uint64) {
	if length == LockToEOF {
		length = 0
	}
	if version == 1 {
		e.u32(uint32(offset))
		e.u32(uint32(length))
	} else {
		e.u64(offset)
		e.u64(length)
	}
}

// TestLock observes conflicts using NLM for NFSv2/v3 or LOCKT for NFSv4.
// nil means no conflict was reported at that instant, not permission to write.
// It never acquires, monitors, reclaims or releases locks. Protected profiles
// are refused for NLM rather than opening an unprotected side channel.
func (c *Client) TestLock(ctx context.Context, fh []byte, write bool, offset, length uint64) (*LockConflict, error) {
	if c.v4 != nil {
		return c.v4.testLock(ctx, fh, write, offset, length)
	}
	version := uint32(4)
	switch c.Version() {
	case "2":
		version = 1
		if len(fh) != 32 {
			return nil, errors.New("NLM v1 requires a 32-byte NFSv2 handle")
		}
	case "3":
		if len(fh) == 0 || len(fh) > 64 {
			return nil, errors.New("invalid NFSv3 handle for NLM")
		}
	default:
		return nil, errors.New("locktest currently requires NFSv2/v3 with AUTH_SYS over TCP or UDP")
	}
	if err := validateNLMRange(version, offset, length); err != nil {
		return nil, err
	}
	if c.config == nil || c.nfs == nil || c.nfs.conn == nil {
		return nil, errors.New("NLM requires an active connection profile")
	}
	cfg := *c.config
	if c.Security() != "sys" || cfg.Security != "" && cfg.Security != "sys" || cfg.TLS.Enabled || cfg.Transport == "iwarp" {
		return nil, errors.New("NLM inspection requires AUTH_SYS without TLS; security downgrade refused")
	}
	if cfg.NLMPort < 0 || cfg.NLMPort > 65535 || len(c.Auth.Groups) > 16 {
		return nil, errors.New("invalid NLM port or AUTH_SYS group count")
	}
	// Use the connected NFS peer, not a fresh DNS answer for a different server.
	c.nfs.mu.Lock()
	closed := c.nfs.closed || c.nfs.closing
	peer := c.nfs.conn.RemoteAddr().String()
	c.nfs.mu.Unlock()
	if closed {
		return nil, ErrConnectionLost
	}
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return nil, fmt.Errorf("NLM peer: %w", err)
	}
	cfg.Host = host
	cfg.Transport = c.Transport()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	port := cfg.NLMPort
	if port == 0 {
		port, err = discoverNLMPort(ctx, cfg, version)
		if err != nil {
			return nil, err
		}
	}
	rpc, err := dialConfiguredRPC(ctx, cfg, port, nlmProgram, version)
	if err != nil {
		return nil, fmt.Errorf("connect NLM: %w", err)
	}
	defer rpc.conn.Close()
	// A fresh owner cannot accidentally exempt another client's held lock.
	var cookie, owner [16]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(owner[:]); err != nil {
		return nil, err
	}
	caller, _, err := net.SplitHostPort(rpc.conn.LocalAddr().String())
	if err != nil || len(caller) > 1024 {
		return nil, errors.New("invalid NLM caller address")
	}
	var e encoder
	e.opaque(cookie[:])
	if write {
		e.u32(1)
	} else {
		e.u32(0)
	}
	e.str(caller)
	e.opaque(fh)
	e.opaque(owner[:])
	e.u32(uint32(os.Getpid()))
	encodeNLMRange(&e, version, offset, length)
	d, err := rpc.call(ctx, nlmProgram, version, 1, &c.Auth, e)
	if err != nil {
		return nil, fmt.Errorf("NLM TEST: %w", err)
	}
	return decodeNLMTest(d, version, cookie[:], write, offset, length)
}

func discoverNLMPort(ctx context.Context, cfg Config, version uint32) (int, error) {
	return discoverSidePort(ctx, cfg, nlmProgram, version, "NLM")
}

func discoverSidePort(ctx context.Context, cfg Config, program, version uint32, service string) (int, error) {
	if cfg.PortmapPort == 0 {
		cfg.PortmapPort = 111
	}
	if cfg.PortmapPort < 1 || cfg.PortmapPort > 65535 {
		return 0, errors.New("invalid portmapper port")
	}
	cfg.ReservedPort = false
	pm, err := dialConfiguredRPC(ctx, cfg, cfg.PortmapPort, 100000, 2)
	if err != nil {
		return 0, fmt.Errorf("%s port discovery: %w", service, err)
	}
	defer pm.conn.Close()
	protocol := uint32(6)
	if cfg.Transport == "udp" {
		protocol = 17
	}
	var e encoder
	e.u32(program)
	e.u32(version)
	e.u32(protocol)
	e.u32(0)
	d, err := pm.call(ctx, 100000, 2, 3, nil, e)
	if err != nil {
		return 0, fmt.Errorf("%s port discovery: %w", service, err)
	}
	port := d.u32()
	if d.err != nil {
		return 0, d.err
	}
	if len(d.b) != 0 {
		return 0, fmt.Errorf("trailing %s portmapper reply", service)
	}
	if port == 0 || port > 65535 {
		return 0, fmt.Errorf("%s v%d/%s unavailable; check the service or explicit port", service, version, cfg.Transport)
	}
	return int(port), nil
}

func decodeNLMTest(d *decoder, version uint32, cookie []byte, write bool, offset, length uint64) (*LockConflict, error) {
	if !bytes.Equal(d.opaque(1024), cookie) || d.err != nil {
		return nil, errors.New("invalid NLM reply cookie")
	}
	status := NLMStatus(d.u32())
	var result *LockConflict
	if status == 1 {
		result = &LockConflict{Protocol: "NLM", Write: d.boolean(), SVID: int32(d.u32())}
		d.opaque(1024) // Remote opaque owner is intentionally not displayed or retained.
		if version == 1 {
			result.Offset, result.Length = uint64(d.u32()), uint64(d.u32())
		} else {
			result.Offset, result.Length = d.u64(), d.u64()
		}
		if result.Length == 0 {
			result.Length = LockToEOF
		}
	}
	if d.err != nil {
		return nil, fmt.Errorf("invalid NLM TEST reply: %w", d.err)
	}
	if len(d.b) != 0 {
		return nil, errors.New("trailing NLM TEST reply")
	}
	if status == 0 {
		return nil, nil
	}
	if status != 1 {
		if status > 9 || version == 1 && status > 5 {
			return nil, fmt.Errorf("invalid NLM v%d status %d", version, status)
		}
		return nil, status
	}
	if err := validateNLMRange(version, result.Offset, result.Length); err != nil {
		return nil, fmt.Errorf("invalid NLM holder: %w", err)
	}
	if !write && !result.Write || !lockRangesOverlap(offset, length, result.Offset, result.Length) {
		return nil, errors.New("NLM returned a holder that does not conflict with the requested range")
	}
	return result, nil
}
