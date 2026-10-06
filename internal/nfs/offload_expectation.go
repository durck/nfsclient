package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
)

// Immutable pre-issue content and destination identity. Range length is the
// journal intent; hashing uses bounded chunks regardless of total file size.
type OffloadExpectation struct {
	SHA256                        string
	Size, FSID, FSIDMinor, FileID uint64
	Parent                        []byte
	Name                          string
}

func validateOffloadExpectation(r, previous OffloadRecord) error {
	if e := r.Expectation; e != nil {
		digest, err := hex.DecodeString(e.SHA256)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != e.SHA256 || e.Size < r.Offset+r.Length || len(e.Parent) == 0 || len(e.Parent) > 128 || e.Name == "" || e.Name == "." || e.Name == ".." || strings.ContainsAny(e.Name, "/\x00") {
			return errors.New("invalid offload content expectation")
		}
	}
	if previous.Pending && previous.ID == r.ID {
		if previous.Expectation != nil {
			p, e := previous.Expectation, r.Expectation
			if e == nil || p.SHA256 != e.SHA256 || p.Size != e.Size || p.FSID != e.FSID || p.FSIDMinor != e.FSIDMinor || p.FileID != e.FileID || p.Name != e.Name || !bytes.Equal(p.Parent, e.Parent) {
				return errors.New("offload expected bytes changed")
			}
		} else if r.Expectation != nil && (previous.Phase != "prepared" || r.Phase != "prepared") {
			return errors.New("offload expectation appeared after issue")
		}
	}
	return nil
}

func (c *Client) offloadRangeDigest(ctx context.Context, fh []byte, offset, length uint64) (_ string, resultErr error) {
	if c.ReadSize == 0 {
		return "", errors.New("offload verification read size unavailable")
	}
	sid, closeIO, err := c.v4.offloadOpenIO(ctx, fh, 1)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	h := sha256.New()
	for done := uint64(0); done < length; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := c.v4.checkLockedIO(fh, 1); err != nil {
			return "", err
		}
		limit := uint32(min(length-done, uint64(c.ReadSize), uint64(1<<20)))
		e := append(encoder(nil), sid...)
		e.u64(offset + done)
		e.u32(limit)
		var data []byte
		var eof bool
		if err := c.v4.compound(ctx, fh4(fh), op4(25, e, func(d *decoder) { eof = d.boolean(); data = d.opaque(limit) })); err != nil {
			return "", err
		}
		if len(data) == 0 {
			return "", io.ErrNoProgress
		}
		h.Write(data)
		done += uint64(len(data))
		if eof && done != length {
			return "", io.ErrUnexpectedEOF
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func adbDigest(ctx context.Context, b ApplicationDataBlock) (string, error) {
	if _, err := ValidateApplicationDataBlock(b); err != nil {
		return "", err
	}
	block := make([]byte, int(b.BlockSize))
	copy(block[b.PatternOffset:], b.Pattern)
	h := sha256.New()
	for n := uint64(0); n < b.BlockCount; n++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if b.FirstNumber != nil {
			binary.BigEndian.PutUint64(block[b.NumberOffset:], uint64(*b.FirstNumber)+n)
		}
		h.Write(block)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Client) prepareOffloadExpectation(ctx context.Context, sourceClient *Client, source, destination []byte, sourceOffset, offset, length uint64, adb *ApplicationDataBlock) error {
	if c.config == nil || !c.config.OffloadSessionRecovery {
		return nil
	}
	name, ok := c.v4.parents[string(destination)]
	if !ok {
		return errors.New("offload recovery requires a resolved destination name")
	}
	auth, identity := c.Auth, c.Identity()
	auth.Groups = slices.Clone(auth.Groups)
	dst, err := c.GetAttr(ctx, destination)
	if err != nil {
		return err
	}
	if !reconcileAttributes(dst) {
		return errors.New("offload recovery requires stable destination identity attributes")
	}
	var digest string
	if adb != nil {
		digest, err = adbDigest(ctx, *adb)
	} else {
		sourceAuth, sourceIdentity := sourceClient.Auth, sourceClient.Identity()
		sourceAuth.Groups = slices.Clone(sourceAuth.Groups)
		before, e := sourceClient.GetAttr(ctx, source)
		if e != nil {
			return e
		}
		if !reconcileAttributes(before) || before.Size < sourceOffset+length {
			return errors.New("offload source range or identity unavailable")
		}
		digest, err = sourceClient.offloadRangeDigest(ctx, source, sourceOffset, length)
		if err == nil {
			after, e := sourceClient.GetAttr(ctx, source)
			if e != nil {
				return e
			}
			if !sameReconcileAttributes(before, after) || sourceIdentity != sourceClient.Identity() || sourceAuth.UID != sourceClient.Auth.UID || sourceAuth.GID != sourceClient.Auth.GID || !slices.Equal(sourceAuth.Groups, sourceClient.Auth.Groups) {
				return errors.New("offload source changed while hashing expected bytes")
			}
		}
	}
	if err != nil {
		return err
	}
	if identity != c.Identity() || auth.UID != c.Auth.UID || auth.GID != c.Auth.GID || !slices.Equal(auth.Groups, c.Auth.Groups) {
		return errors.New("offload identity changed while preparing expected bytes")
	}
	r := c.v4.recall
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.offload == nil || r.offload.journal == nil {
		return errors.New("offload expectation journal unavailable")
	}
	j := r.offload.journal
	record := j.record
	record.Expectation = &OffloadExpectation{SHA256: digest, Size: max(dst.Size, offset+length), FSID: dst.FSID, FSIDMinor: dst.FSIDMinor, FileID: dst.FileID, Parent: bytes.Clone(name.dir), Name: name.name}
	return j.append(record)
}

// A successful STATUS proves the original operation is quiescent. A new
// protected connection may now stabilize and verify bytes under a read lock;
// it cannot issue a replacement COPY/WRITE_SAME, even if verification fails.
func verifyOffloadExpectation(ctx context.Context, c *Client, r OffloadRecord) (resultErr error) {
	e := r.Expectation
	if e == nil {
		return errors.New("offload has no pre-issue content expectation")
	}
	// OPEN validates that this original name still resolves to the exact file
	// handle; changed namespace bindings therefore cannot redirect verification.
	if c.v4.parents == nil {
		c.v4.parents = make(map[string]v4Name)
	}
	c.v4.parents[string(r.Destination)] = v4Name{dir: bytes.Clone(e.Parent), name: e.Name}
	auth := c.Auth
	auth.Groups = slices.Clone(auth.Groups)
	identity := c.Identity()
	before, err := c.GetAttr(ctx, r.Destination)
	if err != nil {
		return err
	}
	if !reconcileAttributes(before) || before.Size != e.Size || before.FSID != e.FSID || before.FSIDMinor != e.FSIDMinor || before.FileID != e.FileID {
		return errors.New("offload destination identity or size changed")
	}
	var lock uint64
	tracked, owned := ctx.Value(offloadResourceContextKey{}).(offloadResourceContext)
	owned = owned && tracked.v == c.v4 && tracked.journal.endpoint == "verification"
	if owned {
		lock, err = c.v4.ownedOffloadReadLock(ctx, tracked.journal, r.Destination)
	} else {
		lock, err = c.Lock(ctx, r.Destination, false)
	}
	if err != nil {
		return err
	}
	defer func() {
		if owned {
			resultErr = errors.Join(resultErr, c.v4.cleanupOffloadResources(context.Background(), tracked.journal))
		} else {
			resultErr = errors.Join(resultErr, c.Unlock(ctx, lock))
		}
	}()
	var commit encoder
	commit.u64(r.Offset)
	commit.u32(0)
	if err := c.v4.compound(ctx, fh4(r.Destination), op4(5, commit, func(d *decoder) { d.take(8) })); err != nil {
		return err
	}
	digest, err := c.offloadRangeDigest(ctx, r.Destination, r.Offset, r.Length)
	if err != nil {
		return err
	}
	if digest != e.SHA256 {
		return errors.New("offload destination differs from pre-issue expected bytes")
	}
	after, err := c.GetAttr(ctx, r.Destination)
	if err != nil {
		return err
	}
	if !sameReconcileAttributes(before, after) || identity != c.Identity() || auth.UID != c.Auth.UID || auth.GID != c.Auth.GID || !slices.Equal(auth.Groups, c.Auth.Groups) {
		return errors.New("offload destination or identity changed during verification")
	}
	if held := c.v4.locks[lock]; held == nil || held.file == nil || !bytes.Equal(held.file.fh, r.Destination) {
		return errors.New("offload verification lock changed")
	}
	return ctx.Err()
}
