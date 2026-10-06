package nfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// UploadV2 stages CREATE inside a newly created private directory. Never send
// unguarded v2 CREATE to the destination. LINK publishes without replacement.
// Existing-target replacement is refused until ACL preservation is supported.
func (c *Client) UploadV2(ctx context.Context, dir []byte, name string, mode uint32, r io.Reader, size int64, overwrite bool, progress func(uint64)) (written int64, resultErr error) {
	if c.Version() != "2" {
		return 0, errors.New("UploadV2 requires NFSv2")
	}
	if size < 0 || size > maxV2File {
		return 0, errors.New("NFSv2 upload limit is 2 GiB minus one byte")
	}
	if name == "" || name == "." || name == ".." || len(name) > 255 || strings.ContainsAny(name, "/\x00") {
		return 0, errors.New("invalid NFSv2 destination name")
	}
	if _, err := handle2(dir); err != nil {
		return 0, err
	}
	if old, err := c.lookup2(ctx, dir, name); err == nil {
		if !overwrite {
			return 0, Status(17)
		}
		if old.Attr.Type != 1 {
			return 0, errors.New("overwrite destination must be a regular file")
		}
		return 0, ErrLegacyReplacementUnsupported
	} else if !errors.Is(err, Status(2)) {
		return 0, err
	}
	var stage Node
	var stageName string
	for attempt := 0; attempt < 4; attempt++ {
		var token [12]byte
		if _, err := rand.Read(token[:]); err != nil {
			return 0, err
		}
		stageName = ".nfs-upload-" + hex.EncodeToString(token[:])
		var err error
		stage, err = c.create2(ctx, dir, stageName, 0700, true)
		if errors.Is(err, Status(17)) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("create staging directory %q (an unacknowledged directory may remain): %w", stageName, err)
		}
		break
	}
	if len(stage.Handle) == 0 {
		return 0, errors.New("could not reserve an unused staging directory after four attempts")
	}
	created, published := false, false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var cleanupErr error
		if created {
			if err := c.remove2(cleanup, stage.Handle, "payload"); err != nil && !errors.Is(err, Status(2)) {
				cleanupErr = err
			}
		}
		if err := c.rmdir2(cleanup, dir, stageName); err != nil && !errors.Is(err, Status(2)) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		if cleanupErr != nil {
			state := "see the preceding error for publication state"
			if published {
				state = "destination published successfully; do not retry the upload"
			}
			resultErr = errors.Join(resultErr, fmt.Errorf("%s; temporary directory %q may remain: %w", state, stageName, cleanupErr))
		}
	}()
	if stage.Attr.Type != 2 || stage.Attr.Mode&0777 != 0700 {
		return 0, errors.New("server did not create a private 0700 staging directory")
	}
	// Unguarded CREATE is permitted only inside this fresh directory.
	e, _ := handle2(stage.Handle)
	e.str("payload")
	e.u32(0600)
	e.u32(^uint32(0)) // uid: server-selected owner
	e.u32(^uint32(0)) // gid
	e.u32(0)          // size
	for i := 0; i < 4; i++ {
		e.u32(^uint32(0))
	} // timestamps
	d, err := c.call(ctx, 9, e)
	if err != nil {
		return 0, fmt.Errorf("create staged payload; destination unchanged: %w", err)
	}
	created = true
	file := Node{Handle: append([]byte(nil), d.take(32)...), Attr: attr2(d)}
	if d.err != nil {
		return 0, d.err
	}
	if file.Attr.Type != 1 || file.Attr.Size != 0 {
		return 0, errors.New("server did not create an empty regular staging file")
	}
	written, err = c.write2(ctx, file.Handle, r, progress)
	if err != nil {
		return written, fmt.Errorf("staged upload incomplete; destination unchanged: %w", err)
	}
	if written != size {
		return written, errors.New("upload source changed size; destination unchanged")
	}
	a, err := c.getAttr2(ctx, file.Handle)
	if err != nil {
		return written, err
	}
	if a.Type != 1 || a.Size != uint64(size) {
		return written, errors.New("staged file size/type mismatch; destination unchanged")
	}
	if err := c.chmod2(ctx, file.Handle, mode&0777); err != nil {
		return written, err
	}
	// Even an overwrite request cannot replace an object that was absent at
	// lookup and appeared later. LINK provides atomic no-replace publication.
	err = c.link2(ctx, file.Handle, dir, name)
	if err != nil {
		var status Status
		if errors.As(err, &status) {
			return written, fmt.Errorf("publication rejected; destination unchanged: %w", err)
		}
		return written, fmt.Errorf("publication outcome unknown; inspect %q before retrying: %w", name, err)
	}
	published = true
	return written, nil
}

func (c *Client) write2(ctx context.Context, fh []byte, r io.Reader, progress func(uint64)) (int64, error) {
	return c.write2At(ctx, fh, r, progress, 0)
}

func (c *Client) write2At(ctx context.Context, fh []byte, r io.Reader, progress func(uint64), start uint64) (int64, error) {
	if start > maxV2File {
		return 0, errors.New("NFSv2 upload limit is 2 GiB minus one byte")
	}
	base, err := handle2(fh)
	if err != nil {
		return 0, err
	}
	if c.WriteSize == 0 {
		return 0, errors.New("zero NFSv2 write size")
	}
	buf := make([]byte, min(c.WriteSize, 8192))
	offset := start
	for {
		if err := ctx.Err(); err != nil {
			return int64(offset - start), err
		}
		n, readErr := r.Read(buf)
		if n < 0 || n > len(buf) {
			return int64(offset - start), errors.New("invalid reader count")
		}
		if offset+uint64(n) > maxV2File {
			return int64(offset - start), errors.New("NFSv2 upload limit is 2 GiB minus one byte")
		}
		if n > 0 {
			e := append(encoder(nil), base...)
			e.u32(0) // unused beginoffset
			e.u32(uint32(offset))
			e.u32(0) // unused totalcount
			e.opaque(buf[:n])
			d, err := c.call(ctx, 8, e)
			if err != nil {
				var status Status
				if !errors.As(err, &status) {
					err = c.uncertainLegacyWrite(err)
				}
				return int64(offset - start), err
			}
			a := attr2(d)
			if d.err != nil {
				return int64(offset - start), c.uncertainLegacyWrite(d.err)
			}
			if len(d.b) != 0 || a.Type != 1 || a.Size < offset+uint64(n) || a.Size > maxV2File {
				return int64(offset - start), c.uncertainLegacyWrite(errors.New("invalid NFSv2 WRITE result attributes"))
			}
			// v2 success acknowledges the whole synchronous write; no COMMIT.
			offset += uint64(n)
			if progress != nil {
				progress(offset - start)
			}
		}
		if readErr == io.EOF {
			return int64(offset - start), nil
		}
		if readErr != nil {
			return int64(offset - start), readErr
		}
		if n == 0 {
			return int64(offset - start), io.ErrNoProgress
		}
	}
}

func (c *Client) link2(ctx context.Context, fh, dir []byte, name string) error {
	e, err := handle2(fh)
	if err != nil {
		return err
	}
	h, err := handle2(dir)
	if err != nil {
		return err
	}
	e = append(e, h...)
	e.str(name)
	_, err = c.call(ctx, 12, e)
	return err
}

func (c *Client) rmdir2(ctx context.Context, dir []byte, name string) error {
	e, err := handle2(dir)
	if err != nil {
		return err
	}
	e.str(name)
	_, err = c.call(ctx, 15, e)
	return err
}
