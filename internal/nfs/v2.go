package nfs

import (
	"context"
	"errors"
	"io"
	"sort"
	"time"
)

const maxV2File = 1<<31 - 1

func handle2(fh []byte) (encoder, error) {
	if len(fh) != 32 {
		return nil, errors.New("NFSv2 requires a 32-byte file handle")
	}
	return append(encoder(nil), fh...), nil
}
func attr2(d *decoder) Attr {
	a := Attr{Type: d.u32(), Mode: d.u32(), NLink: d.u32(), HasNLink: true}
	a.UID = d.u32()
	a.GID = d.u32()
	a.Size = uint64(d.u32())
	d.u32()
	d.u32()
	d.u32()
	a.FSID = uint64(d.u32())
	a.FileID = uint64(d.u32())
	a.HasFSID, a.HasFileID = true, true
	d.take(8)
	sec, usec := d.u32(), d.u32()
	a.MTime = time.Unix(int64(sec), int64(usec)*1000)
	if usec >= 1e6 {
		d.err = errors.New("invalid NFSv2 modification timestamp")
	}
	sec, usec = d.u32(), d.u32()
	if usec >= 1e6 {
		d.err = errors.New("invalid NFSv2 metadata timestamp")
	}
	a.CTime = time.Unix(int64(sec), int64(usec)*1000)
	a.HasSize, a.HasMTime, a.HasCTime = true, true, true
	return a
}
func (c *Client) getAttr2(ctx context.Context, fh []byte) (Attr, error) {
	e, err := handle2(fh)
	if err != nil {
		return Attr{}, err
	}
	d, err := c.call(ctx, 1, e)
	if err != nil {
		return Attr{}, err
	}
	a := attr2(d)
	return a, d.err
}
func (c *Client) lookup2(ctx context.Context, dir []byte, name string) (Node, error) {
	e, err := handle2(dir)
	if err != nil {
		return Node{}, err
	}
	e.str(name)
	d, err := c.call(ctx, 4, e)
	if err != nil {
		return Node{}, err
	}
	n := Node{Handle: append([]byte(nil), d.take(32)...), Attr: attr2(d)}
	if d.err == nil && len(d.b) != 0 {
		return Node{}, errors.New("trailing NFSv2 object reply data")
	}
	return n, d.err
}
func (c *Client) readlink2(ctx context.Context, fh []byte) (string, error) {
	e, err := handle2(fh)
	if err != nil {
		return "", err
	}
	d, err := c.call(ctx, 5, e)
	if err != nil {
		return "", err
	}
	s := d.str()
	return s, d.err
}
func (c *Client) tune2(ctx context.Context, fh []byte) error {
	e, err := handle2(fh)
	if err != nil {
		return err
	}
	d, err := c.call(ctx, 17, e)
	if err != nil {
		return err
	}
	size := d.u32()
	d.take(16)
	if d.err != nil {
		return d.err
	}
	if size == 0 {
		return errors.New("server returned zero transfer maximum")
	}
	c.ReadSize = min(size, 8192)
	if c.Transport() == "udp" {
		c.ReadSize = min(c.ReadSize, c.udpSize())
	}
	c.WriteSize = c.ReadSize
	return nil
}
func (c *Client) readdir2(ctx context.Context, fh []byte) ([]Entry, error) {
	base, err := handle2(fh)
	if err != nil {
		return nil, err
	}
	entries := []Entry{}
	var cookie uint32
	seen := map[uint32]bool{}
	for {
		e := append(encoder(nil), base...)
		e.u32(cookie)
		count := uint32(8192)
		if c.Transport() == "udp" {
			count = c.udpSize()
		}
		e.u32(count)
		d, err := c.call(ctx, 16, e)
		if err != nil {
			return nil, err
		}
		old := cookie
		for d.boolean() && d.err == nil {
			d.u32()
			name := d.str()
			cookie = d.u32()
			if d.err != nil {
				return nil, d.err
			}
			if name == "." || name == ".." {
				continue
			}
			n, err := c.lookup2(ctx, fh, name)
			if errors.Is(err, Status(2)) {
				continue
			}
			if err != nil {
				return nil, err
			}
			entries = append(entries, Entry{Name: name, Node: n})
			if len(entries) > 1000000 {
				return nil, errors.New("directory exceeds one million entries")
			}
		}
		eof := d.boolean()
		if d.err != nil {
			return nil, d.err
		}
		if eof {
			break
		}
		if cookie == old || seen[cookie] {
			return nil, errors.New("directory listing made no progress")
		}
		seen[cookie] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}
func (c *Client) read2(ctx context.Context, fh []byte, w io.Writer, progress func(uint64)) (int64, error) {
	base, err := handle2(fh)
	if err != nil {
		return 0, err
	}
	var offset uint32
	for {
		if offset >= maxV2File {
			return int64(offset), errors.New("NFSv2 transfer exceeds the supported 2 GiB limit")
		}
		e := append(encoder(nil), base...)
		e.u32(offset)
		e.u32(min(c.ReadSize, maxV2File-offset))
		e.u32(0)
		d, err := c.call(ctx, 6, e)
		if err != nil {
			return int64(offset), err
		}
		a := attr2(d)
		data := d.opaque(min(c.ReadSize, 8192))
		if d.err != nil {
			return int64(offset), d.err
		}
		if a.Size > maxV2File {
			return int64(offset), errors.New("NFSv2 files above 2 GiB are unsupported")
		}
		n, err := w.Write(data)
		offset += uint32(n)
		if progress != nil {
			progress(uint64(offset))
		}
		if err != nil {
			return int64(offset), err
		}
		if n != len(data) {
			return int64(offset), io.ErrShortWrite
		}
		if uint64(offset) >= a.Size {
			return int64(offset), nil
		}
		if n == 0 {
			return int64(offset), io.ErrNoProgress
		}
	}
}
func sattr2(e *encoder, mode uint32) {
	e.u32(mode)
	for i := 0; i < 7; i++ {
		e.u32(^uint32(0))
	}
}
func (c *Client) chmod2(ctx context.Context, fh []byte, mode uint32) error {
	e, err := handle2(fh)
	if err != nil {
		return err
	}
	sattr2(&e, mode)
	d, err := c.call(ctx, 2, e)
	if err != nil {
		return err
	}
	attr2(d)
	return d.err
}
func (c *Client) create2(ctx context.Context, dir []byte, name string, mode uint32, directory bool) (Node, error) {
	// NFSv2 CREATE has no guarded/exclusive mode. UploadV2 alone may use it
	// inside a freshly reserved private directory; never use it for a target.
	if !directory {
		return Node{}, errors.New("NFSv2 has no guarded file creation; use the staged UploadV2 operation")
	}
	e, err := handle2(dir)
	if err != nil {
		return Node{}, err
	}
	e.str(name)
	sattr2(&e, mode)
	d, err := c.call(ctx, 14, e)
	if err != nil {
		return Node{}, err
	}
	n := Node{Handle: append([]byte(nil), d.take(32)...), Attr: attr2(d)}
	if d.err == nil && len(d.b) != 0 {
		return Node{}, errors.New("trailing NFSv2 object reply data")
	}
	return n, d.err
}
func (c *Client) remove2(ctx context.Context, dir []byte, name string) error {
	e, err := handle2(dir)
	if err != nil {
		return err
	}
	e.str(name)
	_, err = c.call(ctx, 10, e)
	return err
}
func (c *Client) rename2(ctx context.Context, fromDir []byte, from string, toDir []byte, to string) error {
	e, err := handle2(fromDir)
	if err != nil {
		return err
	}
	e.str(from)
	h, err := handle2(toDir)
	if err != nil {
		return err
	}
	e = append(e, h...)
	e.str(to)
	d, err := c.call(ctx, 11, e)
	if err != nil {
		return err
	}
	if len(d.b) != 0 {
		return errors.New("trailing NFSv2 RENAME reply data")
	}
	return d.err
}
