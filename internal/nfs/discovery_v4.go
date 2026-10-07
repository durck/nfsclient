package nfs

import (
	"bytes"
	"context"
	"errors"
)

type discoveryChild struct {
	Entry
	Err error
}

// Read minimal attributes, including rdattr_error: a denied or relocated child
// must not hide its accessible siblings. The budget counts files too, so a
// directory containing millions of files cannot evade the discovery limit.
func (v *v4Client) discoveryChildren(ctx context.Context, fh []byte, limit int) ([]discoveryChild, int, error) {
	var entries []discoveryChild
	var cookie uint64
	verifier := make([]byte, 8)
	seenCookies := map[uint64]bool{}
	seenNames := map[string]bool{}
	used := 0
	for {
		if err := ctx.Err(); err != nil {
			return entries, used, err
		}
		var req encoder
		req.u64(cookie)
		req = append(req, verifier...)
		maxCount := uint32(4096)
		if v.channel.Response == 0 && v.maxReplyPayload != 0 {
			maxCount = min(maxCount, v.maxReplyPayload)
		}
		req.u32(maxCount)
		req.u32(maxCount)
		bitmap4(&req, 1, 8, 11, 19, 20)
		old := cookie
		var page []discoveryChild
		var nextVerifier []byte
		eof, limited := false, false
		err := v.compound(ctx, fh4(fh), op4(26, req, func(d *decoder) {
			nextVerifier = append([]byte(nil), d.take(8)...)
			for d.boolean() && d.err == nil {
				cookie = d.u64()
				entry := discoveryChild{Entry: Entry{Name: d.str()}}
				bits := readBitmap4(d)
				a := &decoder{b: d.opaque(65536)}
				for _, bit := range bits {
					switch bit {
					case 11:
						if status := a.u32(); status != 0 {
							entry.Err = Status(status)
						}
					case 19:
						entry.Handle = append([]byte(nil), a.opaque(128)...)
					case 1, 8, 20:
						decodeAttr4(&entry.Attr, bit, a)
					default:
						a.err = errors.New("unsolicited discovery attribute")
					}
				}
				if a.err != nil {
					d.err = a.err
					return
				}
				if len(a.b) != 0 {
					d.err = errors.New("trailing discovery attributes")
					return
				}
				if entry.Name == "." || entry.Name == ".." {
					continue
				}
				if !validDiscoveryName(entry.Name) {
					d.err = errors.New("invalid discovery entry name")
					return
				}
				if seenNames[entry.Name] {
					d.err = errors.New("directory changed: repeated discovery name")
					return
				}
				if used+len(page) >= limit {
					limited = true
					continue
				}
				seenNames[entry.Name] = true
				page = append(page, entry)
			}
			eof = d.boolean()
		}))
		if err != nil {
			return entries, used, err
		}
		if old != 0 && !bytes.Equal(verifier, nextVerifier) {
			return entries, used, errors.New("directory changed: discovery cookie verifier changed")
		}
		verifier = nextVerifier
		used += len(page)
		for _, entry := range page {
			if entry.Err == nil && (len(entry.Handle) == 0 || entry.Attr.Type == 0) {
				entry.Node, entry.Err = v.lookup(ctx, fh, entry.Name)
			}
			entries = append(entries, entry)
		}
		if limited || used == limit && !eof {
			return entries, used, errDiscoveryLimit
		}
		if eof {
			return entries, used, nil
		}
		if cookie == old || seenCookies[cookie] {
			return entries, used, errors.New("discovery listing made no progress")
		}
		seenCookies[cookie] = true
	}
}
