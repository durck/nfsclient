package gssapi

import (
	"bytes"
	stdcontext "context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

type keyringSelection struct{ anchor, collection, cache string }

func parseKeyringName(name string) (keyringSelection, error) {
	p := strings.Split(name, ":")
	if len(p) != 4 || p[0] != "KEYRING" || (p[1] != "session" && p[1] != "process" && p[1] != "user" && p[1] != "persistent") {
		return keyringSelection{}, errors.New("KEYRING requires explicit session/process/user collection and cache, or persistent UID and cache")
	}
	for _, s := range p[2:] {
		if s == "" || len(s) > 256 || !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n;") {
			return keyringSelection{}, errors.New("KEYRING collection/cache must be nonempty names of at most 256 bytes without controls or semicolons")
		}
	}
	if p[1] == "persistent" {
		uid, err := strconv.ParseUint(p[2], 10, 32)
		if err != nil || uid == 1<<32-1 || strconv.FormatUint(uid, 10) != p[2] {
			return keyringSelection{}, errors.New("persistent KEYRING requires an explicit canonical UID")
		}
	}
	return keyringSelection{p[1], p[2], p[3]}, nil
}

type kernelKeyDescription struct {
	kind, name string
	uid        uint32
}
type keyringSource interface {
	anchor(string) (int, error)
	list(int, int) ([]int, error)
	describe(int) (kernelKeyDescription, error)
	read(int) ([]byte, error)
}

// Resolve only direct children: recursive KEYCTL_SEARCH could select a cache
// reachable through an unrelated collection. No primary/default name is read.
func selectedKeyring(s keyringSource, parent int, name string, uid uint32) (int, error) {
	ids, err := s.list(parent, 4096)
	if err != nil {
		return 0, err
	}
	found := 0
	for _, id := range ids {
		d, err := s.describe(id)
		if err != nil {
			return 0, err
		}
		if d.kind != "keyring" || d.name != name {
			continue
		}
		if d.uid != uid || found != 0 {
			return 0, errors.New("KEYRING selected ring has a foreign owner or ambiguous name")
		}
		found = id
	}
	if found == 0 {
		return 0, errors.New("KEYRING selected collection/cache does not exist")
	}
	return found, nil
}

// MIT KEYRING stores FILE-v4 principal and single-credential payloads in user/
// big_key children. A second pass detects membership, payload and path changes.
func readKeyringSnapshot(ctx stdcontext.Context, s keyringSource, selection keyringSelection, uid uint32) (*credentials.CCache, error) {
	if ctx == nil {
		ctx = stdcontext.Background()
	}
	resolve := func() (int, int, int, error) {
		if err := ctx.Err(); err != nil {
			return 0, 0, 0, err
		}
		var a int
		var err error
		collection := "_krb_" + selection.collection
		if selection.anchor == "persistent" {
			if selection.collection != strconv.FormatUint(uint64(uid), 10) {
				return 0, 0, 0, errors.New("persistent KEYRING UID must match the current effective UID")
			}
			persistent, ok := s.(interface{ persistent(uint32) (int, error) })
			if !ok {
				return 0, 0, 0, errors.New("persistent KEYRING unavailable")
			}
			a, err = persistent.persistent(uid)
			// MIT stores every per-UID persistent collection under _krb,
			// not the _krb_<collection> name used by other anchor types.
			collection = "_krb"
		} else {
			a, err = s.anchor(selection.anchor)
		}
		if err != nil {
			return 0, 0, 0, err
		}
		c, err := selectedKeyring(s, a, collection, uid)
		if err != nil {
			return 0, 0, 0, err
		}
		k, err := selectedKeyring(s, c, selection.cache, uid)
		return a, c, k, err
	}
	a, c, k, err := resolve()
	if err != nil {
		return nil, err
	}
	ids, err := s.list(k, 66)
	if err != nil {
		return nil, err
	}
	values := make([][]byte, len(ids))
	descriptions := make([]kernelKeyDescription, len(ids))
	defer func() {
		for _, b := range values {
			clear(b)
		}
	}()
	principalIndex, offsetIndex := -1, -1
	credentialIndices := []int{}
	seen := map[int]bool{}
	total := 0
	for i, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if id <= 0 || seen[id] {
			return nil, errors.New("KEYRING duplicate or invalid child ID")
		}
		seen[id] = true
		d, err := s.describe(id)
		if err != nil {
			return nil, err
		}
		if d.uid != uid || (d.kind != "user" && d.kind != "big_key") {
			return nil, errors.New("KEYRING credential has a foreign owner or unsupported key type")
		}
		descriptions[i] = d
		switch d.name {
		case "__krb5_princ__":
			if principalIndex != -1 || d.kind != "user" {
				return nil, errors.New("KEYRING invalid principal key")
			}
			principalIndex = i
		case "__krb5_time_offsets__":
			if offsetIndex != -1 || d.kind != "user" {
				return nil, errors.New("KEYRING invalid clock offset key")
			}
			offsetIndex = i
		default:
			credentialIndices = append(credentialIndices, i)
		}
		values[i], err = s.read(id)
		if err != nil {
			return nil, err
		}
		if len(values[i]) > maxCCacheSize-4-total {
			return nil, errors.New("KEYRING snapshot exceeds 4 MiB")
		}
		total += len(values[i])
	}
	if principalIndex < 0 || len(credentialIndices) == 0 || len(credentialIndices) > 64 {
		return nil, errors.New("KEYRING requires a principal and 1..64 credentials")
	}
	principal := values[principalIndex]
	p := &cacheReader{b: principal}
	p.principal()
	if p.err != nil || len(p.b) != 0 {
		return nil, errors.New("KEYRING principal is malformed")
	}
	if offsetIndex >= 0 && !bytes.Equal(values[offsetIndex], make([]byte, 8)) {
		return nil, errors.New("KEYRING clock offset is malformed or nonzero; synchronize clocks")
	}
	cache := make([]byte, 4, maxCCacheSize)
	copy(cache, []byte{5, 4, 0, 0})
	defer func() { clear(cache) }()
	if len(principal) > maxCCacheSize-len(cache) {
		return nil, errors.New("KEYRING principal exceeds snapshot budget")
	}
	cache = append(cache, principal...)
	for _, i := range credentialIndices {
		b := values[i]
		if len(b) > maxCCacheSize-len(cache) {
			return nil, errors.New("KEYRING snapshot exceeds 4 MiB")
		}
		one := make([]byte, 4+len(principal)+len(b))
		copy(one, []byte{5, 4, 0, 0})
		copy(one[4:], principal)
		copy(one[4+len(principal):], b)
		parsed, err := parseCCache(one)
		clear(one)
		if err != nil {
			return nil, err
		}
		for _, cred := range parsed.Credentials {
			clear(cred.Key.KeyValue)
			clear(cred.Ticket)
			clear(cred.SecondTicket)
		}
		if len(parsed.Credentials) != 1 {
			return nil, errors.New("KEYRING child must contain exactly one credential")
		}
		cache = append(cache, b...)
	}
	for i, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d, err := s.describe(id)
		if err != nil || d != descriptions[i] {
			return nil, fmt.Errorf("KEYRING key description changed: %v", err)
		}
		after, err := s.read(id)
		if err != nil {
			return nil, err
		}
		same := bytes.Equal(after, values[i])
		clear(after)
		if !same {
			return nil, errors.New("KEYRING credential changed during snapshot")
		}
	}
	after, err := s.list(k, 66)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(ids, after) {
		return nil, errors.New("KEYRING membership changed during snapshot")
	}
	aa, cc, kk, err := resolve()
	if err != nil {
		return nil, err
	}
	if aa != a || cc != c || kk != k {
		return nil, errors.New("KEYRING selected path changed during snapshot")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return parseCCache(cache)
}
