package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// Independent kernel fixture with immutable FILE-v4 bytes and direct-child
// membership. No production keyctl or cacheReader is used to construct it.
type keyringFixture struct {
	mode         string
	payload      map[int][]byte
	reads, lists map[int]int
	descriptions map[int]kernelKeyDescription
}

func newKeyringFixture(mode string) *keyringFixture {
	w := syntheticCCache(4, "root")
	n := 8
	count := int(binary.BigEndian.Uint32(w[8:12]))
	for i := 0; i <= count; i++ {
		n += 4 + int(binary.BigEndian.Uint32(w[4+n:8+n]))
	}
	return &keyringFixture{mode: mode, payload: map[int][]byte{4: bytes.Clone(w[4 : 4+n]), 5: bytes.Clone(w[4+n:]), 6: make([]byte, 8)}, reads: map[int]int{}, lists: map[int]int{}, descriptions: map[int]kernelKeyDescription{2: {"keyring", "_krb_collection", 1000}, 3: {"keyring", "cache", 1000}, 4: {"user", "__krb5_princ__", 1000}, 5: {"big_key", "krbtgt/NFS.TEST@NFS.TEST", 1000}, 6: {"user", "__krb5_time_offsets__", 1000}}}
}
func (f *keyringFixture) anchor(name string) (int, error) {
	if name != "session" {
		return 0, errors.New("wrong anchor")
	}
	return 1, nil
}
func (f *keyringFixture) list(id, limit int) ([]int, error) {
	f.lists[id]++
	ids := map[int][]int{1: {2}, 2: {3}, 3: {4, 5, 6}}[id]
	if id == 3 {
		switch f.mode {
		case "missing-principal":
			ids = []int{5, 6}
		case "empty":
			ids = []int{4, 6}
		case "duplicate-id":
			ids = []int{4, 5, 5, 6}
		case "membership-change":
			if f.lists[id] > 1 {
				ids = []int{4, 6}
			}
		case "many":
			ids = make([]int, 67)
		}
	}
	if f.mode == "duplicate-path" && id == 1 {
		ids = []int{2, 7}
		f.descriptions[7] = f.descriptions[2]
	}
	if f.mode == "path-change" && id == 2 && f.lists[id] > 1 {
		ids = []int{8}
		f.descriptions[8] = f.descriptions[3]
	}
	if len(ids) > limit {
		return nil, errors.New("key count bound")
	}
	return ids, nil
}
func (f *keyringFixture) describe(id int) (kernelKeyDescription, error) {
	d := f.descriptions[id]
	if f.mode == "foreign-ring" && id == 2 || f.mode == "foreign-credential" && id == 5 {
		d.uid = 2000
	}
	if f.mode == "nested-ring" && id == 5 {
		d.kind = "keyring"
	}
	if f.mode == "wrong-principal-type" && id == 4 {
		d.kind = "big_key"
	}
	if f.mode == "description-change" && id == 5 && f.reads[id] > 0 {
		d.name = "changed"
	}
	if f.mode == "denied" {
		return d, errors.New("permission denied")
	}
	return d, nil
}
func (f *keyringFixture) read(id int) ([]byte, error) {
	f.reads[id]++
	b := bytes.Clone(f.payload[id])
	switch f.mode {
	case "credential-change":
		if id == 5 && f.reads[id] > 1 {
			b[len(b)-1] ^= 1
		}
	case "offset":
		if id == 6 {
			b[7] = 1
		}
	case "offset-short":
		if id == 6 {
			b = b[:7]
		}
	case "principal-trailing":
		if id == 4 {
			b = append(b, 0)
		}
	case "credential-double":
		if id == 5 {
			b = append(b, b...)
		}
	case "credential-truncated":
		if id == 5 {
			b = b[:len(b)-1]
		}
	case "large":
		if id == 5 {
			b = make([]byte, maxCCacheSize)
		}
	case "revoked":
		if id == 5 && f.reads[id] > 1 {
			return nil, errors.New("key revoked")
		}
	}
	return b, nil
}
func TestKEYRINGSnapshot(t *testing.T) {
	for _, mode := range []string{"success", "missing-principal", "empty", "duplicate-id", "membership-change", "many", "duplicate-path", "path-change", "foreign-ring", "foreign-credential", "nested-ring", "wrong-principal-type", "description-change", "denied", "credential-change", "offset", "offset-short", "principal-trailing", "credential-double", "credential-truncated", "large", "revoked", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			c, err := readKeyringSnapshot(ctx, newKeyringFixture(mode), keyringSelection{"session", "collection", "cache"}, 1000)
			if (err == nil) != (mode == "success") {
				t.Fatal("wrong snapshot result", err)
			}
			if err == nil && (c.DefaultPrincipal.Realm != "NFS.TEST" || len(c.Credentials) != 1 || !bytes.Equal(c.Credentials[0].Key.KeyValue, bytes.Repeat([]byte{0x42}, 32))) {
				t.Fatal("wrong credentials")
			}
		})
	}
}
func TestKEYRINGSelectionBounds(t *testing.T) {
	for i, name := range []string{"KEYRING:", "KEYRING:session:c", "KEYRING:thread:c:s", "KEYRING:session::s", "KEYRING:session:c:s\x00", "KEYRING:session:c:s;bad", "KEYRING:persistent::cache", "KEYRING:persistent:01:cache", "KEYRING:persistent:-1:cache", "KEYRING:persistent:4294967295:cache", "KEYRING:persistent:4294967296:cache", "KEYRING:persistent:uid:cache"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := parseKeyringName(name); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
	for _, anchor := range []string{"session", "process", "user"} {
		if _, err := parseKeyringName("KEYRING:" + anchor + ":c:s"); err != nil {
			t.Fatal(err)
		}
	}
}
