package gssapi

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cacheData(b []byte, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}
func cachePrincipal(b []byte, realm string, parts ...string) []byte {
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint32(b, uint32(len(parts)))
	b = cacheData(b, []byte(realm))
	for _, p := range parts {
		b = cacheData(b, []byte(p))
	}
	return b
}
func syntheticCCache(version byte, client string) []byte {
	b := []byte{5, version}
	if version == 4 {
		b = append(b, 0, 0)
	}
	b = cachePrincipal(b, "NFS.TEST", "root")
	b = cachePrincipal(b, "NFS.TEST", client)
	b = cachePrincipal(b, "NFS.TEST", "krbtgt", "NFS.TEST")
	b = binary.BigEndian.AppendUint16(b, 18)
	if version == 3 {
		b = binary.BigEndian.AppendUint16(b, 18)
	}
	b = cacheData(b, bytes.Repeat([]byte{0x42}, 32))
	for _, v := range []int64{1700000000, 1700000000, 1700003600, 1700007200} {
		b = binary.BigEndian.AppendUint32(b, uint32(v))
	}
	b = append(b, 0)
	b = append(b, make([]byte, 12)...)
	b = cacheData(b, []byte("synthetic ticket bytes, not a real credential"))
	return cacheData(b, nil)
}

func TestCCacheBoundsAndIdentity(t *testing.T) {
	for _, version := range []byte{3, 4} {
		wire := syntheticCCache(version, "root")
		c, err := parseCCache(wire)
		if err != nil {
			t.Fatal(err)
		}
		if c.DefaultPrincipal.Realm != "NFS.TEST" || len(c.Credentials) != 1 || len(c.Credentials[0].Key.KeyValue) != 32 || !c.Credentials[0].EndTime.Equal(time.Unix(1700003600, 0)) {
			t.Fatal("wrong cache decoding")
		}
		for i := 0; i < len(wire); i++ {
			if _, err := parseCCache(wire[:i]); err == nil {
				t.Fatalf("accepted truncated v%d cache at %d", version, i)
			}
		}
		if _, err := parseCCache(append(wire, 0)); err == nil {
			t.Fatal("accepted trailing partial entry")
		}
	}
	if _, err := parseCCache(syntheticCCache(4, "another-client")); err == nil {
		t.Fatal("mixed principals accepted")
	}
	if _, err := parseCCache(syntheticCCache(4, strings.Repeat("a", 4097))); err == nil {
		t.Fatal("oversized principal accepted")
	}
	if _, err := parseCCache(make([]byte, maxCCacheSize+1)); err == nil {
		t.Fatal("oversized cache accepted")
	}
	for _, version := range []byte{0, 1, 2, 5} {
		if _, err := parseCCache([]byte{5, version}); err == nil {
			t.Fatal("unsupported format accepted")
		}
	}
	wire := syntheticCCache(4, "root")
	binary.BigEndian.PutUint32(wire[8:12], 0xffffffff)
	if _, err := parseCCache(wire); err == nil {
		t.Fatal("oversized component count accepted")
	}
}

func TestCCacheHeaderAndFileSelection(t *testing.T) {
	base := syntheticCCache(4, "root")
	for _, header := range [][]byte{{0, 99, 0, 3, 1, 2, 3}, {0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0}} {
		wire := append([]byte{5, 4, 0, byte(len(header))}, header...)
		wire = append(wire, base[4:]...)
		if _, err := parseCCache(wire); err != nil {
			t.Fatal(err)
		}
	}
	for _, header := range [][]byte{{0, 1, 0, 1, 0}, {0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0}, {0, 1, 0, 8, 0}, {0}} {
		wire := append([]byte{5, 4, 0, byte(len(header))}, header...)
		wire = append(wire, base[4:]...)
		if _, err := parseCCache(wire); err == nil {
			t.Fatal("invalid/unsupported header accepted")
		}
	}
	file := filepath.Join(t.TempDir(), "cache.file")
	if err := os.WriteFile(file, base, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCCache("FILE:" + file); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"DIR:" + file, "KCM:123", filepath.Dir(file)} {
		if _, err := readCCache(path); err == nil {
			t.Fatal("non-FILE source accepted")
		}
	}
	// Parsing must not retain aliases into the input that readCCache clears.
	c, err := parseCCache(base)
	if err != nil {
		t.Fatal(err)
	}
	clear(base)
	if len(c.Credentials[0].Ticket) == 0 || c.Credentials[0].Key.KeyValue[0] != 0x42 {
		t.Fatal("cache aliases cleared input")
	}
}

func FuzzParseCCache(f *testing.F) {
	f.Add(syntheticCCache(4, "root"))
	f.Add(syntheticCCache(3, "root"))
	f.Add([]byte{5, 4, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseCCache(b) })
}
