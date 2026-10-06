package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// All key bytes are synthetic test fixtures, never derived from real credentials.
func syntheticEntry(etype uint16, keyLen int, kvno32 bool) []byte {
	return syntheticProfileEntry(account, 2, etype, keyLen, kvno32)
}

func syntheticProfileEntry(accountName string, kvno uint8, etype uint16, keyLen int, kvno32 bool) []byte {
	var b bytes.Buffer
	put := func(value any) { _ = binary.Write(&b, binary.BigEndian, value) }
	put(uint16(1))
	for _, value := range []string{realm, accountName} {
		put(uint16(len(value)))
		b.WriteString(value)
	}
	put(uint32(1))
	put(uint32(1700000000) + uint32(etype))
	put(kvno)
	put(etype)
	put(uint16(keyLen))
	b.Write(bytes.Repeat([]byte{byte(etype)}, keyLen))
	if kvno32 {
		put(uint32(kvno))
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, int32(b.Len()))
	out.Write(b.Bytes())
	return out.Bytes()
}

func syntheticKeytab(kvno32 bool) []byte {
	b := []byte{5, 2}
	b = append(b, syntheticEntry(17, 16, kvno32)...)
	return append(b, syntheticEntry(18, 32, kvno32)...)
}

func TestAliasPreservesAllEntryFields(t *testing.T) {
	for _, extended := range []bool{false, true} {
		t.Run(map[bool]string{false: "kvno8", true: "kvno32"}[extended], func(t *testing.T) {
			input := syntheticKeytab(extended)
			original := bytes.Clone(input)
			output, err := aliasKeytab(input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("input bytes changed")
			}
			before, after := keytab.New(), keytab.New()
			if before.Unmarshal(input) != nil || after.Unmarshal(output) != nil || len(after.Entries) != 2 {
				t.Fatal("invalid test keytab")
			}
			for i, want := range before.Entries {
				got := after.Entries[i]
				if got.Principal.Realm != realm || got.Principal.NumComponents != 2 ||
					strings.Join(got.Principal.Components, "/") != "nfs/"+server ||
					got.Principal.NameType != want.Principal.NameType || !got.Timestamp.Equal(want.Timestamp) ||
					got.KVNO8 != want.KVNO8 || got.KVNO != want.KVNO || got.Key.KeyType != want.Key.KeyType ||
					!bytes.Equal(got.Key.KeyValue, want.Key.KeyValue) {
					t.Fatalf("entry %d did not preserve key metadata and bytes", i)
				}
			}
		})
	}
}

func TestInteropProfileIsExplicitAndPreservesKeys(t *testing.T) {
	for _, kvno := range []int{1, 2, 255} {
		profile, err := selectProfile("interop", kvno)
		if err != nil {
			t.Fatal(err)
		}
		input := append([]byte{5, 2}, syntheticProfileEntry("nv-nfs", uint8(kvno), 17, 16, true)...)
		input = append(input, syntheticProfileEntry("nv-nfs", uint8(kvno), 18, 32, true)...)
		before := keytab.New()
		if err := before.Unmarshal(input); err != nil {
			t.Fatal("bad synthetic input")
		}
		output, err := aliasKeytabFor(input, profile)
		if err != nil {
			t.Fatal(err)
		}
		after := keytab.New()
		if err := after.Unmarshal(output); err != nil || len(after.Entries) != 2 {
			t.Fatal("invalid interop output")
		}
		for i, got := range after.Entries {
			want := before.Entries[i]
			if strings.Join(got.Principal.Components, "/") != "nfs/nfs-interop.msad.nfs.test" ||
				got.Principal.Realm != realm || got.Principal.NameType != want.Principal.NameType ||
				got.KVNO != uint32(kvno) || got.KVNO8 != uint8(kvno) || !got.Timestamp.Equal(want.Timestamp) ||
				got.Key.KeyType != want.Key.KeyType || !bytes.Equal(got.Key.KeyValue, want.Key.KeyValue) {
				t.Fatal("interop fields or keys changed")
			}
		}
		if _, err := aliasKeytab(input); err == nil {
			t.Fatal("legacy accepted interop account")
		}
		if _, err := aliasKeytabFor(syntheticKeytab(true), profile); err == nil {
			t.Fatal("interop accepted legacy account")
		}
	}
	for _, tc := range []struct {
		name string
		kvno int
	}{{"interop", 0}, {"interop", -1}, {"interop", 256}, {"legacy", 1}, {"other", 2}} {
		if _, err := selectProfile(tc.name, tc.kvno); err == nil {
			t.Fatal("invalid profile/KVNO accepted")
		}
	}
}

func TestAliasRejectsMalformedOrUnexpectedEntries(t *testing.T) {
	good := syntheticKeytab(true)
	// Fixed offsets in the independently written synthetic first entry.
	tail := 2 + 4 + 2 + 2 + len(realm) + 2 + len(account)
	mutate := func(offset int, value byte) []byte {
		b := bytes.Clone(good)
		b[offset] = value
		return b
	}
	cases := map[string][]byte{
		"version1":           mutate(1, 1),
		"wrong-account":      bytes.ReplaceAll(good, []byte(account), []byte("bad-nfs")),
		"wrong-realm":        bytes.ReplaceAll(good, []byte(realm), []byte("msad.nfs.test")),
		"component-count":    mutate(7, 2),
		"negative-length":    mutate(2, 0xff),
		"zero-length":        append([]byte{5, 2, 0, 0, 0, 0}, good[2:]...),
		"overflow-length":    mutate(2, 0x7f),
		"wrong-kvno8":        mutate(tail+8, 3),
		"wrong-kvno32":       mutate(tail+13+16+3, 3),
		"unexpected-enctype": mutate(tail+10, 23),
		"wrong-key-length":   mutate(tail+12, 15),
		"trailing-byte":      append(bytes.Clone(good), 0),
		"trailing-marker":    append(bytes.Clone(good), 0, 0, 0, 0),
		"oversize":           bytes.Repeat([]byte{'x'}, maxInput+1),
		"duplicate":          append(append([]byte{5, 2}, syntheticEntry(17, 16, true)...), syntheticEntry(17, 16, true)...),
		"only-one":           append([]byte{5, 2}, syntheticEntry(17, 16, true)...),
		"three-entries":      append(bytes.Clone(good), syntheticEntry(18, 32, true)...),
		"aes128-short-key":   append(append([]byte{5, 2}, syntheticEntry(17, 15, true)...), syntheticEntry(18, 32, true)...),
		"aes256-short-key":   append(append([]byte{5, 2}, syntheticEntry(17, 16, true)...), syntheticEntry(18, 31, true)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := aliasKeytab(data)
			if err != errInput || out != nil {
				t.Fatal("expected sanitized input refusal without output")
			}
		})
	}
	for n := range len(good) {
		if output, err := aliasKeytab(good[:n]); err == nil || output != nil {
			t.Fatalf("truncated input of length %d accepted", n)
		}
	}
}

func TestInteropCLIRequiresMatchingExplicitKVNO(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.kt")
	original := append([]byte{5, 2}, syntheticProfileEntry("nv-nfs", 255, 17, 16, true)...)
	original = append(original, syntheticProfileEntry("nv-nfs", 255, 18, 32, true)...)
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "service.kt")
	for _, flags := range [][]string{{}, {"-profile", "interop"}, {"-profile", "interop", "-kvno", "2"}} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"-input", input, "-output", output}, flags...)
		if run(args, &stdout, &stderr) == 0 || stdout.Len() != 0 {
			t.Fatal("mismatched or implicit profile/KVNO accepted")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("refused interop input created output")
		}
	}
	var stdout, stderr bytes.Buffer
	args := []string{"-input", input, "-output", output, "-profile", "interop", "-kvno", "255"}
	if run(args, &stdout, &stderr) != 0 || stderr.Len() != 0 {
		t.Fatal("explicit interop profile failed")
	}
	if stdout.String() != "Created service keytab: two AES entries, KVNO 255; source preserved.\n" {
		t.Fatal("unexpected interop CLI output")
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if run(args, &stdout, &stderr) == 0 {
		t.Fatal("existing interop output accepted")
	}
	if after, err := os.ReadFile(output); err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing interop output changed")
	}
	if after, err := os.ReadFile(input); err != nil || !bytes.Equal(original, after) {
		t.Fatal("interop source changed")
	}
}

func TestConvertCreatesPrivateOutputAndPreservesSource(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "source.kt"), filepath.Join(dir, "service.kt")
	original := syntheticKeytab(true)
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", input, "-output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stdout.String() != "Created service keytab: two AES entries, KVNO 2; source preserved.\n" || stderr.Len() != 0 {
		t.Fatal("unexpected CLI output")
	}
	got, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("source file changed")
	}
	want, err := aliasKeytab(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(output)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("output file differs from verified encoding")
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("output must be regular")
	}
	// Windows mode bits do not represent ACLs; the runtime directory owns that policy.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatal("output is not mode 0600")
	}
}

func TestConvertRefusesExistingPathsAndInvalidInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.kt")
	original := syntheticKeytab(true)
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := convert(input, input); err == nil {
		t.Fatal("same input/output accepted")
	}
	alias := filepath.Join(dir, "hardlink.kt")
	if err := os.Link(input, alias); err != nil {
		t.Fatal(err)
	}
	if err := convert(input, alias); err == nil {
		t.Fatal("hard-linked source accepted as output")
	}
	output := filepath.Join(dir, "existing.kt")
	sentinel := []byte("synthetic-existing-file")
	if err := os.WriteFile(output, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := convert(input, output); err == nil {
		t.Fatal("existing output accepted")
	}
	if got, err := os.ReadFile(output); err != nil || !bytes.Equal(got, sentinel) {
		t.Fatal("existing output changed")
	}
	if err := convert(input, dir); err == nil {
		t.Fatal("output directory accepted")
	}
	newOutput := filepath.Join(dir, "absent.kt")
	if err := convert(dir, newOutput); err == nil {
		t.Fatal("input directory accepted")
	}
	bad := filepath.Join(dir, "bad.kt")
	if err := os.WriteFile(bad, []byte("synthetic-secret-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if run([]string{"-input", bad, "-output", newOutput}, &stdout, &stderr) != 1 || stdout.Len() != 0 ||
		strings.Contains(stderr.String(), "synthetic-secret-marker") {
		t.Fatal("invalid input did not fail with sanitized diagnostics")
	}
	if _, err := os.Lstat(newOutput); !os.IsNotExist(err) {
		t.Fatal("invalid input created output")
	}
	if err := os.WriteFile(bad, bytes.Repeat([]byte{'x'}, maxInput+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := convert(bad, newOutput); err == nil {
		t.Fatal("oversized input file accepted")
	}
	if _, err := os.Lstat(newOutput); !os.IsNotExist(err) {
		t.Fatal("oversized input created output")
	}
	if got, err := os.ReadFile(input); err != nil || !bytes.Equal(got, original) {
		t.Fatal("source changed after refusals")
	}
}

func FuzzAliasKeytab(f *testing.F) {
	f.Add(syntheticKeytab(false))
	f.Add(syntheticKeytab(true))
	f.Add([]byte{5, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		original := bytes.Clone(data)
		out, err := aliasKeytab(data)
		if !bytes.Equal(data, original) {
			t.Fatal("input mutated")
		}
		if err != nil {
			if out != nil || err != errInput {
				t.Fatal("unexpected failure output")
			}
			return
		}
		if len(out) > maxInput || len(out) < 2 || out[0] != 5 || out[1] != 2 {
			t.Fatal("invalid successful encoding")
		}
	})
}
