// keytabalias is an offline, fixed-principal Microsoft AD fixture helper.
// It relabels existing MIT-derived keys; it never derives or prints key material.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

const (
	maxInput = 8 * 1024
	realm    = "MSAD.NFS.TEST"
	account  = "svc-nfs"
	server   = "nfs.msad.nfs.test"
)

var errInput = errors.New("input must contain exactly two complete v2 account entries with the selected realm, KVNO and AES128/AES256 keys")

type aliasProfile struct {
	account string
	server  string
	kvno    uint8
}

func selectProfile(name string, kvno int) (aliasProfile, error) {
	if name == "legacy" {
		if kvno != 0 && kvno != 2 {
			return aliasProfile{}, errors.New("legacy profile requires KVNO 2")
		}
		return aliasProfile{account: account, server: server, kvno: 2}, nil
	}
	if name != "interop" || kvno < 1 || kvno > 255 {
		return aliasProfile{}, errors.New("interop profile requires an explicit KVNO between 1 and 255; unknown profiles are refused")
	}
	return aliasProfile{account: "nv-nfs", server: "nfs-interop.msad.nfs.test", kvno: uint8(kvno)}, nil
}

// validateWireFor checks the narrow, fresh MIT keytab shape before gokrb5 parses it.
// The dependency accepts some trailing data and includes input bytes in errors.
// Holes, end markers, padding and unknown extensions are deliberately refused.
// Format: https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html
func validateWireFor(data []byte, profile aliasProfile) error {
	if len(data) < 2 || len(data) > maxInput || data[0] != 5 || data[1] != 2 {
		return errInput
	}
	remaining := data[2:]
	seen := map[uint16]bool{}
	for len(remaining) != 0 {
		if len(seen) == 2 || len(remaining) < 4 {
			return errInput
		}
		size := int32(binary.BigEndian.Uint32(remaining[:4]))
		remaining = remaining[4:]
		if size <= 0 || int64(size) > int64(len(remaining)) {
			return errInput
		}
		record := remaining[:int(size)]
		remaining = remaining[int(size):]
		if len(record) < 2 || binary.BigEndian.Uint16(record[:2]) != 1 {
			return errInput
		}
		record = record[2:]
		for _, expected := range []string{realm, profile.account} {
			if len(record) < 2 {
				return errInput
			}
			size := int(binary.BigEndian.Uint16(record[:2]))
			record = record[2:]
			if size != len(expected) || size > len(record) || string(record[:size]) != expected {
				return errInput
			}
			record = record[size:]
		}
		// name type (4), timestamp (4), KVNO8 (1), enctype (2), key length (2).
		if len(record) < 13 || record[8] != profile.kvno {
			return errInput
		}
		etype := binary.BigEndian.Uint16(record[9:11])
		keySize := int(binary.BigEndian.Uint16(record[11:13]))
		if seen[etype] || (etype != 17 && etype != 18) || keySize != map[uint16]int{17: 16, 18: 32}[etype] {
			return errInput
		}
		record = record[13:]
		if keySize > len(record) {
			return errInput
		}
		record = record[keySize:]
		if len(record) != 0 {
			if len(record) != 4 {
				return errInput
			}
			kvno := binary.BigEndian.Uint32(record)
			if kvno != 0 && kvno != uint32(profile.kvno) {
				return errInput
			}
		}
		seen[etype] = true
	}
	if len(seen) != 2 {
		return errInput
	}
	return nil
}

func aliasKeytab(data []byte) ([]byte, error) {
	profile, _ := selectProfile("legacy", 2)
	return aliasKeytabFor(data, profile)
}

func aliasKeytabFor(data []byte, profile aliasProfile) ([]byte, error) {
	if err := validateWireFor(data, profile); err != nil {
		return nil, err
	}
	kt := keytab.New()
	if err := kt.Unmarshal(data); err != nil || len(kt.Entries) != 2 {
		// Never propagate dependency errors, which can contain raw keytab bytes.
		return nil, errInput
	}
	for i := range kt.Entries {
		entry := &kt.Entries[i]
		if entry.Principal.Realm != realm || len(entry.Principal.Components) != 1 ||
			entry.Principal.Components[0] != profile.account || entry.KVNO8 != profile.kvno || entry.KVNO != uint32(profile.kvno) {
			return nil, errInput
		}
		entry.Principal.Components = []string{"nfs", profile.server}
		entry.Principal.NumComponents = 2
	}
	encoded, err := kt.Marshal()
	if err != nil {
		return nil, errors.New("cannot encode service keytab")
	}
	// Independently decode the output and verify every entry field after encoding.
	check := keytab.New()
	if err := check.Unmarshal(encoded); err != nil || len(check.Entries) != len(kt.Entries) {
		return nil, errors.New("cannot verify service keytab encoding")
	}
	for i, want := range kt.Entries {
		got := check.Entries[i]
		if got.Principal.Realm != realm || got.Principal.NumComponents != 2 ||
			len(got.Principal.Components) != 2 || got.Principal.Components[0] != "nfs" ||
			got.Principal.Components[1] != profile.server || got.Principal.NameType != want.Principal.NameType ||
			got.KVNO != want.KVNO || got.KVNO8 != want.KVNO8 || !got.Timestamp.Equal(want.Timestamp) ||
			got.Key.KeyType != want.Key.KeyType || !bytes.Equal(got.Key.KeyValue, want.Key.KeyValue) {
			return nil, errors.New("service keytab preservation check failed")
		}
	}
	return encoded, nil
}

func readRegular(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 2 || before.Size() > maxInput {
		return nil, errors.New("input must be a regular file between 2 and 8192 bytes")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open input file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("input file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxInput+1))
	if err != nil || len(data) > maxInput || int64(len(data)) != before.Size() {
		return nil, errors.New("cannot read bounded input file")
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("input file changed while reading")
	}
	return data, nil
}

func convert(input, output string) error {
	profile, _ := selectProfile("legacy", 2)
	return convertFor(input, output, profile)
}

func convertFor(input, output string, profile aliasProfile) error {
	in, err := filepath.Abs(input)
	if err != nil {
		return errors.New("invalid input path")
	}
	out, err := filepath.Abs(output)
	if err != nil {
		return errors.New("invalid output path")
	}
	if in == out || (runtime.GOOS == "windows" && strings.EqualFold(in, out)) {
		return errors.New("input and output must be different files")
	}
	data, err := readRegular(in)
	if err != nil {
		return err
	}
	encoded, err := aliasKeytabFor(data, profile)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot exclusively create output; existing paths are never replaced")
	}
	owned, statErr := f.Stat()
	complete := false
	defer func() {
		_ = f.Close()
		// Remove only the incomplete file created by this call, never a replacement.
		if !complete && owned != nil {
			current, err := os.Lstat(out)
			if err == nil && current.Mode().IsRegular() && os.SameFile(owned, current) {
				_ = os.Remove(out)
			}
		}
	}()
	if statErr != nil || !owned.Mode().IsRegular() {
		return errors.New("output is not a regular file")
	}
	if err := f.Chmod(0o600); err != nil {
		return errors.New("cannot restrict output permissions")
	}
	if written, err := f.Write(encoded); err != nil || written != len(encoded) {
		return errors.New("cannot write complete service keytab")
	}
	if err := f.Sync(); err != nil {
		return errors.New("cannot sync service keytab")
	}
	if err := f.Close(); err != nil {
		return errors.New("cannot close service keytab")
	}
	complete = true
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("keytabalias", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "native svc-nfs account keytab")
	output := flags.String("output", "", "new service keytab (must not exist)")
	profileName := flags.String("profile", "legacy", "fixed fixture profile: legacy or interop")
	kvno := flags.Int("kvno", 0, "actual account KVNO, required for interop (1..255); legacy is fixed at 2")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *input == "" || *output == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "require -input and -output, with no positional arguments")
		return 2
	}
	profile, err := selectProfile(*profileName, *kvno)
	if err != nil {
		fmt.Fprintln(stderr, "keytabalias:", err)
		return 2
	}
	if err := convertFor(*input, *output, profile); err != nil {
		fmt.Fprintln(stderr, "keytabalias:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Created service keytab: two AES entries, KVNO %d; source preserved.\n", profile.kvno)
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
