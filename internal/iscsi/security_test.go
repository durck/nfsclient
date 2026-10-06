package iscsi

import (
	"bytes"
	"context"
	"encoding/binary"
	"nfsclient/internal/testiscsi"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func securityFixture(t *testing.T, auth string) (Security, testiscsi.Options) {
	t.Helper()
	dir := t.TempDir()
	a := []byte("initiator-secret-unique")
	b := []byte("target-secret-distinct")
	s := Security{AuthMethod: auth}
	o := testiscsi.Options{AllowProcessKill: true}
	if auth != "none" {
		s.Username = "initiator"
		s.SecretFile = filepath.Join(dir, "initiator.secret")
		if err := os.WriteFile(s.SecretFile, a, 0600); err != nil {
			t.Fatal(err)
		}
		o.CHAPUsername = s.Username
		o.CHAPSecret = a
	}
	if auth == "mutual-chap" {
		s.TargetUsername = "target"
		s.TargetSecretFile = filepath.Join(dir, "target.secret")
		if err := os.WriteFile(s.TargetSecretFile, b, 0600); err != nil {
			t.Fatal(err)
		}
		o.TargetUsername = s.TargetUsername
		o.TargetSecret = b
	}
	return s, o
}

func TestAuthenticatedStorage(t *testing.T) {
	for _, auth := range []string{"none", "chap", "mutual-chap"} {
		for _, digests := range []string{"none", "header", "data", "both"} {
			t.Run(auth+"/"+digests, func(t *testing.T) {
				policy, opts := securityFixture(t, auth)
				if digests == "header" || digests == "both" {
					policy.HeaderDigest = "crc32c"
					opts.HeaderDigest = true
				}
				if digests == "data" || digests == "both" {
					policy.DataDigest = "crc32c"
					opts.DataDigest = true
				}
				path := filepath.Join(t.TempDir(), "disk")
				before := bytes.Repeat([]byte{0x72}, 131072)
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
				peer := testiscsi.Start(t, path, opts)
				target, err := ParseTarget(peer.URL())
				if err != nil {
					t.Fatal(err)
				}
				v, err := OpenWithSecurity(context.Background(), target, testiscsi.Initiator, time.Second, true, policy)
				if err != nil {
					t.Fatal(err)
				}
				defer v.Close()
				got := make([]byte, 8193)
				if n, err := v.ReadAt(got, 37); err != nil || n != len(got) || !bytes.Equal(got, before[37:37+len(got)]) {
					t.Fatal("authenticated read", n, err)
				}
				patch := bytes.Repeat([]byte{0xa6}, 70656)
				if n, err := v.WriteAt(patch, 512); err != nil || n != len(patch) {
					t.Fatal("authenticated write", n, err)
				}
				if err := v.Sync(); err != nil {
					t.Fatal(err)
				}
				copy(before[512:], patch)
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, before) {
					t.Fatal("physical write oracle", err)
				}
			})
		}
	}
}

func TestStorageSecurityRefusals(t *testing.T) {
	for _, mode := range []string{"wrong-secret", "wrong-identity", "auth-downgrade", "chap-algorithm", "chap-malformed", "chap-drop", "mutual-reflect", "mutual-wrong", "missing-mutual", "same-secret", "header-downgrade", "data-downgrade", "header-corrupt", "data-corrupt"} {
		t.Run(mode, func(t *testing.T) {
			policy, opts := securityFixture(t, "mutual-chap")
			switch mode {
			case "wrong-secret":
				opts.CHAPSecret = []byte("a different server secret")
			case "wrong-identity":
				policy.Username = "incorrect"
			case "missing-mutual":
				opts.TargetSecret = nil
			case "same-secret":
				if err := os.WriteFile(policy.TargetSecretFile, opts.CHAPSecret, 0600); err != nil {
					t.Fatal(err)
				}
			case "header-downgrade":
				policy.HeaderDigest = "crc32c"
			case "data-downgrade":
				policy.DataDigest = "crc32c"
			case "header-corrupt":
				policy.HeaderDigest = "crc32c"
				opts.HeaderDigest = true
				opts.Fault = mode
			case "data-corrupt":
				policy.DataDigest = "crc32c"
				opts.DataDigest = true
				opts.Fault = mode
			default:
				opts.Fault = mode
			}
			path := filepath.Join(t.TempDir(), "disk")
			before := make([]byte, 65536)
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			peer := testiscsi.Start(t, path, opts)
			target, _ := ParseTarget(peer.URL())
			v, err := OpenWithSecurity(context.Background(), target, testiscsi.Initiator, time.Second, true, policy)
			if err == nil {
				v.Close()
				t.Fatal("unsafe security accepted")
			}
			if strings.Contains(err.Error(), "initiator-secret") || strings.Contains(err.Error(), "target-secret") {
				t.Fatal("secret leaked in error")
			}
			if !strings.Contains(mode, "corrupt") && len(peer.Events()) != 0 || bytes.Contains(peer.Events(), []byte{0x8a}) {
				t.Fatalf("SCSI before authentication/digest agreement: %x", peer.Events())
			}
			actual, _ := os.ReadFile(path)
			if !bytes.Equal(actual, before) {
				t.Fatal("refusal changed storage")
			}
		})
	}
}

func TestDigestWireAndPadding(t *testing.T) {
	// CRC32C("123456789") = e3069283; iSCSI serializes it least byte first.
	if got := crc32Value([]byte("123456789")); got != 0xe3069283 {
		t.Fatalf("CRC vector %x", got)
	}
	var p pdu
	p.h[0] = 0x25
	p.data = []byte{1, 2, 3}
	var wire bytes.Buffer
	if err := writeDigestPDU(&wire, p, true, true); err != nil {
		t.Fatal(err)
	}
	b := wire.Bytes()
	if len(b) != 60 || binary.LittleEndian.Uint32(b[48:52]) != crc32Value(b[:48]) || binary.LittleEndian.Uint32(b[56:]) != crc32Value(b[52:56]) {
		t.Fatal("digest placement")
	}
	b[55] = 0xab
	binary.LittleEndian.PutUint32(b[56:], crc32Value(b[52:56]))
	got, err := readDigestPDU(bytes.NewReader(b), true, true)
	if err != nil || !bytes.Equal(got.data, p.data) {
		t.Fatal("nonzero padding with valid CRC rejected", err)
	}
	b[55] ^= 1
	if _, err = readDigestPDU(bytes.NewReader(b), true, true); err == nil {
		t.Fatal("padding corruption accepted")
	}
	p.data = nil
	wire.Reset()
	if err = writeDigestPDU(&wire, p, true, true); err != nil || wire.Len() != 52 {
		t.Fatal("zero-length data must omit data digest", err)
	}
}

func crc32Value(b []byte) uint32 {
	var c uint32 = 0xffffffff
	for _, v := range b {
		c ^= uint32(v)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ 0x82f63b78
			} else {
				c >>= 1
			}
		}
	}
	return ^c
}

func TestStorageSecurityPolicyBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	for _, input := range []string{`{"auth_method":"none","header_digest":"crc32c","data_digest":"none"}`, `{"auth_method":"none","auth_method":"chap","header_digest":"none","data_digest":"none"}`, `{"auth_method":"none","HeaderDigest":"none","data_digest":"none"}`, `{"auth_method":"none","secret":"sensitive","header_digest":"none","data_digest":"none"}`, `{"auth_method":null,"header_digest":"none","data_digest":"none"}`, `{"auth_method":"none"}`} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadSecurity(path)
		valid := strings.Contains(input, `"crc32c"`)
		if (err == nil) != valid {
			t.Fatal("policy acceptance", err)
		}
	}
	policy, _ := securityFixture(t, "chap")
	for _, n := range []int{0, 11, 1025} {
		if err := os.WriteFile(policy.SecretFile, make([]byte, n), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := policy.secrets(); err == nil {
			t.Fatalf("accepted %d-byte secret", n)
		}
	}
}

func TestDigestFailurePoisonsSession(t *testing.T) {
	for _, mode := range []string{"header-corrupt-read", "data-corrupt-read"} {
		t.Run(mode, func(t *testing.T) {
			policy, opts := securityFixture(t, "mutual-chap")
			policy.HeaderDigest = "crc32c"
			policy.DataDigest = "crc32c"
			opts.HeaderDigest = true
			opts.DataDigest = true
			opts.Fault = mode
			path := filepath.Join(t.TempDir(), "disk")
			if err := os.WriteFile(path, make([]byte, 65536), 0600); err != nil {
				t.Fatal(err)
			}
			peer := testiscsi.Start(t, path, opts)
			target, _ := ParseTarget(peer.URL())
			v, err := OpenWithSecurity(context.Background(), target, testiscsi.Initiator, time.Second, true, policy)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if n, err := v.ReadAt(make([]byte, 512), 0); err == nil || n != 0 {
				t.Fatal("corrupt read accepted")
			}
			if err := v.Check(); err == nil {
				t.Fatal("session was not poisoned")
			}
			if n, err := v.WriteAt(make([]byte, 512), 0); err == nil || n != 0 {
				t.Fatal("write after digest failure accepted")
			}
			if bytes.Contains(peer.Events(), []byte{0x8a}) {
				t.Fatal("sent write after digest failure")
			}
		})
	}
}

func TestAuthenticatedOSDWithDigests(t *testing.T) {
	policy, opts := securityFixture(t, "mutual-chap")
	policy.HeaderDigest = "crc32c"
	policy.DataDigest = "crc32c"
	opts.HeaderDigest = true
	opts.DataDigest = true
	opts.OSDSystemID = bytes.Repeat([]byte{0x17}, 20)
	opts.OSDName = []byte("authenticated-osd")
	data := bytes.Repeat([]byte("osd-value"), 1000)
	opts.OSDObjects = map[[2]uint64][]byte{{0x10000, 0x10001}: data}
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
		t.Fatal(err)
	}
	peer := testiscsi.Start(t, path, opts)
	target, _ := ParseTarget(peer.URL())
	cap := make([]byte, 80)
	v, err := OpenObjectWithSecurity(context.Background(), target, testiscsi.Initiator, time.Second, opts.OSDSystemID, opts.OSDName, cap, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	length, err := v.Length(0x10000, 0x10001, cap)
	if err != nil || length != uint64(len(data)) {
		t.Fatal("OSD length", length, err)
	}
	out := make([]byte, 3071)
	if err := v.Read(0x10000, 0x10001, 513, cap, out); err != nil || !bytes.Equal(out, data[513:513+len(out)]) {
		t.Fatal("OSD bytes", err)
	}
}

func TestCHAPNumericalGrammar(t *testing.T) {
	for _, s := range []string{"0", "71", "255", "0x47", "0Xff", "0x0005"} {
		if _, err := iscsiNumber(s, 8); err != nil {
			t.Fatal(s, err)
		}
	}
	for _, s := range []string{"", "00", "071", "0b1000111", "0o107", "+71", "-1", "0x", "0x_47", "7_1", "256", "0x100", " 71"} {
		if _, err := iscsiNumber(s, 8); err == nil {
			t.Fatal("invalid numerical value accepted", s)
		}
	}
	b, err := chapBinary("0x123456789abcdef123456789abcdef1")
	if err != nil || len(b) != 16 || b[0] != 1 {
		t.Fatal("odd hex binary", b, err)
	}
}

func TestCHAPWireNumericalGrammar(t *testing.T) {
	for _, mode := range []string{"chap-hex-odd", "chap-octal", "chap-binary-number"} {
		t.Run(mode, func(t *testing.T) {
			policy, opts := securityFixture(t, "mutual-chap")
			opts.Fault = mode
			path := filepath.Join(t.TempDir(), "disk")
			if err := os.WriteFile(path, make([]byte, 65536), 0600); err != nil {
				t.Fatal(err)
			}
			peer := testiscsi.Start(t, path, opts)
			target, _ := ParseTarget(peer.URL())
			v, err := OpenWithSecurity(context.Background(), target, testiscsi.Initiator, time.Second, true, policy)
			if mode != "chap-hex-odd" {
				if err == nil {
					v.Close()
					t.Fatal("forbidden numerical format accepted")
				}
				if len(peer.Events()) != 0 {
					t.Fatal("SCSI before valid authentication")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if n, err := v.WriteAt(bytes.Repeat([]byte{0x95}, 512), 0); err != nil || n != 512 {
				t.Fatal("hexadecimal authenticated write", n, err)
			}
		})
	}
}
