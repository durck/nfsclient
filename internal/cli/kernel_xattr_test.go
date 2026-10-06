package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
)

func xattrBinary() []byte {
	b := make([]byte, 1024)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestKernelV42Xattr(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprint(locked), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			s := lockWaitSession(t, ctx, host, ca, "4.2")
			name := fmt.Sprintf("xattr-api-%s-%t-%d", runtime.GOOS, locked, time.Now().UnixNano())
			local := filepath.Join(t.TempDir(), "source")
			payload := []byte("xattr metadata fixture\n")
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, local, name); err != nil {
				t.Fatal(err)
			}
			if locked {
				id, err := s.Lock(ctx, name, false)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.SetXattr(ctx, name, "blocked", []byte("x"), 1); err == nil {
					t.Fatal("read lock mutation accepted")
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				id, err = s.Lock(ctx, name, true)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := s.Client.Unlock(ctx, id); err != nil {
						t.Error(err)
					}
				}()
			}
			if names, err := s.ListXattrs(ctx, name); err != nil || len(names) != 0 {
				t.Fatal("empty xattrs", names, err)
			}
			if err := s.SetXattr(ctx, name, "binary", []byte{1}, 1); err != nil {
				t.Fatal(err)
			}
			if err := s.SetXattr(ctx, name, "binary", []byte{2}, 1); !errors.Is(err, nfs.Status(17)) {
				t.Fatal("create collision", err)
			}
			if err := s.SetXattr(ctx, name, "absent", []byte{2}, 2); !errors.Is(err, nfs.Status(10095)) {
				t.Fatal("replace absent", err)
			}
			if err := s.SetXattr(ctx, name, "binary", xattrBinary(), 2); err != nil {
				t.Fatal(err)
			}
			if got, err := s.GetXattr(ctx, name, "binary"); err != nil || !bytes.Equal(got, xattrBinary()) {
				t.Fatal("binary roundtrip", err)
			}
			if err := s.SetXattr(ctx, name, "empty", nil, 0); err != nil {
				t.Fatal(err)
			}
			if err := s.SetXattr(ctx, name, "пример", []byte("UTF-8 key"), 1); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 20; i++ {
				if err := s.SetXattr(ctx, name, fmt.Sprintf("entry-%02d", i), []byte{byte(i), 0, 255}, 1); err != nil {
					t.Fatal(i, err)
				}
			}
			if err := s.SetXattr(ctx, name, "temporary", []byte("remove me"), 1); err != nil {
				t.Fatal(err)
			}
			if err := s.RemoveXattr(ctx, name, "temporary"); err != nil {
				t.Fatal(err)
			}
			if err := s.RemoveXattr(ctx, name, "temporary"); !errors.Is(err, nfs.Status(10095)) {
				t.Fatal("remove missing", err)
			}
			names, err := s.ListXattrs(ctx, name)
			if err != nil || len(names) != 23 {
				t.Fatal("complete xattr list", names, err)
			}
			if err := s.SetXattr(ctx, "readonly", "refused", []byte("x"), 1); !errors.Is(err, nfs.Status(1)) && !errors.Is(err, nfs.Status(13)) {
				t.Fatal("read-only owner denial", err)
			}
			if _, err := s.GetXattr(ctx, "link", "binary"); err == nil {
				t.Fatal("symlink accepted")
			}
			if err := s.Mkdir(ctx, name+"-dir"); err != nil {
				t.Fatal(err)
			}
			if err := s.SetXattr(ctx, name+"-dir", "directory", payload, 1); err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if _, err := s.Cat(ctx, name, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
				t.Fatal("xattr changed content", err)
			}
			t.Logf("V42_XATTR platform=%s locked=%t create_replace_either remove binary_empty_unicode directory denials list23 bytes_verified", runtime.GOOS, locked)
		})
	}
}

func TestKernelV42XattrCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	name := fmt.Sprintf("xattr-cli-%s-%d", runtime.GOOS, time.Now().UnixNano())
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("xattr metadata fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := []string{host, "--nfs-version", "4.2", "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "5s"}
	for _, cmd := range []string{"put " + strconv.Quote(source) + " " + name, "lock " + name + " write", "setxattr " + name + " binary create 0001ff", "getxattr " + name + " binary", "setxattr " + name + " binary replace 0203ff", "setxattr " + name + " empty either \"\"", "setxattr " + name + " temporary create 00", "removexattr " + name + " temporary", "xattrs " + name, "unlock 1"} {
		a = append(a, "-c", cmd)
	}
	out, err := runKerberosCLI(t, a)
	if err != nil || !strings.Contains(out, `"hex":"0001ff"`) || !strings.Contains(out, `["binary","empty"]`) {
		t.Fatal("CLI xattr flow", err, out)
	}
	t.Logf("V42_XATTR_CLI platform=%s binary_empty_create_replace_remove_list_verified", runtime.GOOS)
}

func TestXattrCLIInvalidArguments(t *testing.T) {
	for _, cmd := range []string{"xattrs", "getxattr file", "removexattr file", "setxattr file key wrong 00", "setxattr file key create g0", "setxattr file key create a", "setxattr file key create " + strings.Repeat("aa", 65537)} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), cmd); err == nil {
			t.Fatal("invalid xattr command accepted")
		}
	}
}
