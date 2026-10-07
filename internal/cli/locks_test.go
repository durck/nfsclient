package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func exerciseFileLocks(t *testing.T, ctx context.Context, a, b *session.Session, remote string) {
	t.Helper()
	local := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(local, []byte("lock-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Put(ctx, local, remote); err != nil {
		t.Fatal(err)
	}
	if err := a.Chmod(ctx, remote, 0666); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	sh := &Shell{Session: a, Out: &output, Err: io.Discard, LocalDir: t.TempDir(), ProgressMode: "never"}
	run := func(line string) {
		t.Helper()
		if _, err := sh.Execute(ctx, line); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	run(fmt.Sprintf("lock %q read", remote))
	first := a.Client.Locks()[0].ID
	second, err := b.Lock(ctx, remote, false)
	if err != nil {
		t.Fatal("shared readers", err)
	}
	run("locks")
	if !strings.Contains(output.String(), "held") || !strings.Contains(output.String(), "read") {
		t.Fatal(output.String())
	}
	if _, err = a.Replace(ctx, local, remote, nil); err == nil {
		t.Fatal("replacement bypassed held inode")
	}
	if err = a.Use(ctx, a.Export); !errors.Is(err, nfs.ErrLocksHeld) {
		t.Fatal("use discarded lock", err)
	}
	if _, err = sh.Execute(ctx, "reconnect"); !errors.Is(err, nfs.ErrLocksHeld) {
		t.Fatal("reconnect discarded lock", err)
	}
	run(fmt.Sprintf("unlock %d", first))
	if _, err = a.Lock(ctx, remote, true); !errors.Is(err, nfs.Status(10010)) {
		t.Fatal("writer did not conflict with reader", err)
	}
	if err = b.Client.Unlock(ctx, second); err != nil {
		t.Fatal(err)
	}
	run(fmt.Sprintf("lock %q write", remote))
	writer := a.Client.Locks()[0].ID
	if os.Getenv("NFS_VIEWER_TEST_IDLE") == "1" {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(8 * time.Second):
		}
		t.Log("LOCK_LEASE idle=8s")
	}
	if _, err = b.Lock(ctx, remote, false); !errors.Is(err, nfs.Status(10010)) {
		t.Fatal("reader did not conflict with writer", err)
	}
	var content bytes.Buffer
	if _, err = a.Cat(ctx, remote, &content); err != nil || content.String() != "lock-content\n" {
		t.Fatal("owner READ", err)
	}
	node, _, err := a.Resolve(ctx, remote, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Client.WriteFrom(ctx, node.Handle, bytes.NewBufferString("lock-updated\n")); err != nil {
		t.Fatal("owner WRITE", err)
	}
	if _, err = b.Lock(ctx, remote, true); !errors.Is(err, nfs.Status(10010)) {
		t.Fatal("owner I/O dropped lock", err)
	}
	run(fmt.Sprintf("unlock %d", writer))
	second, err = b.Lock(ctx, remote, true)
	if err != nil {
		t.Fatal("handoff after unlock", err)
	}
	if err = b.Client.Unlock(ctx, second); err != nil {
		t.Fatal(err)
	}
	exerciseRangeLocks(t, ctx, a, b, remote)
	run(fmt.Sprintf("lock %q write", remote))
	a.Client.Close()
	second, err = b.Lock(ctx, remote, false)
	if err != nil {
		t.Fatal("close did not release", err)
	}
	content.Reset()
	if _, err = b.Cat(ctx, remote, &content); err != nil || content.String() != "lock-updated\n" {
		t.Fatal("handoff content", err)
	}
	if err = b.Client.Unlock(ctx, second); err != nil {
		t.Fatal(err)
	}
	t.Log("LOCK_INTEROP shared_readers conflict owner_read_write unlock_handoff close_release")
}

func exerciseRangeLocks(t *testing.T, ctx context.Context, a, b *session.Session, remote string) {
	t.Helper()
	var output bytes.Buffer
	sh := &Shell{Session: a, Out: &output, Err: io.Discard, LocalDir: t.TempDir(), ProgressMode: "never"}
	run := func(line string) {
		t.Helper()
		if _, err := sh.Execute(ctx, line); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	unlockA := func() { t.Helper(); run(fmt.Sprintf("unlock %d", a.Client.Locks()[0].ID)) }
	unlockB := func(id uint64) {
		t.Helper()
		if err := b.Client.Unlock(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	deny := func(write bool, offset, length uint64) {
		t.Helper()
		if id, err := b.LockRange(ctx, remote, write, offset, length); id != 0 || !errors.Is(err, nfs.Status(10010)) {
			t.Fatal("range conflict missing", id, err)
		}
	}
	run(fmt.Sprintf("lock %q write 0 8", remote))
	id, err := b.LockRange(ctx, remote, true, 8, 8)
	if err != nil {
		t.Fatal("adjacent writers conflict", err)
	}
	unlockB(id)
	deny(true, 7, 2)
	deny(false, 0, 1)
	var data bytes.Buffer
	if n, err := a.Cat(ctx, remote, &data); n != 0 || !errors.Is(err, nfs.ErrPartialLockIO) || data.Len() != 0 {
		t.Fatal("unprotected whole-file read", n, err)
	}
	node, _, err := a.Resolve(ctx, remote, false)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := a.Client.WriteFrom(ctx, node.Handle, bytes.NewBufferString("must-not-write")); n != 0 || !errors.Is(err, nfs.ErrPartialLockIO) {
		t.Fatal("unprotected whole-file write", n, err)
	}
	download := filepath.Join(sh.LocalDir, "partial-download")
	if _, err := a.Get(ctx, remote, download); !errors.Is(err, nfs.ErrPartialLockIO) {
		t.Fatal("partial-lock download", err)
	}
	if _, err := os.Stat(download); !os.IsNotExist(err) {
		t.Fatal("refused download was published", err)
	}
	run("locks")
	if !strings.Contains(output.String(), "offset=0 length=8") {
		t.Fatal(output.String())
	}
	unlockA()
	run(fmt.Sprintf("lock %q read 2 4", remote))
	id, err = b.LockRange(ctx, remote, false, 4, 4)
	if err != nil {
		t.Fatal("overlapping readers conflict", err)
	}
	unlockB(id)
	deny(true, 5, 1)
	unlockA()
	const future = uint64(1 << 33)
	run(fmt.Sprintf("lock %q write %d eof", remote, future))
	id, err = b.LockRange(ctx, remote, true, future-1, 1)
	if err != nil {
		t.Fatal("prefix adjacent to EOF range", err)
	}
	unlockB(id)
	deny(true, future+4096, 1)
	run("locks")
	if !strings.Contains(output.String(), fmt.Sprintf("offset=%d length=eof", future)) {
		t.Fatal(output.String())
	}
	unlockA()
	id, err = b.LockRange(ctx, remote, true, future+4096, 1)
	if err != nil {
		t.Fatal("range unlock did not release tail", err)
	}
	unlockB(id)
	t.Log("LOCK_RANGE_INTEROP adjacent_writers overlapping_conflicts shared_readers future_eof whole_io_refused")
}

func TestLockRangeSyntax(t *testing.T) {
	for _, tc := range []struct {
		args           []string
		offset, length uint64
	}{
		{nil, 0, nfs.LockToEOF}, {[]string{"0", "1"}, 0, 1},
		{[]string{"8589934592", "4096"}, 1 << 33, 4096},
		{[]string{"123", "eof"}, 123, nfs.LockToEOF},
		{[]string{"18446744073709551615", "eof"}, nfs.LockToEOF, nfs.LockToEOF},
		{[]string{"0", "18446744073709551615"}, 0, nfs.LockToEOF},
	} {
		o, l, err := parseLockRange(tc.args)
		if err != nil || o != tc.offset || l != tc.length {
			t.Fatal(tc.args, o, l, err)
		}
	}
	for _, args := range [][]string{{"0"}, {"0", "1", "extra"}, {"-1", "1"}, {"+1", "1"}, {"0x10", "1"}, {"1_000", "1"}, {"1", "0"}, {"1", "-1"}, {"1", "EOF"}, {"1", ""}, {"18446744073709551616", "1"}, {"18446744073709551615", "1"}} {
		if _, _, err := parseLockRange(args); err == nil {
			t.Fatal("invalid lock range accepted", args)
		}
		line := "lock file read"
		for _, arg := range args {
			line += " " + strconv.Quote(arg)
		}
		// An invalid command must return before consulting a session/network.
		if _, err := (&Shell{}).Execute(context.Background(), line); err == nil {
			t.Fatal("invalid shell range accepted", line)
		}
	}
	if _, err := (&session.Session{}).LockRange(context.Background(), "file", true, nfs.LockToEOF, 1); err == nil {
		t.Fatal("session accepted overflow before resolution")
	}
	if lockLengthLabel(nfs.LockToEOF) != "eof" || lockLengthLabel(7) != "7" {
		t.Fatal("range formatting")
	}
	sh, _, out := testShell(t)
	if err := sh.printCommandHelp("lock"); err != nil || !strings.Contains(out.String(), "OFFSET LENGTH|eof") {
		t.Fatal("range help", err)
	}
	c := completer{shell: sh, ctx: context.Background()}
	line := []rune("lock file read 123 e")
	matches, _ := c.Do(line, len(line))
	if len(matches) != 1 || string(matches[0]) != "of " {
		t.Fatalf("EOF completion: %q", matches)
	}
}

func TestGaneshaFileLocks(t *testing.T) {
	portText := os.Getenv("NFS_VIEWER_TEST_PORT")
	if portText == "" {
		t.Skip("requires the disposable Ganesha fixture")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			connect := func() *session.Session {
				c, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: version, NFSPort: port, Timeout: 3 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(c, "127.0.0.1", false, false, nil)
				t.Cleanup(func() { s.Client.Close() })
				if err := s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				return s
			}
			exerciseFileLocks(t, ctx, connect(), connect(), fmt.Sprintf("locks-%s-%d", version, time.Now().UnixNano()))
		})
	}
}

func TestMicrosoftADNFSLocks(t *testing.T) {
	if os.Getenv("NFS_VIEWER_MSAD_NFS") != "1" {
		t.Skip("requires the enrolled Microsoft AD interop fixture")
	}
	base := os.Getenv("NFS_VIEWER_MSAD_NFS_CREDENTIALS")
	if !filepath.IsAbs(base) {
		t.Fatal("absolute credential directory required")
	}
	host := msadTestHost(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, sec := range []string{"krb5", "krb5i", "krb5p"} {
			for _, cred := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+sec+"/"+cred, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					connect := func(user string) *session.Session {
						k := nfs.KerberosConfig{ConfigFile: filepath.Join(base, "krb5.conf"), Principal: user + "@MSAD.NFS.TEST", SPN: "nfs/nfs-interop.msad.nfs.test"}
						if cred == "keytab" {
							k.Keytab = filepath.Join(base, user+".keytab")
						} else {
							k.CCache = filepath.Join(base, user+".ccache")
						}
						c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: version, NFSPort: 2049, Timeout: 5 * time.Second, Security: sec, Kerberos: k})
						if err != nil {
							t.Fatal(err)
						}
						s := session.New(c, host, false, false, nil)
						t.Cleanup(func() { s.Client.Close() })
						if err := s.Use(ctx, "/"); err != nil {
							t.Fatal(err)
						}
						return s
					}
					exerciseFileLocks(t, ctx, connect("nv-alice"), connect("nv-bob"), "data/locks-"+version+"-"+sec+"-"+cred)
				})
			}
		}
	}
}
