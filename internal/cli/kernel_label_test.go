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

func TestKernelV42Label(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := lockWaitSession(t, ctx, host, ca, "4.2")
	name := fmt.Sprintf("label-api-%s-%d", runtime.GOOS, time.Now().UnixNano())
	local := filepath.Join(t.TempDir(), "source")
	payload := []byte("label refusal preserves content\n")
	if err := os.WriteFile(local, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, local, name); err != nil {
		t.Fatal(err)
	}
	id, err := s.Lock(ctx, name, true)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := s.GetSecurityLabel(ctx, name)
	if !errors.Is(readErr, nfs.Status(10032)) && !errors.Is(readErr, nfs.Status(10004)) {
		t.Fatal("expected unsupported kernel label", readErr)
	}
	writeErr := s.SetSecurityLabel(ctx, name, nfs.SecurityLabel{Format: 0, Policy: 0, Data: []byte("user_u:object_r:user_home_t:s0")})
	if !errors.Is(writeErr, nfs.Status(10032)) && !errors.Is(writeErr, nfs.Status(10004)) {
		t.Fatal("expected rejected kernel label SETATTR", writeErr)
	}
	var b bytes.Buffer
	if _, err := s.Cat(ctx, name, &b); err != nil || !bytes.Equal(b.Bytes(), payload) {
		t.Fatal("read after rejected label", err)
	}
	locks := s.Client.Locks()
	if len(locks) != 1 || locks[0].Uncertain {
		t.Fatal("refusal damaged lock", locks)
	}
	if err := s.Client.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Logf("V42_LABEL platform=%s read=%v write=%v lock_and_bytes_preserved", runtime.GOOS, readErr, writeErr)
}

func TestKernelV42LabelCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	name := fmt.Sprintf("label-cli-%s-%d", runtime.GOOS, time.Now().UnixNano())
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("label refusal preserves content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{host, "--nfs-version", "4.2", "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "5s"}
	for _, cmd := range []string{"put " + strconv.Quote(source) + " " + name, "label " + name, "setlabel " + name + " 0 0 6100ff"} {
		out, err := runKerberosCLI(t, append(append([]string(nil), args...), "-c", cmd))
		if strings.HasPrefix(cmd, "put ") {
			if err != nil {
				t.Fatal(err, out)
			}
			continue
		}
		message := fmt.Sprint(err) + out
		if err == nil || (!strings.Contains(message, "10032") && !strings.Contains(message, "10004") && !strings.Contains(message, "not supported")) {
			t.Fatal("CLI label refusal", err, out)
		}
	}
	t.Logf("V42_LABEL_CLI platform=%s unsupported_get_set_verified", runtime.GOOS)
}

func TestLabelCLIInvalidArguments(t *testing.T) {
	for _, line := range []string{"label", "setlabel file 0 0", "setlabel file -1 0 aa", "setlabel file 0 4294967296 aa", "setlabel file 0 0 g0", "setlabel file 0 0 a", "setlabel file 0 0 " + strings.Repeat("aa", 4097)} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), line); err == nil {
			t.Fatal("invalid label accepted", line)
		}
	}
}
