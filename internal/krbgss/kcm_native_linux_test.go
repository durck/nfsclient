//go:build linux

package gssapi

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/types"
)

const nativeKCMSocket = "/var/run/.heim_org.h5l.kcm-socket"

func TestKCMNativeDaemonUIDIsolation(t *testing.T) {
	if name := os.Getenv("NFS_VIEWER_KCM_UID_CHILD"); name != "" {
		if os.Getenv("NFS_VIEWER_KCM_DAEMON_NATIVE") != "1" || os.Geteuid() != 20001 || !strings.HasPrefix(name, "KCM:0:nfs-test-") {
			t.Fatal("invalid isolated UID test profile")
		}
		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), time.Second)
		defer cancel()
		cache, err := readSelectedCCache(ctx, name, nativeKCMSocket)
		if cache != nil {
			clearNativeCache(cache)
		}
		if err == nil || !strings.Contains(err.Error(), "KCM operation") {
			t.Fatalf("native daemon did not refuse another UID's cache: %v", err)
		}
		return
	}
	requireNativeKCM(t)
	name := nativeKCMCache(t, "root", "")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The runner places the binary in /tmp so the unprivileged child can
	// execute it without access to the fixture's private keytab directory.
	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestKCMNativeDaemonUIDIsolation$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "NFS_VIEWER_KCM_UID_CHILD="+name)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 20001, Gid: 20001}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated UID probe: %v\n%s", err, output)
	}
}

func requireNativeKCM(t *testing.T) string {
	t.Helper()
	if os.Getenv("NFS_VIEWER_KCM_DAEMON_NATIVE") != "1" {
		t.Skip("requires the isolated tests/kcm-native SSSD/MIT fixture")
	}
	for _, path := range []string{"/.dockerenv", "/run/nfs-test/kcm.ready"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("test requires disposable container marker", err)
		}
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture setup requires its container-local root account")
	}
	conf, err := os.ReadFile("/etc/krb5.conf")
	if err != nil {
		t.Fatal(err)
	}
	return string(conf)
}

func nativeKCMCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "KRB5_CONFIG=/etc/krb5.conf")
	if err := cmd.Run(); err != nil {
		t.Fatalf("native fixture %s failed: %v", name, err)
	}
}

func nativeKCMCache(t *testing.T, user, life string) string {
	t.Helper()
	name := fmt.Sprintf("KCM:0:nfs-test-%d", time.Now().UnixNano())
	keytab := "/run/nfs-test/" + user + ".keytab"
	if user == "root" {
		keytab = "/run/nfs-test/client.keytab"
	}
	args := []string{"-k", "-t", keytab, "-c", name}
	if life != "" {
		args = append(args, "-l", life)
	}
	nativeKCMCommand(t, "kinit", append(args, user+"@NFS.TEST")...)
	t.Cleanup(func() { _ = exec.Command("kdestroy", "-c", name).Run() })
	return name
}

func nativeKCMInitiator(ctx stdcontext.Context, conf, name string) (*Initiator, error) {
	return NewInitiator(WithConfig[Initiator](conf), WithRealm[Initiator]("NFS.TEST"), WithUsername[Initiator]("root"), WithCCache(name), WithKCMSocket(nativeKCMSocket), WithNetworkContext(ctx))
}

func TestKCMNativeDaemonGSS(t *testing.T) {
	conf := requireNativeKCM(t)
	for _, protection := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(protection, func(t *testing.T) {
			name := nativeKCMCache(t, "root", "")
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Second)
			defer cancel()
			before, err := readSelectedCCache(ctx, name, nativeKCMSocket)
			if err != nil {
				t.Fatal("SSSD snapshot", err)
			}
			defer clearNativeCache(before)
			i, err := nativeKCMInitiator(ctx, conf, name)
			if err != nil {
				t.Fatal("native KCM import", err)
			}
			defer i.Close()
			spn := types.NewPrincipalName(2, "nfs/server.nfs.test")
			a, err := NewAcceptor(WithKeytab[Acceptor]("/etc/krb5.keytab"), WithServicePrincipal[Acceptor](&spn))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			flags := gssapi.ContextFlagMutual | gssapi.ContextFlagInteg
			if protection == "krb5p" {
				flags |= gssapi.ContextFlagConf
			}
			request, _, err := i.Initiate("nfs@server.nfs.test", flags, nil)
			if err != nil {
				t.Fatal("native TGS", err)
			}
			reply, _, err := a.Accept(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = i.Initiate("nfs@server.nfs.test", flags, reply); err != nil {
				t.Fatal(err)
			}
			if !i.established || !a.established || a.peerName != "root@NFS.TEST" {
				t.Fatal("mutual authentication identity mismatch")
			}
			payload := []byte{0, 255, 128, 'K', 'C', 'M'}
			if protection != "krb5" {
				mic, err := i.MakeSignature(payload)
				if err != nil || a.VerifySignature(payload, mic) != nil {
					t.Fatal("native KCM integrity exchange", err)
				}
			}
			if protection == "krb5p" {
				sealed, err := i.Seal(payload)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := a.Unseal(sealed)
				if err != nil || !bytes.Equal(plain, payload) {
					t.Fatal("native KCM privacy exchange", err)
				}
			}
			after, err := readSelectedCCache(ctx, name, nativeKCMSocket)
			if err != nil {
				t.Fatal(err)
			}
			defer clearNativeCache(after)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("read-only KCM import changed daemon credentials")
			}
		})
	}
}

func TestKCMNativeDaemonSelection(t *testing.T) {
	conf := requireNativeKCM(t)
	for _, mode := range []string{"explicit-over-default", "missing", "principal-replaced", "same-principal-refreshed", "destroyed", "expired", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			name := nativeKCMCache(t, "root", "")
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 6*time.Second)
			defer cancel()
			switch mode {
			case "explicit-over-default":
				other := nativeKCMCache(t, "alice", "")
				nativeKCMCommand(t, "kswitch", "-c", other)
				t.Setenv("KRB5CCNAME", other)
			case "missing":
				name += "-missing"
			case "principal-replaced":
				nativeKCMCommand(t, "kinit", "-k", "-t", "/run/nfs-test/alice.keytab", "-c", name, "alice@NFS.TEST")
			case "same-principal-refreshed":
				first, err := nativeKCMInitiator(ctx, conf, name)
				if err != nil {
					t.Fatal(err)
				}
				first.Close()
				nativeKCMCommand(t, "kinit", "-k", "-t", "/run/nfs-test/client.keytab", "-c", name, "root@NFS.TEST")
			case "destroyed":
				nativeKCMCommand(t, "kdestroy", "-c", name)
			case "expired":
				name = nativeKCMCache(t, "root", "2s")
				cache, err := readSelectedCCache(ctx, name, nativeKCMSocket)
				if err != nil {
					t.Fatal(err)
				}
				home, ok := cache.GetEntry(types.NewPrincipalName(2, "krbtgt/NFS.TEST"))
				if !ok {
					t.Fatal("native fixture has no home TGT")
				}
				until := home.EndTime.Add(50 * time.Millisecond)
				if delay := time.Until(until); delay <= 0 || delay > 3*time.Second {
					t.Fatal("fixture did not provide a short valid TGT")
				}
				clearNativeCache(cache)
				timer := time.NewTimer(max(0, time.Until(until)))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			case "canceled":
				cancel()
			}
			i, err := nativeKCMInitiator(ctx, conf, name)
			if i != nil {
				i.Close()
			}
			wantSuccess := mode == "explicit-over-default" || mode == "same-principal-refreshed"
			if wantSuccess && err != nil || !wantSuccess && err == nil {
				t.Fatalf("selection outcome: %v", err)
			}
			if mode == "principal-replaced" && !strings.Contains(err.Error(), "principal does not match") {
				t.Fatal("incorrect principal-change refusal", err)
			}
		})
	}
}
