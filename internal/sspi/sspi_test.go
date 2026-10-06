package sspi

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/gssapi"
)

type testBackend struct {
	result           stepResult
	calls, closes    atomic.Int32
	entered, release chan struct{}
	fail             error
}

func (b *testBackend) step(target string, in []byte, flags uint32) (stepResult, error) {
	n := b.calls.Add(1)
	if target != "nfs/server.test" || flags != requestMutual|requestIntegrity|requestConnection|requestConfidentiality {
		return stepResult{}, errors.New("native profile changed")
	}
	if b.entered != nil {
		close(b.entered)
		<-b.release
	}
	if b.fail != nil {
		return stepResult{}, b.fail
	}
	if n == 1 {
		if len(in) != 0 {
			return stepResult{}, errors.New("first input is not empty")
		}
		return stepResult{token: []byte("ap-request"), more: true}, nil
	}
	if !bytes.Equal(in, []byte("ap-reply")) {
		return stepResult{}, errors.New("server token changed")
	}
	return b.result, nil
}
func (*testBackend) sign(p []byte) ([]byte, error) { return append([]byte("mic:"), p...), nil }
func (*testBackend) verify(p, mic []byte) error {
	if !bytes.Equal(mic, append([]byte("mic:"), p...)) {
		return errors.New("bad MIC")
	}
	return nil
}
func (*testBackend) seal(p []byte) ([]byte, error) { return append([]byte("sealed:"), p...), nil }
func (*testBackend) unseal(p []byte) ([]byte, error) {
	if !bytes.HasPrefix(p, []byte("sealed:")) {
		return nil, errors.New("bad wrap")
	}
	return bytes.Clone(p[7:]), nil
}
func (b *testBackend) close() error { b.closes.Add(1); return nil }

func testInitiator(ctx context.Context) (*Initiator, *testBackend) {
	b := &testBackend{result: stepResult{flags: requestMutual | requestIntegrity | requestConnection | requestConfidentiality, principal: "user@EXAMPLE.TEST", server: "nfs/server.test@EXAMPLE.TEST", packageName: "Kerberos", expiry: time.Now().Add(time.Hour), sizes: sizes{MaxSignature: 32, SecurityTrailer: 60, BlockSize: 16}}}
	return &Initiator{network: ctx, native: b, principal: "user@EXAMPLE.TEST", spn: "nfs/server.test"}, b
}

const testFlags = gssapi.ContextFlagMutual | gssapi.ContextFlagInteg | gssapi.ContextFlagConf

func establishTest(t *testing.T, i *Initiator) {
	t.Helper()
	token, more, err := i.Initiate("nfs/server.test", testFlags, nil)
	if err != nil || !more || string(token) != "ap-request" {
		t.Fatal(token, more, err)
	}
	token, more, err = i.Initiate("nfs/server.test", testFlags, []byte("ap-reply"))
	if err != nil || more || len(token) != 0 || !i.Established() {
		t.Fatal(token, more, err)
	}
}

func TestSSPIFixedProfileAndMessageServices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	i, b := testInitiator(ctx)
	establishTest(t, i)
	cancel()
	// Setup cancellation no longer governs an established context's lifetime.
	message := []byte("RPC sequence and payload")
	mic, err := i.MakeSignature(message)
	if err != nil {
		t.Fatal(err)
	}
	if err = i.VerifySignature(message, mic); err != nil {
		t.Fatal(err)
	}
	token, err := i.Seal(message)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := i.Unseal(token)
	if err != nil || !bytes.Equal(plain, message) {
		t.Fatal(plain, err)
	}
	if a, b, err := i.TokenSizes(); err != nil || a != 32 || b != 76 {
		t.Fatal(a, b, err)
	}
	i.Close()
	i.Close()
	if b.closes.Load() != 1 || i.Established() {
		t.Fatal("handle ownership lost", b.closes.Load())
	}
	if _, err = i.MakeSignature(message); err == nil {
		t.Fatal("closed handle reused")
	}
}

func TestSSPIRejectsChangedContextEvidence(t *testing.T) {
	for _, mode := range []string{"principal", "server", "package", "mutual", "integrity", "privacy", "delegation", "expired", "signature-size", "continued", "extra-token"} {
		t.Run(mode, func(t *testing.T) {
			i, b := testInitiator(context.Background())
			switch mode {
			case "principal":
				b.result.principal = "other@EXAMPLE.TEST"
			case "server":
				b.result.server = "nfs/other.test@EXAMPLE.TEST"
			case "package":
				b.result.packageName = "NTLM"
			case "mutual":
				b.result.flags &^= requestMutual
			case "integrity":
				b.result.flags &^= requestIntegrity
			case "privacy":
				b.result.flags &^= requestConfidentiality
			case "delegation":
				b.result.flags |= 1
			case "expired":
				b.result.expiry = time.Now().Add(-time.Second)
			case "signature-size":
				b.result.sizes.MaxSignature = 401
			case "continued":
				b.result.more = true
			case "extra-token":
				b.result.token = []byte("unexpected")
			}
			if _, _, err := i.Initiate("nfs/server.test", testFlags, nil); err != nil {
				t.Fatal(err)
			}
			if _, _, err := i.Initiate("nfs/server.test", testFlags, []byte("ap-reply")); err == nil {
				t.Fatal("invalid evidence accepted")
			}
			if i.Established() || b.closes.Load() != 1 {
				t.Fatal("failed context retained")
			}
		})
	}
}

func TestSSPICancellationDefersNativeReleaseSafely(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	i, b := testInitiator(ctx)
	b.entered = make(chan struct{})
	b.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, _, err := i.Initiate("nfs/server.test", testFlags, nil); done <- err }()
	<-b.entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native setup cancellation blocked")
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if b.closes.Load() != 0 {
		t.Fatal("handle deleted concurrently with native setup")
	}
	close(b.release)
	deadline := time.Now().Add(time.Second)
	for b.closes.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("late native setup leaked handles")
		}
		time.Sleep(time.Millisecond)
	}
	if i.Established() {
		t.Fatal("late reply reestablished cancelled context")
	}
}

func TestSSPISetupRefusalsAndExpiry(t *testing.T) {
	for _, mode := range []string{"spn", "flags", "input", "cancelled", "native-failure", "expired-message"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			i, b := testInitiator(ctx)
			defer i.Close()
			spn, flags, input := "nfs/server.test", testFlags, []byte(nil)
			switch mode {
			case "spn":
				spn = "nfs/other.test"
			case "flags":
				flags |= gssapi.ContextFlagDeleg
			case "input":
				input = []byte("early-server-token")
			case "cancelled":
				cancel()
			case "native-failure":
				b.fail = errors.New("no current-logon Kerberos credential")
			case "expired-message":
				establishTest(t, i)
				i.expiry = time.Now().Add(-time.Second)
				if _, err := i.Seal([]byte("data")); err == nil {
					t.Fatal("expired context sealed data")
				}
				return
			}
			if _, _, err := i.Initiate(spn, flags, input); err == nil {
				t.Fatal("invalid setup accepted")
			}
			if mode != "native-failure" && b.calls.Load() != 0 {
				t.Fatal("invalid setup reached native API")
			}
		})
	}
}
