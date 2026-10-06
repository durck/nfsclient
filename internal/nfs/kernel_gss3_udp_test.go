package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicit isolated kernel fixture; exercise the public protected UDP path.
func TestKernelGSS3UDPProtectedDiagnostic(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KERNEL_GSS_V3_UDP_DIAGNOSTIC") != "1" {
		t.Skip("requires explicit isolated kernel protected-UDP diagnostic")
	}
	for _, gate := range []string{"NFS_VIEWER_KERNEL", "NFS_VIEWER_KERNEL_GSS_V3"} {
		if os.Getenv(gate) != "1" {
			t.Fatalf("diagnostic requires %s=1", gate)
		}
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing explicit fixture setting %s", name)
		}
		return value
	}
	port := func(name string) int {
		t.Helper()
		n, err := strconv.Atoi(required(name))
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid fixture port %s", name)
		}
		return n
	}
	base := Config{Host: "127.0.0.1", Version: "3", Transport: "udp", Timeout: 4 * time.Second,
		NFSPort: port("NFS_VIEWER_KERNEL_PORT"), MountPort: port("NFS_VIEWER_KERNEL_MOUNT_PORT"),
		Kerberos: KerberosConfig{ConfigFile: required("NFS_VIEWER_KERNEL_KRB5_CONFIG"), SPN: required("NFS_VIEWER_KERNEL_KRB5_SPN"), Principal: "alice@NFS.TEST"}}
	keytab, cache := required("NFS_VIEWER_KERNEL_KRB5_ALICE_KEYTAB"), required("NFS_VIEWER_KERNEL_KRB5_ALICE_CCACHE")
	bobKeytab := required("NFS_VIEWER_KERNEL_KRB5_BOB_KEYTAB")
	for _, security := range []string{"krb5i", "krb5p"} {
		for _, credential := range []string{"keytab", "ccache"} {
			t.Run(security+"/"+credential, func(t *testing.T) {
				cfg := base
				cfg.Security = security
				if credential == "keytab" {
					cfg.Kerberos.Keytab = keytab
				} else {
					cfg.Kerberos.CCache = cache
				}
				t.Run("transfer-policy", func(t *testing.T) { kernelGSS3UDPTransfer(t, cfg, bobKeytab) })
				for _, mode := range []string{"loss-reorder", "replayed-reply", "altered-verifier", "altered-body", "lost-create"} {
					t.Run(mode, func(t *testing.T) { kernelGSS3UDPFault(t, cfg, mode) })
				}
			})
		}
	}
}

func kernelGSS3UDPConnect(t *testing.T, ctx context.Context, cfg Config, exports ...string) (*Client, Node) {
	t.Helper()
	t.Log("KERNEL_GSS3_UDP_PHASE protected-DATA-NULL")
	c, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	t.Log("KERNEL_GSS3_UDP_PHASE mount-GETATTR")
	export := "/srv/nfs-viewer-kernel/data"
	if len(exports) != 0 {
		export = exports[0]
	}
	root, err := c.Mount(ctx, export)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Tune(ctx, root.Handle); err != nil {
		t.Fatal(err)
	}
	if c.ReadSize != 4096 || c.WriteSize != 4096 {
		t.Fatalf("expected 4096-byte UDP limits, got read=%d write=%d", c.ReadSize, c.WriteSize)
	}
	if c.Identity() != cfg.Kerberos.Principal+" ("+cfg.Security+")" || c.Security() != cfg.Security || c.Transport() != "udp" || c.Version() != "3" {
		t.Fatal("diagnostic changed identity/protection/transport/version")
	}
	return c, root
}

func kernelGSS3UDPPayload() []byte {
	b := make([]byte, 8193)
	for i := range b {
		b[i] = byte(i * 31)
	}
	return b
}

func kernelGSS3UDPCommit(ctx context.Context, c *Client, fh []byte) error {
	// WriteFrom requests FILE_SYNC. Explicitly exercise authenticated COMMIT too;
	// this does not pretend that the server returned an unstable WRITE.
	var e encoder
	e.opaque(fh)
	e.u64(0)
	e.u32(0)
	d, err := c.call(ctx, 21, e)
	if err != nil {
		return err
	}
	wcc(d)
	d.take(8)
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return errors.New("trailing diagnostic COMMIT result")
	}
	return nil
}

func kernelGSS3UDPTransfer(t *testing.T, cfg Config, bobKeytab string, exports ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	alice, root := kernelGSS3UDPConnect(t, ctx, cfg, exports...)
	deny := func(err error) {
		t.Helper()
		if !errors.Is(err, Status(13)) && !errors.Is(err, Status(1)) {
			t.Fatalf("expected server permission denial: %v", err)
		}
	}
	name := fmt.Sprintf("gss3-udp-%d", time.Now().UnixNano())
	t.Log("KERNEL_GSS3_UDP_PHASE CREATE-empty-WRITE-COMMIT-READ")
	file, err := alice.Create(ctx, root.Handle, name, 0600, false)
	if err != nil {
		t.Fatal(err)
	}
	attr, err := alice.GetAttr(ctx, file.Handle)
	if err != nil || attr.UID != 20001 || attr.GID != 20001 || attr.Mode&0777 != 0600 || attr.Size != 0 {
		t.Fatalf("Alice create identity: %+v %v", attr, err)
	}
	var out bytes.Buffer
	if n, err := alice.WriteFrom(ctx, file.Handle, bytes.NewReader(nil)); err != nil || n != 0 {
		t.Fatalf("empty write: %d %v", n, err)
	}
	if n, err := alice.ReadTo(ctx, file.Handle, &out); err != nil || n != 0 || out.Len() != 0 {
		t.Fatalf("empty read: %d %v", n, err)
	}
	payload := kernelGSS3UDPPayload()
	var wrote, read []uint64
	if n, err := alice.WriteFromProgress(ctx, file.Handle, bytes.NewReader(payload), func(n uint64) { wrote = append(wrote, n) }); err != nil || n != int64(len(payload)) {
		t.Fatalf("binary write: %d %v", n, err)
	}
	if err := kernelGSS3UDPCommit(ctx, alice, file.Handle); err != nil {
		t.Fatal(err)
	}
	if n, err := alice.ReadToProgress(ctx, file.Handle, &out, func(n uint64) { read = append(read, n) }); err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("binary read: %d %v", n, err)
	}
	if !reflect.DeepEqual(wrote, []uint64{4096, 8192, 8193}) || !reflect.DeepEqual(read, []uint64{4096, 8192, 8193}) {
		t.Fatalf("UDP chunk boundaries: writes=%v reads=%v", wrote, read)
	}
	bobCfg := cfg
	bobCfg.Kerberos.Keytab, bobCfg.Kerberos.CCache, bobCfg.Kerberos.Principal = bobKeytab, "", "bob@NFS.TEST"
	bob, bobRoot := kernelGSS3UDPConnect(t, ctx, bobCfg, exports...)
	proof, err := bob.Create(ctx, bobRoot.Handle, name+"-bob", 0600, false)
	if err != nil {
		t.Fatal(err)
	}
	bobAttr, err := bob.GetAttr(ctx, proof.Handle)
	if err != nil || bobAttr.UID != 20002 || bobAttr.GID != 20002 {
		t.Fatalf("Bob mapping proof: %+v %v", bobAttr, err)
	}
	out.Reset()
	_, err = bob.ReadTo(ctx, file.Handle, &out)
	deny(err)
	if out.Len() != 0 {
		t.Fatal("denied read exposed bytes")
	}
	_, err = bob.WriteFrom(ctx, file.Handle, strings.NewReader("forbidden"))
	deny(err)
	deny(bob.Chmod(ctx, file.Handle, 0666))
	out.Reset()
	if _, err := alice.ReadTo(ctx, file.Handle, &out); err != nil || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("denials changed original: %v", err)
	}
	after, err := alice.GetAttr(ctx, file.Handle)
	if err != nil || after.FileID != attr.FileID || after.UID != 20001 || after.GID != 20001 || after.Mode&0777 != 0600 || after.Size != uint64(len(payload)) {
		t.Fatalf("denials changed file identity or policy: %+v %v", after, err)
	}
	for _, c := range []*Client{alice, bob} {
		if c.Security() != cfg.Security {
			t.Fatal("protection changed after operations")
		}
	}
	if alice.Identity() != "alice@NFS.TEST ("+cfg.Security+")" || bob.Identity() != "bob@NFS.TEST ("+cfg.Security+")" {
		t.Fatal("identity changed after operations")
	}
	t.Logf("KERNEL_GSS3_UDP_TRANSFER file=%s bytes=%d chunks=4096,4096,1 explicit_commit=true bob_denied=true", name, len(payload))
}

func kernelGSS3UDPFault(t *testing.T, cfg Config, mode string, exports ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	relay := startKernelGSS3UDPRelay(t, cfg.NFSPort)
	relayCfg := cfg
	relayCfg.NFSPort = relay.port
	c, root := kernelGSS3UDPConnect(t, ctx, relayCfg, exports...)
	name := fmt.Sprintf("gss3-udp-%s-%d", mode, time.Now().UnixNano())
	if mode == "lost-create" {
		relay.arm(mode, 8)
		_, err := c.Create(ctx, root.Handle, name, 0600, false)
		if err == nil || !strings.Contains(err.Error(), "outcome unknown") || !strings.Contains(err.Error(), "not replayed") {
			t.Fatalf("lost mutation result: %v", err)
		}
		if _, err := c.GetAttr(ctx, root.Handle); err == nil {
			t.Fatal("reused failed mutation session")
		}
		count, _, relayErr := relay.snapshot()
		if relayErr != nil || count != 1 {
			t.Fatalf("mutation replayed: requests=%d relay=%v", count, relayErr)
		}
		// Independent authentication confirms that the lost reply concealed a
		// real successful mutation. Do not retry that mutation to learn its state.
		check, checkRoot := kernelGSS3UDPConnect(t, ctx, cfg, exports...)
		file, err := check.Lookup(ctx, checkRoot.Handle, name)
		if err != nil || file.Attr.UID != 20001 || file.Attr.GID != 20001 || file.Attr.Mode&0777 != 0600 || file.Attr.Size != 0 {
			t.Fatalf("unknown mutation server state: %+v %v", file.Attr, err)
		}
		if err := check.Remove(ctx, checkRoot.Handle, name); err != nil {
			t.Fatal(err)
		}
		if _, err := check.Lookup(ctx, checkRoot.Handle, name); !errors.Is(err, Status(2)) {
			t.Fatalf("mutation probe cleanup: %v", err)
		}
		t.Log("KERNEL_GSS3_UDP_FAULT mode=lost-create forwarded=1 unknown_outcome=true independent_state_verified=true removed=true")
		return
	}
	file, err := c.Create(ctx, root.Handle, name, 0600, false)
	if err != nil {
		t.Fatal(err)
	}
	// One READ result keeps the retry count distinct from transfer chunking.
	payload := kernelGSS3UDPPayload()[:4096]
	if _, err := c.WriteFrom(ctx, file.Handle, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	relay.arm(mode, 6)
	var out bytes.Buffer
	n, err := c.ReadTo(ctx, file.Handle, &out)
	count, fresh, relayErr := relay.snapshot()
	if relayErr != nil {
		t.Fatal(relayErr)
	}
	if mode == "loss-reorder" {
		if err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) || count != 2 || !fresh {
			t.Fatalf("loss/reorder result: bytes=%d attempts=%d fresh=%t err=%v", n, count, fresh, err)
		}
	} else {
		want := 1
		if mode == "replayed-reply" {
			want = 2
			if !fresh {
				t.Fatal("signed replay did not follow a fresh retry")
			}
		}
		failure := "signature verification failed"
		if mode == "altered-body" && cfg.Security == "krb5p" {
			failure = "RPCSEC_GSS privacy:"
		}
		if err == nil || n != 0 || out.Len() != 0 || count != want || isRPCTimeout(err) || !strings.Contains(err.Error(), "session closed") || !strings.Contains(err.Error(), failure) {
			t.Fatalf("unauthenticated result exposed/retried: bytes=%d attempts=%d err=%v", n, count, err)
		}
		if _, err := c.GetAttr(ctx, file.Handle); err == nil {
			t.Fatal("reused failed authenticated session")
		}
		if after, _, _ := relay.snapshot(); after != count {
			t.Fatal("failed session sent another target call")
		}
	}
	if c.Identity() != "alice@NFS.TEST ("+cfg.Security+")" || c.Security() != cfg.Security {
		t.Fatal("fault changed reported identity/protection")
	}
	t.Logf("KERNEL_GSS3_UDP_FAULT mode=%s forwarded=%d fresh_retry=%t exposed_bytes=%d", mode, count, fresh, out.Len())
}
