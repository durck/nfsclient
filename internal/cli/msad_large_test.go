package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

// Every MiB has its own index, so a reordered or repeated block changes the hash.
func writeMSADLargePayload(w io.Writer, size int64) (string, error) {
	b := make([]byte, 1<<20)
	for i := range b {
		b[i] = byte(i % 251)
	}
	copy(b[8:16], "NFSBIG01")
	h := sha256.New()
	for offset := int64(0); offset < size; offset += int64(len(b)) {
		binary.LittleEndian.PutUint64(b, uint64(offset/int64(len(b))))
		p := b[:min(int64(len(b)), size-offset)]
		if _, err := io.Copy(io.MultiWriter(w, h), bytes.NewReader(p)); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func TestMSADLargePayloadPattern(t *testing.T) {
	var b bytes.Buffer
	digest, err := writeMSADLargePayload(&b, (1<<20)+17)
	if err != nil || b.Len() != (1<<20)+17 {
		t.Fatal(b.Len(), err)
	}
	first, tail := b.Bytes()[:17], b.Bytes()[1<<20:]
	if binary.LittleEndian.Uint64(first) != 0 || binary.LittleEndian.Uint64(tail) != 1 || string(tail[8:16]) != "NFSBIG01" || tail[16] != 16 {
		t.Fatal("block index or final tail differs")
	}
	want := sha256.Sum256(b.Bytes())
	if digest != hex.EncodeToString(want[:]) {
		t.Fatal("digest differs")
	}
}

func TestMicrosoftADNFSLarge(t *testing.T) {
	if os.Getenv("NFS_VIEWER_MSAD_NFS") != "1" || os.Getenv("NFS_VIEWER_MSAD_LARGE") != "1" {
		t.Skip("requires the dedicated large-file Microsoft AD runner")
	}
	base, control, report := os.Getenv("NFS_VIEWER_MSAD_NFS_CREDENTIALS"), os.Getenv("NFS_VIEWER_MSAD_RESTART_CONTROL"), os.Getenv("NFS_VIEWER_MSAD_LARGE_REPORT")
	if !filepath.IsAbs(base) || !filepath.IsAbs(control) || !filepath.IsAbs(report) {
		t.Fatal("absolute fixture directories/report required")
	}
	host := msadTestHost(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: "3", Transport: "tcp", NFSPort: 2049, MountPort: 20048, Security: "krb5p", Timeout: 10 * time.Second, Kerberos: nfs.KerberosConfig{ConfigFile: filepath.Join(base, "krb5.conf"), Keytab: filepath.Join(base, "nv-alice.keytab"), Principal: "nv-alice@MSAD.NFS.TEST", SPN: "nfs/nfs-interop.msad.nfs.test"}})
	if err != nil {
		t.Fatal(err)
	}
	s := session.New(c, host, false, false, nil)
	defer func() { s.Client.Close() }()
	if err := s.Use(ctx, "/srv/nfs-viewer-msad-interop"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	const size int64 = (1 << 32) + 17
	f, err := os.OpenFile(source, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	want, err := writeMSADLargePayload(f, size)
	err = errors.Join(err, f.Close())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LARGE_SOURCE bytes=%d sha256=%s", size, want)
	seed := filepath.Join(dir, "seed")
	if err := os.WriteFile(seed, []byte("old content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	const remote = "data/large.bin"
	if _, err := s.Put(ctx, seed, remote); err != nil {
		t.Fatal(err)
	}
	node, _, err := s.Resolve(ctx, remote, false)
	if err != nil {
		t.Fatal(err)
	}
	policy := &nfs.NFS3ACL{Attr: node.Attr, Access: []nfs.NFS3ACLEntry{{Tag: nfs.ACLUserObj, ID: 25001, Perm: 6}, {Tag: nfs.ACLUser, ID: 25002, Perm: 7}, {Tag: nfs.ACLGroupObj, ID: 25000, Perm: 0}, {Tag: nfs.ACLMask, Perm: 4}, {Tag: nfs.ACLOther, Perm: 0}}}
	policy.Attr.Mode = 0640
	if err := c.SetNFS3ACL(ctx, node.Handle, policy); err != nil {
		t.Fatal(err)
	}
	progress := func(stage string) session.TransferProgress {
		var last uint64
		return func(done, total uint64) {
			if done < last || total != uint64(size) || done > total {
				t.Fatal("invalid large-file progress", stage, done, total)
			}
			if done/(512<<20) != last/(512<<20) || done == total {
				t.Logf("LARGE_PROGRESS stage=%s bytes=%d", stage, done)
			}
			last = done
		}
	}
	if n, err := s.Replace(ctx, source, remote, progress("replace")); err != nil || n != size {
		t.Fatal("large replacement", n, err)
	}
	dest := filepath.Join(dir, "download")
	interrupted, stop := context.WithCancel(ctx)
	n, err := s.GetResume(interrupted, remote, dest, func(done, _ uint64) {
		if done >= 64<<20 {
			stop()
		}
	})
	stop()
	if !errors.Is(err, context.Canceled) || n < 64<<20 || n >= size {
		t.Fatal("expected interrupted large download", n, err)
	}
	part, err := os.Stat(dest + ".nfs-part")
	if err != nil || part.Size() != n {
		t.Fatal("retained prefix differs", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("interrupted download was published", err)
	}
	if err := os.WriteFile(filepath.Join(control, "request"), []byte("restart\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(control, "done")); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	if err := s.Reconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if count, err := s.GetResume(ctx, remote, dest, progress("resume")); err != nil || count != size {
		t.Fatal("large resumed download", count, err)
	}
	download, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	count, err := io.Copy(h, download)
	err = errors.Join(err, download.Close())
	if err != nil || count != size || hex.EncodeToString(h.Sum(nil)) != want {
		t.Fatal("large downloaded bytes differ", count, err)
	}
	result := map[string]any{"passed": true, "bytes": size, "sha256": want, "retained_prefix": n, "server_restart": true, "version": "3", "transport": "tcp", "security": "krb5p"}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("MSAD_LARGE replacement interrupted_download real_restart verified_resume bytes=%d sha256=%s", size, want)
}
