package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
)

func TestPKINITNativeMIT(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PKINIT_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT PKINIT KDC")
	}
	cfg, err := config.Load(os.Getenv("NFS_VIEWER_PKINIT_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv("NFS_VIEWER_PKINIT_FILES")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl := NewWithPassword("root", "NFS.TEST", "", cfg, NetworkContext(ctx))
	defer cl.Destroy()
	files := PKINITIdentity{Cert: filepath.Join(dir, "client.crt"), Key: filepath.Join(dir, "client.key"), CA: filepath.Join(dir, "ca.crt"), CRL: filepath.Join(dir, "clean.crl")}
	if err := cl.LoginPKINIT(files); err != nil {
		t.Fatal(err)
	}
	if _, key, err := cl.GetServiceTicket("nfs/server.nfs.test"); err != nil || len(key.KeyValue) == 0 {
		t.Fatal("PKINIT-authenticated TGT service exchange", err)
	}
}
