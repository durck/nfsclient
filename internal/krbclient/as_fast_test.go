package client

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestFASTCF2RFC6113(t *testing.T) {
	for id, want := range map[int32]string{17: "97df97e4b798b29eb31ed7280287a92a", 18: "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b"} {
		et, _ := crypto.GetEtype(id)
		one, err := et.StringToKey("key1", "key1", et.GetDefaultStringToKeyParams())
		if err != nil {
			t.Fatal(err)
		}
		two, err := et.StringToKey("key2", "key2", et.GetDefaultStringToKeyParams())
		if err != nil {
			t.Fatal(err)
		}
		key, err := fastCF2(types.EncryptionKey{KeyType: id, KeyValue: one}, types.EncryptionKey{KeyType: id, KeyValue: two}, "a", "b")
		if err != nil || hex.EncodeToString(key.KeyValue) != want {
			t.Fatalf("RFC6113 enctype %d: %v", id, err)
		}
	}
}

func TestFASTNativeMIT(t *testing.T) {
	if os.Getenv("NFS_VIEWER_FAST_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT KDC")
	}
	cfg, err := config.Load(os.Getenv("NFS_VIEWER_FAST_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Load(os.Getenv("NFS_VIEWER_FAST_KEYTAB"))
	if err != nil {
		t.Fatal(err)
	}
	armor, err := credentials.LoadCCache(os.Getenv("NFS_VIEWER_FAST_ARMOR"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl := NewWithKeytab("alice", "NFS.TEST", kt, cfg, NetworkContext(ctx), DisablePAFXFAST(true))
	defer cl.Destroy()
	if err := cl.LoginFAST(armor); err != nil {
		t.Fatal(err)
	}
	if _, key, err := cl.GetServiceTicket("nfs/server.nfs.test"); err != nil || len(key.KeyValue) == 0 {
		t.Fatal("FAST-authenticated TGT service exchange", err)
	}
}

func TestFASTCF2RejectsInvalidKeys(t *testing.T) {
	for _, key := range []types.EncryptionKey{{KeyType: 23, KeyValue: make([]byte, 16)}, {KeyType: 17, KeyValue: make([]byte, 32)}, {KeyType: 18}} {
		if _, err := fastCF2(key, key, "a", "b"); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
}
