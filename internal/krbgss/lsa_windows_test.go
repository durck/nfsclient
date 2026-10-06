//go:build windows

package gssapi

import (
	stdcontext "context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unsafe"
)

func TestLSANativeCurrentLogonAvailabilityProbe(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LSA_CURRENT_PROBE") != "1" {
		t.Skip("explicit read-only current-logon metadata probe required")
	}
	p, err := openNativeLSA()
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	b, err := p.query(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.b)
	if len(b.b) < 8 || binary.LittleEndian.Uint32(b.b) != lsaQueryCacheEx {
		t.Fatal("invalid current-logon metadata reply")
	}
	// Only the count is reported. Do not enumerate principals or retrieve keys.
	t.Logf("current-logon cached ticket count=%d; metadata only, no positive import claim", binary.LittleEndian.Uint32(b.b[4:]))
}

func TestLSANativeABI(t *testing.T) {
	var r nativeLSARequest
	if unsafe.Sizeof(uintptr(0)) == 8 {
		if unsafe.Sizeof(r) != 64 || unsafe.Offsetof(r.target) != 16 || unsafe.Offsetof(r.cacheOptions) != 36 || unsafe.Offsetof(r.lower) != 48 {
			t.Fatal("invalid Win64 LSA request ABI")
		}
	} else {
		if unsafe.Sizeof(r) != 40 || unsafe.Offsetof(r.target) != 12 || unsafe.Offsetof(r.cacheOptions) != 24 || unsafe.Offsetof(r.lower) != 32 {
			t.Fatal("invalid Win32 LSA request ABI")
		}
	}
	if lsaQueryCacheEx != 14 || lsaRetrieveEncoded != 8 || lsaCacheOnly != 2 {
		t.Fatal("invalid LSA protocol constants")
	}
}
func TestLSANativeCurrentLogonRefusal(t *testing.T) {
	// This explicit nonexistent identity cannot match a cached current-logon TGT.
	// Do not export, print or inspect host credentials or other logon sessions.
	c, err := readLSACCache(stdcontext.Background(), "nfs-viewer-nonexistent@NO-SUCH-NFS-VIEWER.INVALID")
	if c != nil {
		clearNativeCache(c)
	}
	if err == nil {
		t.Fatal("nonexistent identity acquired native credentials")
	}
	if !strings.Contains(err.Error(), "exactly one cached selected home TGT") {
		t.Fatalf("native cache query did not reach principal selection: %v", err)
	}
	// Errors contain only our phase description and numeric native status.
	// Record the actual refusal boundary without any host ticket metadata.
	t.Log("native refusal boundary:", err)
}
func TestLSANativeCanceledBeforeCall(t *testing.T) {
	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	cancel()
	if _, err := readLSACCache(ctx, "root@NFS.TEST"); err != stdcontext.Canceled {
		t.Fatal("canceled LSA request performed work")
	}
}
