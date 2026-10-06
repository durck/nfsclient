package session

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
)

func TestDownloadSourceEvidence(t *testing.T) {
	base := nfs.Attr{Type: 1, Size: 5, HasSize: true, MTime: time.Unix(100, 1), HasMTime: true, CTime: time.Unix(100, 2), HasCTime: true, HasChange: true, Change: 17, HasFSID: true, FSID: 7, FSIDMinor: 8, HasFileID: true, FileID: 9}
	for name, mutate := range map[string]func(*nfs.Attr){
		"type":                          func(a *nfs.Attr) { a.Type = 2 },
		"size":                          func(a *nfs.Attr) { a.Size++ },
		"missing-size":                  func(a *nfs.Attr) { a.HasSize = false },
		"mtime":                         func(a *nfs.Attr) { a.MTime = a.MTime.Add(time.Nanosecond) },
		"restored-mtime-ctime-changed":  func(a *nfs.Attr) { a.CTime = a.CTime.Add(time.Nanosecond) },
		"restored-times-change-changed": func(a *nfs.Attr) { a.Change++ },
		"change-decreased":              func(a *nfs.Attr) { a.Change = 0 },
		"missing-change":                func(a *nfs.Attr) { a.HasChange = false },
		"missing-mtime":                 func(a *nfs.Attr) { a.HasMTime = false },
		"missing-ctime":                 func(a *nfs.Attr) { a.HasCTime = false },
		"fsid":                          func(a *nfs.Attr) { a.FSID++ },
		"fsid-minor":                    func(a *nfs.Attr) { a.FSIDMinor++ },
		"missing-fsid":                  func(a *nfs.Attr) { a.HasFSID = false },
		"fileid":                        func(a *nfs.Attr) { a.FileID++ },
		"missing-fileid":                func(a *nfs.Attr) { a.HasFileID = false },
	} {
		t.Run(name, func(t *testing.T) {
			after := base
			mutate(&after)
			if err := verifyDownloadSource(base, after); !errors.Is(err, ErrDownloadSourceChanged) {
				t.Fatalf("accepted changed/missing evidence: %v", err)
			}
		})
	}
	if err := verifyDownloadSource(base, base); err != nil {
		t.Fatal(err)
	}
	// v4 recommended timestamps and fileid may be absent; required change is not.
	minimal := nfs.Attr{Type: 1, HasSize: true, HasChange: true}
	if err := downloadSourceReady(minimal, "4.1"); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownloadSource(minimal, minimal); err != nil {
		t.Fatal(err)
	}
	minimal.HasChange = false
	if err := downloadSourceReady(minimal, "4.1"); err == nil {
		t.Fatal("omitted change accepted")
	}
	minimal.HasSize = false
	if err := downloadSourceReady(minimal, "3"); err == nil {
		t.Fatal("omitted size accepted")
	}
	minimal.HasSize = true
	minimal.Size = math.MaxInt64 + 1
	if err := downloadSourceReady(minimal, "3"); err == nil {
		t.Fatal("unsupported local size accepted")
	}
}

func TestDownloadWriterGrowthBound(t *testing.T) {
	var dst bytes.Buffer
	w := downloadWriter{w: &dst, remaining: 4}
	if n, err := w.Write([]byte("ab")); n != 2 || err != nil {
		t.Fatalf("write: %d %v", n, err)
	}
	if n, err := w.Write([]byte("cde")); n != 0 || !errors.Is(err, ErrDownloadSourceChanged) || dst.String() != "ab" {
		t.Fatalf("overflow leaked: %d %v %q", n, err, dst.String())
	}
	if n, err := w.Write([]byte("cd")); n != 2 || err != nil {
		t.Fatalf("exact bound: %d %v", n, err)
	}
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty EOF: %d %v", n, err)
	}
	if n, err := w.Write([]byte("e")); n != 0 || !errors.Is(err, ErrDownloadSourceChanged) || dst.String() != "abcd" {
		t.Fatalf("post-bound growth: %d %v %q", n, err, dst.String())
	}
}

func TestPNFSVerifiedReadThenMetadataCleanup(t *testing.T) {
	base := nfs.Attr{Type: 1, Size: 5, HasSize: true, MTime: time.Unix(100, 1), HasMTime: true, CTime: time.Unix(100, 2), HasCTime: true, HasChange: true, Change: 17, HasFSID: true, FSID: 7, FSIDMinor: 8, HasFileID: true, FileID: 9}
	after := base
	after.CTime = after.CTime.Add(time.Nanosecond)
	if err := verifyDownloadSource(base, after); !errors.Is(err, ErrDownloadSourceChanged) {
		t.Fatal("read-time ctime change accepted", err)
	}
	if err := verifyPNFSReturnedSource(base, after); err != nil {
		t.Fatal("cleanup-only ctime refresh rejected", err)
	}
	for name, mutate := range map[string]func(*nfs.Attr){
		"change":         func(a *nfs.Attr) { a.Change++ },
		"size":           func(a *nfs.Attr) { a.Size++ },
		"type":           func(a *nfs.Attr) { a.Type = 2 },
		"mtime":          func(a *nfs.Attr) { a.MTime = a.MTime.Add(time.Second) },
		"identity":       func(a *nfs.Attr) { a.FileID++ },
		"filesystem":     func(a *nfs.Attr) { a.FSIDMinor++ },
		"missing-change": func(a *nfs.Attr) { a.HasChange = false },
		"missing-ctime":  func(a *nfs.Attr) { a.HasCTime = false },
		"missing-mtime":  func(a *nfs.Attr) { a.HasMTime = false },
		"missing-size":   func(a *nfs.Attr) { a.HasSize = false },
	} {
		t.Run(name, func(t *testing.T) {
			changed := after
			mutate(&changed)
			if err := verifyPNFSReturnedSource(base, changed); !errors.Is(err, ErrDownloadSourceChanged) {
				t.Fatal("cleanup content/identity change accepted", err)
			}
		})
	}
	base.HasChange = false
	if err := verifyPNFSReturnedSource(base, after); !errors.Is(err, ErrDownloadSourceChanged) {
		t.Fatal("missing initial change accepted", err)
	}
}
