//go:build linux

package gssapi

import (
	"bytes"
	stdcontext "context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKCMUnixSocket(t *testing.T) {
	for _, mode := range []string{"success", "symlink", "regular", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kcm")
			if mode == "regular" {
				os.WriteFile(path, []byte("not a socket"), 0600)
				if _, err := readSelectedCCache(stdcontext.Background(), "KCM:fixture", path); err == nil {
					t.Fatal("regular file selected as socket")
				}
				return
			}
			l, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			selected := path
			if mode == "symlink" {
				selected = path + "-link"
				if err := os.Symlink(path, selected); err != nil {
					t.Fatal(err)
				}
				if _, err := readSelectedCCache(stdcontext.Background(), "KCM:fixture", selected); err == nil {
					t.Fatal("symlink accepted")
				}
				return
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err == nil {
					<-kcmTestPeer(t, c, mode, syntheticCCache(4, "root"))
				}
			}()
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), time.Second)
			defer cancel()
			if mode == "cancel" {
				time.AfterFunc(10*time.Millisecond, cancel)
			}
			cache, err := readSelectedCCache(ctx, "KCM:fixture", selected)
			l.Close()
			<-done
			if mode == "success" {
				if err != nil || !bytes.Equal(cache.Credentials[0].Key.KeyValue, bytes.Repeat([]byte{0x42}, 32)) {
					t.Fatal("trusted Unix snapshot failed", err)
				}
			} else if err == nil {
				t.Fatal("cancellation ignored")
			}
		})
	}
}
