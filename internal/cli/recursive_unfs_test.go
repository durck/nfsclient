package cli

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestUNFSRecursiveMetadata(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			cfg := unfsCLIConfig(t, transport)
			ctx := context.Background()
			c, err := nfs.Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s := session.New(c, cfg.Host, false, false, nil)
			if err := s.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("metadata-%s-%s-%d", runtime.GOOS, transport, time.Now().UnixNano())
			if err := s.Mkdir(ctx, name); err != nil {
				t.Fatal(err)
			}
			if err := s.CD(ctx, name); err != nil {
				t.Fatal(err)
			}
			namespaceFlow(t, s, false)
			recursiveMetadataFlow(t, s, true)
			if err := s.CD(ctx, "/"); err != nil {
				t.Fatal(err)
			}
			if err := s.Rmdir(ctx, name); err != nil {
				t.Fatal(err)
			}
		})
	}
}
