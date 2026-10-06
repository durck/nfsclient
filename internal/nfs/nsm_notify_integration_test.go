package nfs

import (
	"context"
	"os"
	"testing"
	"time"
)

// Runs on a client with direct inbound reachability. Polling is disabled after
// LOCK to isolate actual SM_NOTIFY from the server.
func TestNSMFreeBSDNotification(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NSM_NOTIFY") != "1" {
		t.Skip("requires direct inbound NSM address and coordinated server restart")
	}
	cfg := Config{Host: os.Getenv("NFS_VIEWER_NLM_HOST"), Version: "3", Transport: "tcp", PortmapPort: 111, Timeout: 3 * time.Second, NLMClientIP: os.Getenv("NFS_VIEWER_NLM_CLIENT_IP"), NLMStateDir: os.Getenv("NFS_VIEWER_NLM_STATE_ROOT"), Auth: Auth{UID: 20001, GID: 20001}}
	ctx := context.Background()
	c, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	root, err := c.Mount(ctx, os.Getenv("NFS_VIEWER_NLM_EXPORT"))
	if err != nil {
		t.Fatal(err)
	}
	node, err := c.Lookup(ctx, root.Handle, "file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(ctx, node.Handle, true); err != nil {
		t.Fatal(err)
	}
	n := c.nlm.monitor
	n.active.Store(0)
	// Drain any probe which started before active became zero.
	n.probeMu.Lock()
	//lint:ignore SA2001 Acquiring the mutex waits for the in-flight operation to finish.
	n.probeMu.Unlock()
	if err := os.WriteFile(os.Getenv("NFS_VIEWER_NLM_MARKER"), []byte("READY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Stock statd can spend over a minute retrying an earlier unreachable peer
	// before reaching this client. Keep the listener alive through that backlog.
	deadline := time.Now().Add(3 * time.Minute)
	for !n.lost.Load() && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if !n.lost.Load() {
		t.Fatal("no server notification arrived with probes disabled")
	}
	t.Log("server-originated notification invalidated retained state with polling disabled")
}
