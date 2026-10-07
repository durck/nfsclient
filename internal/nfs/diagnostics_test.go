package nfs

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/testutil/loopback"
)

// Exercise actual TCP/UDP records, ports, configured auth and RPC statuses.
func mountDiagnosticPeer(t *testing.T, transport, version string, reply func(*decoder) (encoder, uint32)) *Client {
	t.Helper()
	l, u, err := loopback.Pair()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	respond := func(b []byte) []byte {
		d := &decoder{b: b}
		xid := d.u32()
		if d.u32() != 0 || d.u32() != 2 {
			t.Error("invalid RPC header")
		}
		program, vers, procedure := d.u32(), d.u32(), d.u32()
		flavor := d.u32()
		a := &decoder{b: d.opaque(400)}
		a.u32()
		a.str()
		uid, gid, groups := a.u32(), a.u32(), a.u32()
		group := a.u32()
		if flavor != 1 || uid != 31337 || gid != 31338 || groups != 1 || group != 42 || a.err != nil {
			t.Error("wrong AUTH_SYS identity")
		}
		d.u32()
		d.opaque(400)
		var payload encoder
		var status uint32
		if program == nfsProgram && procedure == 0 {
			// Connect's existing NULL probe.
		} else {
			wantVersion := uint32(3)
			if version == "2" {
				wantVersion = 1
			}
			if program != mountProgram || vers != wantVersion || procedure != 2 || len(d.b) != 0 || d.err != nil {
				t.Errorf("unexpected DUMP call: %d/%d/%d", program, vers, procedure)
			}
			payload, status = reply(d)
		}
		var e encoder
		e.u32(xid)
		e.u32(1)
		e.u32(0)
		e.u32(0)
		e.u32(0)
		e.u32(status)
		if status == 2 {
			e.u32(1)
			e.u32(3)
		}
		return append(e, payload...)
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				for {
					b, err := readRecord(conn)
					if err != nil {
						return
					}
					if _, err = conn.Write(record(respond(b), true)); err != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		defer workers.Done()
		buf := make([]byte, 65536)
		for {
			n, peer, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := u.WriteTo(respond(buf[:n]), peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { l.Close(); u.Close(); workers.Wait() })
	port := l.Addr().(*net.TCPAddr).Port
	c, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: version, Transport: transport, MountPort: port, NFSPort: port, Timeout: time.Second, Auth: Auth{UID: 31337, GID: 31338, Groups: []uint32{42}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func mountDumpEntries(n int) encoder {
	var e encoder
	for i := 0; i < n; i++ {
		e.u32(1)
		e.str("old-client")
		e.str("/data")
	}
	e.u32(0)
	return e
}

func TestMountDiagnosticsWire(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, version := range []string{"2", "3"} {
			t.Run(transport+version, func(t *testing.T) {
				c := mountDiagnosticPeer(t, transport, version, func(*decoder) (encoder, uint32) { return mountDumpEntries(2), 0 })
				r, err := c.Mounts(context.Background())
				if err != nil || !r.Complete || !r.Available || len(r.Entries) != 2 || r.Entries[0].Hostname != "old-client" || r.Entries[0].Path != "/data" || r.Identity != c.Identity() || r.Peer != c.mount.conn.RemoteAddr().String() || len(c.mounted) != 0 {
					t.Fatalf("%+v, %v", r, err)
				}
				if !strings.Contains(r.Meaning, "not an active client list") {
					t.Fatal(r.Meaning)
				}
			})
		}
	}
}

func TestMountDiagnosticsMalformedAndBounded(t *testing.T) {
	cases := map[string]encoder{"truncated": {0, 0, 0}, "boolean": {0, 0, 0, 2}, "trailing": append(mountDumpEntries(0), 0), "entries": mountDumpEntries(mountDumpLimit + 1), "record": make(encoder, maxRecord+1)}
	var hostname, path encoder
	hostname.u32(1)
	hostname.str(strings.Repeat("x", 256))
	hostname.str("/data")
	hostname.u32(0)
	path.u32(1)
	path.str("client")
	path.str(strings.Repeat("/", 1025))
	path.u32(0)
	cases["hostname"], cases["path"] = hostname, path
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			c := mountDiagnosticPeer(t, "tcp", "3", func(*decoder) (encoder, uint32) { return payload, 0 })
			r, err := c.Mounts(context.Background())
			if err == nil || r.Complete || r.Error == "" || len(r.Entries) > mountDumpLimit {
				t.Fatalf("entries=%d complete=%v error=%v", len(r.Entries), r.Complete, err)
			}
			if name == "entries" && len(r.Entries) != mountDumpLimit {
				t.Fatal("partial bounded entries missing")
			}
		})
	}
}

func TestMountDiagnosticsUnavailable(t *testing.T) {
	for _, status := range []uint32{1, 2, 3} {
		c := mountDiagnosticPeer(t, "tcp", "3", func(*decoder) (encoder, uint32) { return nil, status })
		r, err := c.Mounts(context.Background())
		if !errors.Is(err, ErrMountUnavailable) || r.Available || r.Complete {
			t.Fatalf("%+v %v", r, err)
		}
	}
	var calls atomic.Int32
	c := mountDiagnosticPeer(t, "tcp", "3", func(*decoder) (encoder, uint32) { calls.Add(1); return nil, 0 })
	c.version = "4.2"
	r, err := c.Mounts(context.Background())
	if !errors.Is(err, ErrMountUnavailable) || r.Available || calls.Load() != 0 {
		t.Fatalf("v4 contacted MOUNT: %+v %v", r, err)
	}
	_, err = (&Client{}).Mounts(context.Background())
	if !errors.Is(err, ErrMountUnavailable) {
		t.Fatal(err)
	}
}

func TestMountDiagnosticsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := mountDiagnosticPeer(t, "tcp", "3", func(*decoder) (encoder, uint32) {
		cancel()
		time.Sleep(30 * time.Millisecond)
		return mountDumpEntries(0), 0
	})
	start := time.Now()
	r, err := c.Mounts(ctx)
	if !errors.Is(err, context.Canceled) || r.Complete || time.Since(start) > time.Second {
		t.Fatalf("%+v %v", r, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = c.Mounts(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestConnectionInfoRequestedAndObserved(t *testing.T) {
	c := &Client{config: &Config{Host: "requested.example.test", Kerberos: KerberosConfig{Password: "secret-marker"}}, Auth: Auth{UID: 42, Groups: []uint32{7}}, nfs: &rpcClient{conn: serverInfoConn{peer: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 12049}}}, mount: &rpcClient{conn: serverInfoConn{peer: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 30000}}}}
	r := c.ConnectionInfo(context.Background())
	if r.RequestedHost != "requested.example.test" || r.IP != "192.0.2.9" || r.Peer != "192.0.2.9:12049" || r.MountPeer != "192.0.2.9:30000" || r.Identity != c.Identity() {
		t.Fatalf("%+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), "secret-marker") {
		t.Fatalf("secret in diagnostics: %s %v", b, err)
	}
	r.Groups[0] = 999
	if !reflect.DeepEqual(c.Auth.Groups, []uint32{7}) {
		t.Fatal("diagnostics aliased auth groups")
	}
}
