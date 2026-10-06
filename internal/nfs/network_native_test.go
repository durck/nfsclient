package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This opt-in test uses native sockets on the executing OS. It establishes
// source-port selection only; a NAT may rewrite that port beyond loopback.
func TestNativeReservedSourcePorts(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NETWORK_NATIVE") != "1" {
		t.Skip("requires explicit local network fixture opt-in")
	}
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			observed := make(chan int, 1)
			port := 0
			blockedTopPort := false
			if transport == "udp" {
				blocker, err := net.ListenPacket("udp4", "0.0.0.0:1023")
				if err == nil {
					blockedTopPort = true
					defer blocker.Close()
				}
				_, port = udpPeer(t, func(s *net.UDPConn, addr *net.UDPAddr, b []byte) {
					observed <- addr.Port
					s.WriteToUDP(udpReply(binary.BigEndian.Uint32(b), 42), addr)
				})
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				port = listener.Addr().(*net.TCPAddr).Port
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					observed <- conn.RemoteAddr().(*net.TCPAddr).Port
					b, err := readRecord(conn)
					if err != nil {
						return
					}
					reply := udpReply(binary.BigEndian.Uint32(b), 42)
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], uint32(len(reply))|0x80000000)
					conn.Write(append(header[:], reply...))
				}()
			}
			c, err := dialRPCTransport(context.Background(), "127.0.0.1", port, 3*time.Second, true, transport)
			if transport == "tcp" && os.Getenv("NFS_VIEWER_NETWORK_TCP_EXHAUSTED") == "1" {
				if err == nil {
					c.conn.Close()
					t.Fatal("expected explicitly inventoried reserved TCP range exhaustion")
				}
				if !isAddressInUse(err) || !strings.Contains(err.Error(), ":900") {
					t.Fatal("did not exhaust reserved range without ephemeral fallback", err)
				}
				t.Logf("NATIVE_RESERVED os=%s tcp=exhausted-no-ephemeral-fallback", runtime.GOOS)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.conn.Close()
			d, err := c.call(context.Background(), nfsProgram, 3, 0, nil, nil)
			if err != nil || d.u32() != 42 {
				t.Fatal("reserved RPC", err)
			}
			p := <-observed
			if p < 900 || p > 1023 {
				t.Fatalf("server observed nonreserved port %d", p)
			}
			if blockedTopPort && p == 1023 {
				t.Fatal("collision did not advance to another port")
			}
			t.Logf("NATIVE_RESERVED os=%s transport=%s peer_source_port=%d", runtime.GOOS, transport, p)
		})
	}
}

func TestNativeUDPNetwork(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NETWORK_NATIVE") != "1" {
		t.Skip("requires disposable tests/network native UNFS3 fixture")
	}
	host := os.Getenv("NFS_VIEWER_NETWORK_HOST")
	if host == "" {
		t.Fatal("explicit fixture host required")
	}
	port := func(name string) int {
		n, err := strconv.Atoi(os.Getenv("NFS_VIEWER_NETWORK_" + name))
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid %s", name)
		}
		return n
	}
	type counters struct {
		IP      map[string]uint64 `json:"ip"`
		Wire    map[string]uint64 `json:"wire"`
		Dropped uint64            `json:"dropped"`
		MTU     int               `json:"mtu"`
	}
	controlURL := "http://" + net.JoinHostPort(host, strconv.Itoa(port("CONTROL")))
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer httpClient.CloseIdleConnections()
	control := func(t *testing.T, path string) counters {
		t.Helper()
		r, err := httpClient.Get(controlURL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var state counters
		if r.StatusCode != 200 {
			t.Fatal("fixture control", r.Status)
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	defer control(t, "/normal/1500")
	base := Config{Host: host, NFSPort: port("PORT"), MountPort: port("MOUNT_PORT"), Version: "3", Transport: "udp", Timeout: 4 * time.Second, Auth: Auth{UID: 20001, GID: 20001}}
	connect := func(t *testing.T, cfg Config) (*Client, Node) {
		t.Helper()
		c, err := Connect(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		r, err := c.Mount(context.Background(), "/data")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Tune(context.Background(), r.Handle); err != nil {
			t.Fatal(err)
		}
		return c, r
	}
	payload := bytes.Repeat([]byte("native-fragmentation-"), 901)
	for _, mtu := range []int{1500, 900} {
		for _, size := range []uint32{512, 1024, 4096} {
			t.Run(fmt.Sprintf("mtu%d/size%d", mtu, size), func(t *testing.T) {
				before := control(t, fmt.Sprintf("/normal/%d", mtu))
				cfg := base
				cfg.UDPSize = size
				c, root := connect(t, cfg)
				writer := c
				if mtu == 900 && size > 512 {
					seedConfig := cfg
					seedConfig.Transport = "tcp"
					seedConfig.UDPSize = 0
					writer, _ = connect(t, seedConfig)
				}
				name := fmt.Sprintf("network-%s-%d-%d-%d", runtime.GOOS, mtu, size, time.Now().UnixNano())
				file, err := c.Create(context.Background(), root.Handle, name, 0600, false)
				if err != nil {
					t.Fatal(err)
				}
				if n, err := writer.WriteFrom(context.Background(), file.Handle, bytes.NewReader(payload)); err != nil || n != int64(len(payload)) {
					t.Fatal(n, err, "wire", control(t, "/status"))
				}
				var out bytes.Buffer
				if n, err := c.ReadTo(context.Background(), file.Handle, &out); err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
					t.Fatal("native round trip", n, err)
				}
				after := control(t, "/status")
				fragments := after.Wire["out:nfs_udp_fragments"] - before.Wire["out:nfs_udp_fragments"]
				if after.MTU != mtu || (size == 4096 && fragments == 0) {
					t.Fatal("missing native fragmentation evidence", before, after)
				}
				t.Logf("NATIVE_UDP os=%s mtu=%d size=%d bytes=%d seed_transport=%s server_fragments=%d", runtime.GOOS, mtu, size, len(payload), writer.Transport(), fragments)
			})
		}
	}
	t.Run("reduced-mtu-write", func(t *testing.T) {
		control(t, "/normal/900")
		cfg := base
		cfg.UDPSize = 4096
		c, root := connect(t, cfg)
		name := fmt.Sprintf("mtu-write-%s-%d", runtime.GOOS, time.Now().UnixNano())
		file, err := c.Create(context.Background(), root.Handle, name, 0600, false)
		if err != nil {
			t.Fatal(err)
		}
		before := control(t, "/status")
		data := bytes.Repeat([]byte("MTU"), 700)
		start := time.Now()
		n, writeErr := c.WriteFrom(context.Background(), file.Handle, bytes.NewReader(data))
		after := control(t, "/status")
		requests := after.Wire["in:call:100003:3:7"] - before.Wire["in:call:100003:3:7"]
		if time.Since(start) > 6*time.Second || requests > 1 {
			t.Fatal("unbounded or replayed reduced-MTU mutation", requests, writeErr)
		}
		if writeErr != nil && (n != 0 || !strings.Contains(writeErr.Error(), "outcome unknown")) {
			t.Fatal("missing uncertain mutation", n, writeErr)
		}
		cfg.Transport, cfg.UDPSize = "tcp", 0
		fresh, _ := connect(t, cfg)
		var out bytes.Buffer
		if _, err := fresh.ReadTo(context.Background(), file.Handle, &out); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 && !bytes.Equal(out.Bytes(), data) {
			t.Fatal("partial or corrupted native mutation")
		}
		if writeErr == nil && (n != int64(len(data)) || !bytes.Equal(out.Bytes(), data) || requests != 1) {
			t.Fatal("successful mutation missing server proof", n, requests)
		}
		t.Logf("NATIVE_MTU_WRITE os=%s mtu=900 configured_limit=4096 payload_bytes=%d received_requests=%d applied_bytes=%d acknowledged=%t", runtime.GOOS, len(data), requests, out.Len(), writeErr == nil)
	})
	control(t, "/normal/1500")
	for _, mutation := range []bool{false, true} {
		t.Run(fmt.Sprintf("reply-firewall/mutation=%t", mutation), func(t *testing.T) {
			cfg := base
			cfg.UDPSize = 1024
			c, root := connect(t, cfg)
			name := fmt.Sprintf("firewall-%s-%t-%d", runtime.GOOS, mutation, time.Now().UnixNano())
			file, err := c.Create(context.Background(), root.Handle, name, 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			before := control(t, "/drop")
			start := time.Now()
			if mutation {
				_, err = c.WriteFrom(context.Background(), file.Handle, bytes.NewReader([]byte("one native write")))
			} else {
				_, err = c.GetAttr(context.Background(), file.Handle)
			}
			elapsed := time.Since(start)
			state := control(t, "/status")
			control(t, "/normal/1500")
			want := uint64(3)
			if mutation {
				want = 1
			}
			proc := 1
			if mutation {
				proc = 7
			}
			key := fmt.Sprintf("in:call:100003:3:%d", proc)
			requests := state.Wire[key] - before.Wire[key]
			if err == nil || elapsed > 6*time.Second || state.Dropped < want || requests != want {
				t.Fatalf("bounded firewall: err=%v elapsed=%v requests=%d dropped=%d want=%d", err, elapsed, requests, state.Dropped, want)
			}
			if mutation && !strings.Contains(err.Error(), "outcome unknown") {
				t.Fatal("missing uncertain mutation", err)
			}
			if mutation {
				fresh, _ := connect(t, cfg)
				var out bytes.Buffer
				if _, err := fresh.ReadTo(context.Background(), file.Handle, &out); err != nil || out.String() != "one native write" {
					t.Fatal("unacknowledged native write not observed", err, out.String())
				}
			}
			t.Logf("NATIVE_FIREWALL os=%s mutation=%t observed_requests=%d dropped_replies=%d elapsed=%v", runtime.GOOS, mutation, requests, state.Dropped, elapsed)
		})
	}
}
