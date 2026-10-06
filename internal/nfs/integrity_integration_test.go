package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Exercise actual Kerberos MICs on READ/WRITE bodies, not only the RPC verifier.
func TestKerberosIntegrityTampering(t *testing.T) { testKerberosProtectedTampering(t, "krb5i") }
func TestKerberosPrivacyTampering(t *testing.T)   { testKerberosProtectedTampering(t, "krb5p") }

func testKerberosProtectedTampering(t *testing.T, security string) {
	port := os.Getenv("NFS_VIEWER_KRB5_PORT")
	if port == "" {
		t.Skip("requires tests/kerberos fixture")
	}
	mountPort, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"))
	directPort, _ := strconv.Atoi(port)
	modes := []string{"read-payload", "write-payload", "replay-result"}
	if security == "krb5p" {
		modes = append(modes, "wire-privacy")
	}
	payload := []byte("synthetic confidential file contents unique marker")
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan bool, 1)
			t.Cleanup(func() {
				listener.Close()
				select {
				case changed := <-done:
					if !changed {
						t.Error("relay never changed the target payload")
					}
				case <-time.After(12 * time.Second):
					t.Error("relay did not stop")
				}
			})
			go func() {
				changed := false
				defer func() { done <- changed }()
				downstream, err := listener.Accept()
				if err != nil {
					return
				}
				defer downstream.Close()
				upstream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				var previousResult []byte
				for {
					downstream.SetDeadline(time.Now().Add(10 * time.Second))
					upstream.SetDeadline(time.Now().Add(10 * time.Second))
					request, err := readRecord(downstream)
					if err != nil {
						return
					}
					if len(request) < 24 {
						return
					}
					proc := binary.BigEndian.Uint32(request[20:24])
					if security == "krb5p" && bytes.Contains(request, payload) {
						t.Error("plaintext request on wire")
						return
					}
					if proc == 7 && mode == "write-payload" && !changed {
						d := &decoder{b: request}
						d.take(24)
						d.u32()
						d.opaque(400)
						d.u32()
						d.opaque(400)
						token := d.opaque(maxRecord)
						if security == "krb5p" {
							if d.err != nil || len(token) < 60 || token[2]&2 == 0 {
								return
							}
							token[len(token)-1] ^= 1
							changed = true
						} else {
							args := &decoder{b: token}
							args.u32()
							args.opaque(64)
							args.u64()
							args.u32()
							args.u32()
							data := args.opaque(maxRecord)
							if d.err != nil || args.err != nil || len(data) == 0 {
								return
							}
							data[0] ^= 1
							changed = true
						}
					}
					if _, err := upstream.Write(record(request, true)); err != nil {
						return
					}
					reply, err := readRecord(upstream)
					if err != nil {
						return
					}
					if security == "krb5p" && bytes.Contains(reply, payload) {
						t.Error("plaintext response on wire")
						return
					}
					if proc == 1 || proc == 6 {
						d := &decoder{b: reply}
						d.take(12)
						d.u32()
						d.opaque(400)
						status := d.u32()
						if d.err != nil || status != 0 {
							return
						}
						bodyOffset := len(reply) - len(d.b)
						if proc == 1 {
							previousResult = append([]byte(nil), d.b...)
						}
						if proc == 6 && !changed {
							switch mode {
							case "wire-privacy":
								sealed := d.opaque(maxRecord)
								if d.err != nil || len(sealed) < 60 || sealed[2]&2 == 0 {
									return
								}
								changed = true
							case "read-payload":
								token := d.opaque(maxRecord)
								if security == "krb5p" {
									if d.err != nil || len(token) < 60 {
										return
									}
									token[len(token)-1] ^= 1
									changed = true
									break
								}
								result := &decoder{b: token}
								result.u32()
								result.u32()
								postAttr(result)
								result.u32()
								result.boolean()
								data := result.opaque(maxRecord)
								if d.err != nil || result.err != nil || len(data) == 0 {
									return
								}
								data[0] ^= 1
								changed = true
							case "replay-result":
								if len(previousResult) == 0 {
									return
								}
								reply = append(reply[:bodyOffset], previousResult...)
								changed = true
							}
						}
					}
					if _, err := downstream.Write(record(reply, true)); err != nil {
						return
					}
				}
			}()
			cfg := Config{Host: "127.0.0.1", Version: "3", Security: security, Transport: "tcp", Timeout: 3 * time.Second, NFSPort: listener.Addr().(*net.TCPAddr).Port, MountPort: mountPort,
				Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			ctx := context.Background()
			c, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			export := "/integrity"
			if security == "krb5p" {
				export = "/private"
			}
			root, err := c.Mount(ctx, export)
			if err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("tamper-%s-%d", mode, time.Now().UnixNano())
			file, err := c.Create(ctx, root.Handle, name, 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.WriteFrom(ctx, file.Handle, bytes.NewReader(payload))
			if mode == "write-payload" {
				if err == nil {
					t.Fatal("tampered WRITE accepted")
				}
				// Read through a fresh authenticated connection to prove rejection happened
				// before the server changed the file, rather than only rejecting a response.
				cfg.NFSPort = directPort
				verifier, err := Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer verifier.Close()
				a, err := verifier.GetAttr(ctx, file.Handle)
				if err != nil || a.Size != 0 {
					t.Fatalf("server applied tampered WRITE: size=%d err=%v", a.Size, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				n, err := c.ReadTo(ctx, file.Handle, &output)
				if mode == "wire-privacy" {
					if err != nil || n != int64(len(payload)) || !bytes.Equal(output.Bytes(), payload) {
						t.Fatalf("private round trip: n=%d err=%v", n, err)
					}
					return
				}
				want := "result signature verification failed"
				if security == "krb5p" {
					want = "privacy authentication failed"
				}
				if mode == "replay-result" {
					want = "result sequence mismatch"
					if security == "krb5p" {
						want = "privacy result sequence or length mismatch"
					}
				}
				if err == nil || !strings.Contains(err.Error(), want) || n != 0 || output.Len() != 0 {
					t.Fatalf("unverified data exposed: n=%d bytes=%d err=%v", n, output.Len(), err)
				}
			}
			if _, err := c.GetAttr(ctx, file.Handle); err == nil {
				t.Fatal("reused failed integrity connection")
			}
		})
	}
}
