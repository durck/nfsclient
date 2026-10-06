package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This opt-in test intentionally also reproduces the packaged Ganesha failure.
// It uses the public connection path and only the selected loopback fixture.
func TestKerberosUDPProtectedInterop(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_UDP_PROTECTED") != "1" {
		t.Skip("requires explicit protected-UDP server fixture")
	}
	nfsPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	mountPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	for _, security := range []string{"krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) {
			cfg := Config{Host: "127.0.0.1", Version: "3", Transport: "udp", Security: security, Timeout: 3 * time.Second,
				NFSPort: nfsPort, MountPort: mountPort,
				Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			ctx := context.Background()
			c, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			root, err := c.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			file, err := c.Create(ctx, root.Handle, fmt.Sprintf("protected-udp-%d", time.Now().UnixNano()), 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte{0, 255, 'U', 'D', 'P', 27}, 2000)
			if _, err := c.WriteFrom(ctx, file.Handle, bytes.NewReader(payload)); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if _, err := c.ReadTo(ctx, file.Handle, &out); err != nil || !bytes.Equal(out.Bytes(), payload) {
				t.Fatalf("protected UDP round trip: %v", err)
			}
		})
	}
}

// Drop/tamper real MIT/Ganesha replies, so UDP retry and verification are also
// exercised with a real GSS replay window and cryptographic sequence signatures.
func TestKerberosUDPReplies(t *testing.T) {
	port := os.Getenv("NFS_VIEWER_KRB5_UDP_PORT")
	if port == "" {
		t.Skip("requires tests/kerberos UDP fixture")
	}
	mountPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"lost-reply", "altered-signature", "replayed-signature"} {
		t.Run(mode, func(t *testing.T) {
			downstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			upstream, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", port), time.Second)
			if err != nil {
				downstream.Close()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			calls := 0
			go func() {
				var firstReply []byte
				var firstXID, firstSeq uint32
				buf := make([]byte, 65536)
				for {
					downstream.SetReadDeadline(time.Now().Add(8 * time.Second))
					n, addr, err := downstream.ReadFromUDP(buf)
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							err = nil
						}
						done <- err
						return
					}
					request := append([]byte(nil), buf[:n]...)
					d := &decoder{b: request}
					xid := d.u32()
					d.take(16)
					proc, flavor := d.u32(), d.u32()
					cred := &decoder{b: d.opaque(400)}
					cred.u32()
					control, seq := cred.u32(), cred.u32()
					if d.err != nil || cred.err != nil || flavor != 6 {
						done <- fmt.Errorf("invalid GSS request in relay")
						return
					}
					upstream.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err := upstream.Write(request); err != nil {
						done <- err
						return
					}
					n, err = upstream.Read(buf)
					if err != nil {
						done <- err
						return
					}
					reply := append([]byte(nil), buf[:n]...)
					if control == 0 && proc == 0 {
						calls++
						if calls == 1 && mode != "altered-signature" {
							firstXID, firstSeq, firstReply = xid, seq, reply
							continue // The server processed it; lose only its reply.
						}
						if calls == 2 {
							if xid == firstXID || seq != firstSeq+1 {
								done <- fmt.Errorf("retry reused XID/GSS sequence")
								return
							}
							if mode == "replayed-signature" {
								// Adjust only the public XID; the signed sequence is old.
								reply = firstReply
								binary.BigEndian.PutUint32(reply, xid)
							} else if _, err := downstream.WriteToUDP(firstReply, addr); err != nil {
								done <- err
								return
							}
						}
						if mode == "altered-signature" {
							r := &decoder{b: reply}
							r.take(16)
							mic := r.opaque(400)
							if r.err != nil || len(mic) == 0 {
								done <- fmt.Errorf("missing real reply MIC")
								return
							}
							mic[len(mic)-1] ^= 1
						}
					}
					if _, err := downstream.WriteToUDP(reply, addr); err != nil {
						done <- err
						return
					}
				}
			}()
			defer func() {
				downstream.Close()
				upstream.Close()
				if err := <-done; err != nil {
					t.Error(err)
				}
				want := 2
				if mode == "altered-signature" {
					want = 1
				}
				if calls != want {
					t.Errorf("signed NULL calls = %d, want %d", calls, want)
				}
			}()
			cfg := Config{Host: "127.0.0.1", Version: "auto", Transport: "udp", Security: "krb5", Timeout: 5 * time.Second,
				NFSPort: downstream.LocalAddr().(*net.UDPAddr).Port, MountPort: mountPort,
				Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			c, err := Connect(context.Background(), cfg)
			if c != nil {
				defer c.Close()
			}
			if mode == "lost-reply" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.Mount(context.Background(), "/data"); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
				t.Fatalf("tampered/replayed signature: %v", err)
			}
		})
	}
}
