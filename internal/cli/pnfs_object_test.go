package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/iscsi"
	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
	"nfs-viewer/internal/testiscsi"
)

func cliObjectCred(id []byte, object uint64, root bool) []byte {
	b := bytes.Clone(id)
	p := uint64(0x10000)
	if root {
		p = 0
	}
	b = blockCLIQuad(b, p)
	b = blockCLIQuad(b, object)
	b = missingV4Words(b, 1, 0)
	b = missingV4Opaque(b, nil)
	return missingV4Opaque(b, make([]byte, 80))
}

func TestObjectDownloadPublication(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli", "secure-api", "secure-cli", "alldata-api", "alldata-cli", "alldata-osd-secure-icv", "alldata-osd-secure-status", "alldata-return-failure", "alldata-close-failure", "alldata-collision", "alldata-cancel", "osd-id", "osd-drop", "return-failure", "close-failure", "source-change", "collision", "cancel"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				secure := strings.HasPrefix(mode, "secure-")
				allData := strings.HasPrefix(mode, "alldata-")
				mode = strings.TrimPrefix(mode, "secure-")
				mode = strings.TrimPrefix(mode, "alldata-")
				security, storageOptions, profile := secureStorageFixture(t, secure)
				dir := t.TempDir()
				path, dest := filepath.Join(dir, "fixture"), filepath.Join(dir, "download")
				if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
					t.Fatal(err)
				}
				id, system := bytes.Repeat([]byte{0x21}, 16), bytes.Repeat([]byte{0x31}, 20)
				var workingKey []byte
				if allData {
					workingKey = bytes.Repeat([]byte{0x62}, 20)
					storageOptions.OSDKey = workingKey
				}
				credentialWire := func(object uint64, root bool) []byte {
					if !allData {
						return cliObjectCred(id, object, root)
					}
					partition := uint64(0x10000)
					if root {
						partition = 0
					}
					cap, key := testiscsi.OSDCredential(system, workingKey, partition, object, iscsi.ObjectRead|iscsi.ObjectGetAttributes, time.Now().Add(time.Hour))
					b := blockCLIQuad(bytes.Clone(id), partition)
					b = blockCLIQuad(b, object)
					b = missingV4Words(b, 1, 0)
					b = missingV4Opaque(b, key)
					return missingV4Opaque(b, cap)
				}
				want := make([]byte, 1301)
				for i := range want {
					want[i] = byte(i*23 + 7)
				}
				objects := map[[2]uint64][]byte{{0x10000, 0x10001}: {}, {0x10000, 0x10002}: {}}
				for i, b := range want {
					k := [2]uint64{0x10000, 0x10001 + uint64((i/97)%2)}
					objects[k] = append(objects[k], b)
				}
				storageOptions.OSDSystemID = system
				storageOptions.OSDObjects = objects
				storageOptions.Fault = mode
				storageOptions.AllowProcessKill = true
				storage := testiscsi.Start(t, path, storageOptions)
				var policies map[string]iscsi.Security
				if secure {
					policies = storagePolicies(storage.URL(), security)
				}
				target, err := iscsi.ParseTarget(storage.URL())
				if err != nil {
					t.Fatal(err)
				}
				p := &blockCLIPeer{minor: minor, mode: mode, length: uint64(len(want))}
				lsid := bytes.Repeat([]byte{8}, 16)
				binary.BigEndian.PutUint32(lsid, 1)
				p.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
					var e []byte
					switch code {
					case 50:
						p.layouts.Add(1)
						if d.word() != 0 || d.word() != 2 || d.word() != 1 {
							return nil, 0, errors.New("incorrect object layout type"), true
						}
						d.take(24)
						d.take(16)
						if d.word() != 32768 {
							return nil, 0, errors.New("incorrect object reply budget"), true
						}
						e = missingV4Words(e, 1)
						e = append(e, lsid...)
						e = missingV4Words(e, 1)
						e = blockCLIQuad(e, 0)
						e = blockCLIQuad(e, math.MaxUint64)
						e = missingV4Words(e, 1, 2)
						body := missingV4Words(nil, 2)
						body = blockCLIQuad(body, 97)
						body = missingV4Words(body, 0, 0, 0, 1, 0, 2)
						body = append(body, credentialWire(0x10001, false)...)
						body = append(body, credentialWire(0x10002, false)...)
						e = missingV4Opaque(e, body)
					case 47:
						p.devices.Add(1)
						if !bytes.Equal(d.take(16), id) || d.word() != 2 || d.word() != 32768 || d.word() != 0 {
							return nil, 0, errors.New("incorrect object device request"), true
						}
						body := missingV4Words(nil, 2)
						body = missingV4Opaque(body, []byte(target.Name))
						body = missingV4Words(body, 1)
						body = missingV4Opaque(body, []byte("tcp"))
						host, port, _ := net.SplitHostPort(target.Endpoint)
						pn, _ := strconv.Atoi(port)
						body = missingV4Opaque(body, []byte(fmt.Sprintf("%s.%d.%d", host, pn/256, pn%256)))
						body = append(body, make([]byte, 8)...)
						body = missingV4Opaque(body, system)
						body = append(body, credentialWire(0, true)...)
						body = missingV4Opaque(body, nil)
						e = missingV4Words(e, 2)
						e = missingV4Opaque(e, body)
						e = missingV4Words(e, 0)
					case 51:
						p.returned.Add(1)
						if d.word() != 0 || d.word() != 2 || d.word() != 3 || d.word() != 1 {
							return nil, 0, errors.New("incorrect object return type"), true
						}
						d.take(16)
						if !bytes.Equal(d.take(16), lsid) {
							return nil, 0, errors.New("incorrect object return state"), true
						}
						body := d.opaque()
						if len(body) != 4 && len(body) != 60 {
							return nil, 0, errors.New("incorrect OSD report length"), true
						}
						if mode == "return-failure" {
							return nil, 10025, nil, true
						}
						e = missingV4Words(e, 0)
					default:
						return nil, 0, nil, false
					}
					return e, 0, nil, true
				}
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				var policy nfs.TLSConfig
				var served net.Listener = listener
				if allData {
					tlsPolicy, server := referralTLSPolicy(t)
					policy = tlsPolicy
					served = &referralTLSListener{Listener: listener, config: server}
				}
				go func() { done <- p.serve(served) }()
				t.Cleanup(func() {
					listener.Close()
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if mode == "cli" {
					args := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "--pnfs", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never", "-c", "getpnfs target " + strconv.Quote(dest) + " --layout object --osd-target " + strconv.Quote(storage.URL()) + " --osd-initiator " + testiscsi.Initiator}
					if secure {
						args[len(args)-1] += " --osd-security " + strconv.Quote(storage.URL()+"="+profile)
					}
					if allData {
						args[len(args)-1] += " --osd-secure"
						args = append(args, "--tls", "--tls-ca", policy.CAFile, "--tls-server-name", policy.ServerName)
					}
					out, err := runKerberosCLI(t, args)
					if err != nil {
						t.Fatal(err, out)
					}
				} else {
					c, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: fmt.Sprintf("4.%d", minor), Transport: "tcp", NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: 2 * time.Second, PNFS: true, TLS: policy})
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					s := session.New(c, "127.0.0.1", false, false, io.Discard)
					if err := s.Use(ctx, "/"); err != nil {
						t.Fatal(err)
					}
					if mode == "collision" {
						if err := os.WriteFile(dest, []byte("competitor"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					_, err = s.GetPNFS(ctx, "target", dest, nfs.PNFSOptions{Layout: "object", OSDTargets: []string{storage.URL()}, OSDInitiator: testiscsi.Initiator, OSDSecurity: policies, OSDRequireSecure: allData}, func(done, total uint64) {
						if done > 0 && mode == "cancel" {
							cancel()
						}
					})
					if mode == "api" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil {
						t.Fatal("unsafe download published", mode)
					}
				}
				if mode == "api" || mode == "cli" {
					got, err := os.ReadFile(dest)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatal(err, "wrong published bytes")
					}
				} else if mode == "collision" {
					got, err := os.ReadFile(dest)
					if err != nil || string(got) != "competitor" {
						t.Fatal("collision changed")
					}
				} else if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed download published", err)
				}
			})
		}
	}
}
