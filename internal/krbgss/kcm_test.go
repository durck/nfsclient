package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Independent Heimdal IPC framing fixture. It only accepts four read operations;
// the immutable source payload is FILE v4, not the client's parsed structures.
func kcmTestPeer(t *testing.T, conn net.Conn, mode string, wire []byte) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	// Independently locate the realm/components using FILE v4 counted strings.
	size := 8
	count := int(binary.BigEndian.Uint32(wire[8:12]))
	for i := 0; i <= count; i++ {
		size += 4 + int(binary.BigEndian.Uint32(wire[4+size:8+size]))
	}
	principal, cred := bytes.Clone(wire[4:4+size]), bytes.Clone(wire[4+size:])
	go func() {
		defer close(done)
		defer conn.Close()
		defer clear(principal)
		defer clear(cred)
		calls := map[uint16]int{}
		for {
			var h [4]byte
			if _, err := io.ReadFull(conn, h[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(h[:])
			if n < 5 || n > 512 {
				t.Error("KCM request budget")
				return
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(conn, b); err != nil {
				return
			}
			op := binary.BigEndian.Uint16(b[2:4])
			nameEnd := bytes.IndexByte(b[4:], 0)
			if b[0] != 2 || b[1] != 0 || nameEnd < 0 || string(b[4:4+nameEnd]) != "fixture" {
				t.Error("wrong KCM selected cache/version")
				return
			}
			extra := b[5+nameEnd:]
			calls[op]++
			var payload []byte
			switch op {
			case 22:
				payload = make([]byte, 4)
				if mode == "offset" {
					payload[3] = 1
				}
				if mode == "offset-short" {
					payload = payload[:3]
				}
			case 8:
				payload = bytes.Clone(principal)
				if mode == "principal-nul" {
					payload = append(payload, 0)
				}
				if mode == "principal-trailing" {
					payload = append(payload, 0, 0)
				}
				if mode == "principal-change" && calls[op] > 1 {
					payload[len(payload)-1] ^= 1
				}
			case 9:
				payload = bytes.Repeat([]byte{1}, 16)
				switch mode {
				case "uuid-zero":
					clear(payload)
				case "uuid-short":
					payload = payload[:15]
				case "uuid-empty":
					payload = nil
				case "uuid-duplicate":
					payload = append(payload, payload...)
				case "uuid-many":
					payload = make([]byte, 16*65)
				case "list-change":
					if calls[op] > 1 {
						payload[0] = 2
					}
				}
			case 10:
				if !bytes.Equal(extra, bytes.Repeat([]byte{1}, 16)) {
					t.Error("unknown KCM UUID")
					return
				}
				extra = nil
				payload = bytes.Clone(cred)
				if mode == "credential-change" && calls[op] > 1 {
					payload[len(payload)-1] ^= 1
				}
				if mode == "credential-truncated" {
					payload = payload[:len(payload)-1]
				}
				if mode == "credential-double" {
					payload = append(payload, payload...)
				}
			default:
				t.Errorf("KCM sent non-read operation %d", op)
				return
			}
			if len(extra) != 0 {
				t.Error("extra KCM request arguments")
				return
			}
			if mode == "drop" {
				return
			}
			if mode == "cancel" {
				var b [1]byte
				conn.Read(b[:])
				return
			}
			code, transport := uint32(0), uint32(0)
			if mode == "denied" {
				code = uint32(13)
			}
			if mode == "transport" {
				transport = 5
			}
			response := binary.BigEndian.AppendUint32(nil, code)
			response = append(response, payload...)
			n = lenAsU32(response)
			if mode == "reply-large" {
				n = maxCCacheSize + 1
			}
			if mode == "reply-short" {
				n = 3
			}
			packet := binary.BigEndian.AppendUint32(nil, n)
			packet = binary.BigEndian.AppendUint32(packet, transport)
			packet = append(packet, response...)
			for len(packet) > 0 {
				part := min(len(packet), 3)
				if _, err := conn.Write(packet[:part]); err != nil {
					return
				}
				packet = packet[part:]
			}
			clear(payload)
			clear(response)
		}
	}()
	return done
}
func lenAsU32(b []byte) uint32 { return uint32(len(b)) }

func TestKCMSnapshot(t *testing.T) {
	for _, mode := range []string{"success", "principal-nul", "offset", "offset-short", "principal-trailing", "principal-change", "uuid-zero", "uuid-short", "uuid-empty", "uuid-duplicate", "uuid-many", "list-change", "credential-change", "credential-truncated", "credential-double", "drop", "denied", "transport", "reply-large", "reply-short", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			done := kcmTestPeer(t, server, mode, syntheticCCache(4, "root"))
			defer func() { client.Close(); <-done }()
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 500*time.Millisecond)
			defer cancel()
			if mode == "cancel" {
				time.AfterFunc(10*time.Millisecond, cancel)
			}
			c, err := readKCMConn(ctx, client, "fixture")
			if (err == nil) != (mode == "success" || mode == "principal-nul") {
				t.Fatal("wrong snapshot result", err)
			}
			if mode == "success" && (c.DefaultPrincipal.Realm != "NFS.TEST" || len(c.Credentials) != 1 || !bytes.Equal(c.Credentials[0].Key.KeyValue, bytes.Repeat([]byte{0x42}, 32))) {
				t.Fatal("wrong credential")
			}
		})
	}
}

func TestKCMSelectionBounds(t *testing.T) {
	for i, tc := range []struct{ name, socket string }{{"FILE:cache", "socket"}, {"KCM:", "/tmp/kcm"}, {"KCM:name\x00", "/tmp/kcm"}, {"KCM:name", "relative"}, {"KCM:name", ""}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if ValidateCCacheSelection(tc.name, tc.socket) == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
}
