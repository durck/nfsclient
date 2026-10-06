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

func objectWriteCredential(id, system, key []byte, object uint64, rights byte, expiry time.Time, unsecured bool) []byte {
	partition := uint64(0x10000)
	if object == 0 {
		partition = 0
	}
	cap, capKey := testiscsi.OSDCredential(system, key, partition, object, rights, expiry)
	if unsecured {
		cap = make([]byte, 80)
		capKey = nil
	}
	b := append([]byte(nil), id...)
	b = blockCLIQuad(b, partition)
	b = blockCLIQuad(b, object)
	b = missingV4Words(b, 1, 0)
	b = missingV4Opaque(b, capKey)
	return missingV4Opaque(b, cap)
}

func TestSecuredObjectRangeWrite(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"aligned", "stripe-crossing", "cli", "rights-unused", "root-second-nosec", "nosec", "expired", "component-short", "unbounded", "no-approval", "extend", "source-change", "identity", "cancel", "expiry", "recall", "osd-write-short", "osd-write-error", "osd-write-drop", "osd-flush-drop", "commit-error", "commit-size", "commit-lost"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runSecuredObjectRangeWrite(t, minor, mode) })
		}
	}
}

func runSecuredObjectRangeWrite(t *testing.T, minor uint32, mode string) {
	t.Helper()
	dir := t.TempDir()
	path, source := filepath.Join(dir, "device"), filepath.Join(dir, "patch")
	original := make([]byte, 1301)
	for i := range original {
		original[i] = byte(i*17 + 3)
	}
	patch := bytes.Repeat([]byte{0xab}, 401)
	offset := uint64(41)
	if mode == "aligned" {
		offset = 0
		patch = patch[:388]
	}
	if mode == "rights-unused" {
		patch = patch[:10]
	}
	for p, b := range map[string][]byte{path: make([]byte, 512), source: patch} {
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	id, system, key := bytes.Repeat([]byte{0x21}, 16), bytes.Repeat([]byte{0x31}, 20), bytes.Repeat([]byte{0x41}, 20)
	secondID := bytes.Repeat([]byte{0x22}, 16)
	objects := map[[2]uint64][]byte{{0x10000, 0x10001}: {}, {0x10000, 0x10002}: {}}
	for i, b := range original {
		k := [2]uint64{0x10000, 0x10001 + uint64(i/97%2)}
		objects[k] = append(objects[k], b)
	}
	if mode == "component-short" {
		objects[[2]uint64{0x10000, 0x10002}] = objects[[2]uint64{0x10000, 0x10002}][:10]
	}
	storage := testiscsi.Start(t, path, testiscsi.Options{OSDSystemID: system, OSDKey: key, OSDObjects: objects, Fault: mode, AllowProcessKill: true})
	target, err := iscsi.ParseTarget(storage.URL())
	if err != nil {
		t.Fatal(err)
	}
	p := &blockCLIPeer{minor: minor, mode: mode, length: uint64(len(original)), write: true}
	lsid := append(missingV4Words(nil, 1), bytes.Repeat([]byte{8}, 12)...)
	expiry := time.Now().Add(time.Hour)
	if mode == "expiry" {
		expiry = time.Now().Add(1500 * time.Millisecond)
	}
	if mode == "expired" {
		expiry = time.Now().Add(-time.Second)
	}
	confirmed := offset
	p.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
		var e []byte
		switch code {
		case 50:
			p.layouts.Add(1)
			if d.word() != 0 || d.word() != 2 || d.word() != 2 || !bytes.Equal(d.take(8), make([]byte, 8)) {
				return nil, 0, errors.New("object write LAYOUTGET mode/range"), true
			}
			d.take(16)
			if !bytes.Equal(d.take(16), bytes.Repeat([]byte{6}, 16)) || d.word() != 32768 {
				return nil, 0, errors.New("object write LAYOUTGET lock"), true
			}
			e = missingV4Words(e, 1)
			e = append(e, lsid...)
			e = missingV4Words(e, 1)
			e = blockCLIQuad(e, 0)
			span := uint64(len(original))
			if mode == "unbounded" {
				span = math.MaxUint64
			}
			e = blockCLIQuad(e, span)
			e = missingV4Words(e, 2, 2)
			body := missingV4Words(nil, 2)
			body = blockCLIQuad(body, 97)
			body = missingV4Words(body, 0, 0, 0, 1, 0, 2)
			for _, object := range []uint64{0x10001, 0x10002} {
				rights := byte(0xe2)
				if mode == "rights-unused" && object == 0x10002 {
					rights = 0xa0
				}
				deviceID := id
				if mode == "root-second-nosec" && object == 0x10002 {
					deviceID = secondID
				}
				body = append(body, objectWriteCredential(deviceID, system, key, object, rights, expiry, mode == "nosec")...)
			}
			e = missingV4Opaque(e, body)
		case 47:
			p.devices.Add(1)
			deviceID := d.take(16)
			if (!bytes.Equal(deviceID, id) && !(mode == "root-second-nosec" && bytes.Equal(deviceID, secondID))) || d.word() != 2 || d.word() != 32768 || d.word() != 0 {
				return nil, 0, errors.New("object write GETDEVICEINFO"), true
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
			body = append(body, objectWriteCredential(deviceID, system, key, 0, 0x20, time.Now().Add(time.Hour), mode == "root-second-nosec" && bytes.Equal(deviceID, secondID))...)
			body = missingV4Opaque(body, nil)
			e = missingV4Words(e, 2)
			e = missingV4Opaque(e, body)
			e = missingV4Words(e, 0)
		case 49:
			//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
			if binary.BigEndian.Uint64(d.take(8)) != 0 || binary.BigEndian.Uint64(d.take(8)) != 0 || d.word() != 0 || !bytes.Equal(d.take(16), lsid) || d.word() != 1 {
				return nil, 0, errors.New("object LAYOUTCOMMIT geometry/state"), true
			}
			last := binary.BigEndian.Uint64(d.take(8))
			if d.word() != 0 || d.word() != 2 || !bytes.Equal(d.opaque(), make([]byte, 8)) {
				return nil, 0, errors.New("object layout update body"), true
			}
			actions := storage.OSDActions()
			if len(actions) == 0 || actions[len(actions)-1] != 0x8808 || last < confirmed || last >= offset+uint64(len(patch)) {
				return nil, 0, errors.New("metadata publication before OSD flush"), true
			}
			p.committed.Add(1)
			confirmed = last + 1
			if mode == "commit-error" {
				return nil, 5, nil, true
			}
			if mode == "commit-size" {
				return blockCLIQuad(missingV4Words(nil, 1), uint64(len(original))+1), 0, nil, true
			}
			e = missingV4Words(e, 0)
		case 51:
			p.returned.Add(1)
			if d.word() != 0 || d.word() != 2 || d.word() != 3 || d.word() != 1 {
				return nil, 0, errors.New("object return profile"), true
			}
			d.take(16)
			if !bytes.Equal(d.take(16), lsid) {
				return nil, 0, errors.New("object return state"), true
			}
			report := d.opaque()
			if len(report) != 4 && len(report) != 60 {
				return nil, 0, errors.New("object I/O report length"), true
			}
			if strings.HasPrefix(mode, "osd-write-") || mode == "osd-flush-drop" {
				if len(report) != 60 || binary.BigEndian.Uint32(report[52:56]) != 1 {
					return nil, 0, errors.New("write error not reported to MDS"), true
				}
			}
			e = missingV4Words(e, 0)
		default:
			return nil, 0, nil, false
		}
		return e, 0, nil, true
	}
	recalled := false
	p.beforeReply = func(c net.Conn) error {
		if p.committed.Load() != 1 {
			return nil
		}
		if mode == "commit-lost" {
			return io.EOF
		}
		if mode != "recall" || recalled {
			return nil
		}
		recalled = true
		b := missingV4Words(nil, 17, 0, 2, 0x40000001, 1, 1, 0, 0, 0, 0, 0, minor, 0, 2, 11)
		b = append(b, bytes.Repeat([]byte{9}, 16)...)
		b = missingV4Words(b, 1, 0, 0, 1, 0, 5, 2, 2, 0, 1)
		b = missingV4Opaque(b, []byte("target"))
		b = blockCLIQuad(b, 0)
		b = blockCLIQuad(b, math.MaxUint64)
		b = append(b, lsid...)
		wire := missingV4Words(nil, uint32(len(b))|0x80000000)
		wire = append(wire, b...)
		if _, err := c.Write(wire); err != nil {
			return err
		}
		reply, _, err := readObservedRPC(c)
		if err != nil {
			return err
		}
		if len(reply) < 28 || binary.BigEndian.Uint32(reply[24:28]) != 0 {
			return errors.New("object callback was not accepted")
		}
		return nil
	}
	policy, server := referralTLSPolicy(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.serve(&referralTLSListener{Listener: listener, config: server}) }()
	t.Cleanup(func() {
		listener.Close()
		if err := <-done; err != nil {
			t.Error("object MDS", err)
		}
	})
	options := nfs.PNFSOptions{Layout: "object", ObjectWrite: mode != "no-approval", OSDRequireSecure: true, OSDTargets: []string{storage.URL()}, OSDInitiator: testiscsi.Initiator, Extend: mode == "extend"}
	var n int64
	if mode == "cli" {
		command := "putrangepnfs " + strconv.Quote(source) + " target " + strconv.FormatUint(offset, 10) + " --layout object --object-write --osd-secure --osd-target " + strconv.Quote(storage.URL()) + " --osd-initiator " + testiscsi.Initiator
		args := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "--pnfs", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never", "--tls", "--tls-ca", policy.CAFile, "--tls-server-name", policy.ServerName, "-c", "lock target write", "-c", command, "-c", "unlock 1"}
		out, e := runKerberosCLI(t, args)
		if e != nil {
			t.Fatal(e, out)
		}
		n = int64(len(patch))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, e := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: fmt.Sprintf("4.%d", minor), Transport: "tcp", NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: 2 * time.Second, PNFS: true, TLS: policy})
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		s := session.New(c, "127.0.0.1", false, false, io.Discard)
		if e = s.Use(ctx, "/"); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Lock(ctx, "target", true); e != nil {
			t.Fatal(e)
		}
		progress := func(done, total uint64) {
			if done == 0 {
				return
			}
			switch mode {
			case "source-change":
				if e := os.WriteFile(source, []byte("changed"), 0600); e != nil {
					t.Error(e)
				}
			case "identity":
				s.BaseAuth.UID++
			case "cancel":
				cancel()
			case "expiry":
				time.Sleep(1600 * time.Millisecond)
			}
		}
		n, err = s.PutPNFSRange(ctx, source, "target", offset, options, progress)
		if mode == "aligned" || mode == "stripe-crossing" {
			if err != nil || n != int64(len(patch)) {
				t.Fatal(n, err)
			}
		} else if err == nil {
			t.Fatal("unsafe object write succeeded", n)
		}
		if mode == "source-change" || mode == "identity" || mode == "cancel" || mode == "expiry" || mode == "recall" {
			if n != int64(97-offset%97) {
				t.Fatal("confirmed prefix lost", n, err)
			}
		}
		if strings.HasPrefix(mode, "osd-") || strings.HasPrefix(mode, "commit-") {
			if n != 0 {
				t.Fatal("uncertain first chunk reported", n, err)
			}
			if c.RequireRangeLock([]byte("target"), offset, uint64(len(patch)), true) == nil {
				t.Fatal("uncertain object session not quarantined")
			}
		}
	}
	if mode == "aligned" || mode == "stripe-crossing" || mode == "cli" {
		expected := bytes.Clone(original)
		copy(expected[offset:], patch)
		for i, b := range expected {
			object := uint64(0x10001 + i/97%2)
			physical := (i/194)*97 + i%97
			if storage.ObjectBytes(0x10000, object)[physical] != b {
				t.Fatalf("physical object bytes differ at %d", i)
			}
		}
		if n != int64(len(patch)) {
			t.Fatal("full count mismatch", n)
		}
	}
	writes := 0
	if mode == "root-second-nosec" && len(storage.OSDActions()) != 0 {
		t.Fatal("storage accessed before every root was approved")
	}
	for _, a := range storage.OSDActions() {
		if a == 0x8806 {
			writes++
		}
	}
	if mode == "rights-unused" || mode == "nosec" || mode == "expired" || mode == "component-short" || mode == "unbounded" || mode == "no-approval" || mode == "extend" {
		if writes != 0 {
			t.Fatal("write before complete preflight", writes)
		}
	}
	if strings.HasPrefix(mode, "osd-") || strings.HasPrefix(mode, "commit-") {
		if writes != 1 {
			t.Fatal("uncertain write replayed", writes)
		}
	}
}

func TestObjectWriteCLIArguments(t *testing.T) {
	for _, command := range []string{
		"putpnfs a b --layout object --object-write",
		"getpnfs a b --layout object --object-write",
		"putrangepnfs a b 0 --layout object",
		"putrangepnfs a b 0 --layout object --object-write --extend",
		"putrangepnfs a b 0 --layout object --object-write --object-write",
		"putrangepnfs a b 0 --layout file --object-write",
		"putrangepnfs a b 0 --layout file --osd-secure",
	} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), command); err == nil {
			t.Fatalf("unsafe arguments accepted: %s", command)
		}
	}
}
