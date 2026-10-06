package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func policyACE(kind, flags, mask uint32, who string) []byte {
	return missingV4Opaque(missingV4Words(nil, kind, flags, mask), []byte(who))
}
func policyFields(private bool) map[uint32][]byte {
	mode, owner, group := uint32(07640), "original@example.test", "original-group@example.test"
	if private {
		mode, owner, group = 0600, "uploader@example.test", "uploaders@example.test"
	}
	allow := policyACE(0, 0, 7, "OWNER@")
	audit := policyACE(2, 0x10, 1, "EVERYONE@")
	legacy := append(missingV4Words(nil, 2), allow...)
	legacy = append(legacy, audit...)
	dacl := append(missingV4Words(nil, 3, 1), policyACE(0, 0x80, 7, "OWNER@")...)
	sacl := append(missingV4Words(nil, 5, 1), policyACE(2, 0x90, 1, "EVERYONE@")...)
	label := missingV4Opaque(missingV4Words(nil, 7, 42), []byte{0, 255, 'a'})
	return map[uint32][]byte{0: blockCLIBitmap(nil, []uint32{0, 1, 3, 4, 7, 8, 10, 12, 13, 20, 30, 31, 33, 36, 37, 52, 53, 58, 59, 80}), 1: missingV4Words(nil, 1), 3: blockCLIQuad(nil, 7), 4: blockCLIQuad(nil, 0), 7: missingV4Words(nil, 0), 8: blockCLIQuad(blockCLIQuad(nil, 1), 0), 10: missingV4Words(nil, 60), 12: legacy, 13: missingV4Words(nil, 15), 20: blockCLIQuad(nil, 2), 30: blockCLIQuad(nil, 32768), 31: blockCLIQuad(nil, 32768), 33: missingV4Words(nil, mode), 36: missingV4Opaque(nil, []byte(owner)), 37: missingV4Opaque(nil, []byte(group)), 52: missingV4Words(nil, 0, 1, 0), 53: missingV4Words(nil, 0, 1, 0), 58: dacl, 59: sacl, 80: label}
}

func TestReplacementPolicyPublication(t *testing.T) {
	for _, mode := range []string{"api", "cli", "owner-denied", "missing-ack", "label-change", "sacl-change", "mode-cleared", "source-change", "identity-change", "private-allow", "attributes-api", "attributes-cli", "attributes-denied", "attributes-readback", "attributes-source-change", "attributes-cli-denied"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			dir := t.TempDir()
			path := filepath.Join(dir, "upload")
			want := []byte("new payload\x00\xff")
			if err := os.WriteFile(path, want, 0600); err != nil {
				t.Fatal(err)
			}
			original, stage := policyFields(false), policyFields(true)
			attributes := strings.HasPrefix(mode, "attributes-")
			oldX := map[string][]byte{"user.empty": {}, "user.binary": {0, 255, 1}}
			newX := map[string][]byte{}
			oldNamed := []byte{255, 0, 'n', 'a'}
			var newNamed []byte
			namedCreated := false
			namedOriginal, namedStage := policyFields(false), policyFields(true)
			if attributes {
				for _, fields := range []map[uint32][]byte{original, stage} {
					fields[0] = blockCLIBitmap(nil, []uint32{0, 1, 3, 4, 7, 8, 10, 12, 13, 20, 30, 31, 33, 36, 37, 52, 53, 58, 59, 80, 82})
					fields[82] = missingV4Words(nil, 1)
				}
				original[7] = missingV4Words(nil, 1)
			}
			originalData := []byte("old contents")
			original[4] = blockCLIQuad(nil, uint64(len(originalData)))
			stageData := []byte{}
			stageName := ""
			published, removed := false, false
			var setters [][]uint32
			if mode == "private-allow" {
				stage[58] = append(missingV4Words(nil, 1, 2), policyACE(0, 0, 7, "OWNER@")...)
				stage[58] = append(stage[58], policyACE(0, 0, 1, "EVERYONE@")...)
			}
			p := &blockCLIPeer{minor: 2}
			p.operationHook = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error, bool) {
				var e []byte
				switch code {
				case 43:
					d.take(8)
					seq := d.word()
					d.word()
					fore, back := d.take(28), d.take(28)
					d.word()
					if d.word() != 0 {
						return nil, 0, errors.New("unexpected ordinary callback credentials"), true
					}
					e = append(e, bytes.Repeat([]byte{9}, 16)...)
					e = missingV4Words(e, seq, 0)
					e = append(e, fore...)
					e = append(e, back...)
				case 9:
					fields := original
					if *current == "stage" {
						fields = stage
					}
					if *current == "old-named" || *current == "new-named" {
						fields = namedOriginal
						value := oldNamed
						if *current == "new-named" {
							fields, value = namedStage, newNamed
						}
						fields[1] = missingV4Words(nil, 9)
						fields[4] = blockCLIQuad(nil, uint64(len(value)))
					}
					if *current == "old-attrs" || *current == "new-attrs" {
						fields = policyFields(true)
						fields[1] = missingV4Words(nil, 8)
					}
					if *current == "root" {
						fields = policyFields(true)
						fields[1] = missingV4Words(nil, 2)
						fields[33] = missingV4Words(nil, 0755)
					}
					wanted := d.bitmap()
					var bits []uint32
					var values []byte
					for _, bit := range wanted {
						if val, ok := fields[bit]; ok {
							bits = append(bits, bit)
							values = append(values, val...)
						}
					}
					e = missingV4Opaque(blockCLIBitmap(nil, bits), values)
				case 15:
					name := string(d.opaque())
					if (*current == "old-attrs" || *current == "new-attrs") && name == "binary" {
						if *current == "old-attrs" {
							*current = "old-named"
						} else {
							*current = "new-named"
						}
						break
					}
					if *current != "root" {
						return nil, 0, errors.New("lookup outside replacement parent"), true
					}
					if name == "target" {
						*current = "original"
					} else if name == stageName && stageName != "" && !removed {
						*current = "stage"
					} else {
						return nil, 2, nil, true
					}
				case 18:
					d.word()
					share, deny := d.word(), d.word()
					d.take(8)
					d.opaque()
					create := d.word()
					if create == 1 {
						if d.word() != 1 || !reflect.DeepEqual(d.bitmap(), []uint32{33}) || !bytes.Equal(d.opaque(), missingV4Words(nil, 0600)) {
							return nil, 0, errors.New("nonprivate stage creation"), true
						}
					}
					if d.word() != 0 {
						return nil, 0, errors.New("invalid claim"), true
					}
					name := string(d.opaque())
					if *current == "old-attrs" || *current == "new-attrs" {
						if name != "binary" || deny != 0 || (share != 1 && share != 2) || (create == 1 && share != 2) {
							return nil, 0, errors.New("invalid named attribute OPEN"), true
						}
						if *current == "old-attrs" {
							if create != 0 || share != 1 {
								return nil, 0, errors.New("source named mutation"), true
							}
							*current = "old-named"
						} else {
							if create == 1 {
								namedCreated = true
								stage[7] = missingV4Words(nil, 1)
							}
							*current = "new-named"
						}
						e = append(e, bytes.Repeat([]byte{7}, 16)...)
						e = missingV4Words(e, 1)
						e = blockCLIQuad(blockCLIQuad(e, 1), 1)
						e = missingV4Words(e, 0, 0, 0)
						break
					}
					if share != 2 || deny != 0 || !strings.HasPrefix(name, ".nfs-upload-") {
						return nil, 0, errors.New("unexpected replacement OPEN"), true
					}
					if create == 1 {
						if stageName != "" {
							return nil, 17, nil, true
						}
						stageName = name
					} else if name != stageName {
						return nil, 0, errors.New("stage OPEN changed name"), true
					}
					*current = "stage"
					e = append(e, bytes.Repeat([]byte{7}, 16)...)
					e = missingV4Words(e, 1)
					e = blockCLIQuad(blockCLIQuad(e, 1), 1)
					e = missingV4Words(e, 0, 0, 0)
				case 3:
					d.word()
					e = missingV4Words(nil, 63, 13)
				case 38:
					if *current == "new-named" {
						d.take(16)
						off := uint64(d.word())<<32 | uint64(d.word())
						if d.word() != 2 || off != uint64(len(newNamed)) || !bytes.Equal(stageData, want) {
							return nil, 0, errors.New("invalid named WRITE"), true
						}
						data := d.opaque()
						newNamed = append(newNamed, data...)
						e = append(missingV4Words(nil, uint32(len(data)), 2), []byte("verifier")...)
						break
					}
					if *current != "stage" || len(setters) != 0 {
						return nil, 0, errors.New("payload written outside private stage"), true
					}
					d.take(16)
					off := uint64(d.word())<<32 | uint64(d.word())
					if d.word() != 2 || off != uint64(len(stageData)) {
						return nil, 0, errors.New("invalid stable WRITE"), true
					}
					data := d.opaque()
					stageData = append(stageData, data...)
					stage[4] = blockCLIQuad(nil, uint64(len(stageData)))
					if mode == "source-change" {
						original[3] = blockCLIQuad(nil, 8)
					}
					e = missingV4Words(nil, uint32(len(data)), 2)
					e = append(e, []byte("verifier")...)
				case 34:
					if (*current != "stage" && *current != "new-named") || !bytes.Equal(stageData, want) || !bytes.Equal(d.take(16), make([]byte, 16)) {
						return nil, 0, errors.New("metadata before payload or outside stage"), true
					}
					bits := d.bitmap()
					values := d.opaque()
					if *current == "new-named" {
						var expected []byte
						for _, bit := range bits {
							expected = append(expected, namedOriginal[bit]...)
						}
						if !bytes.Equal(values, expected) {
							return nil, 0, errors.New("named policy mismatch"), true
						}
						for _, bit := range bits {
							namedStage[bit] = bytes.Clone(namedOriginal[bit])
						}
						if slices.Contains(bits, uint32(58)) {
							namedStage[12] = bytes.Clone(namedOriginal[12])
						}
						return blockCLIBitmap(nil, bits), 0, nil, true
					}
					setters = append(setters, slices.Clone(bits))
					var expected []byte
					for _, bit := range bits {
						expected = append(expected, original[bit]...)
					}
					if !bytes.Equal(expected, values) {
						return nil, 0, errors.New("metadata values changed"), true
					}
					if reflect.DeepEqual(bits, []uint32{36, 37}) {
						if mode == "owner-denied" {
							return blockCLIBitmap(nil, nil), 1, nil, true
						}
						stage[33] = missingV4Words(nil, 0600)
					} else if !reflect.DeepEqual(bits, []uint32{33, 58, 59, 80}) {
						return nil, 0, errors.New("wrong final policy attributes"), true
					}
					for _, bit := range bits {
						stage[bit] = bytes.Clone(original[bit])
					}
					if len(setters) > 1 {
						stage[12] = bytes.Clone(original[12])
						switch mode {
						case "label-change":
							stage[80] = missingV4Opaque(missingV4Words(nil, 7, 42), []byte("wrong"))
						case "sacl-change":
							stage[59] = missingV4Words(nil, 0, 0)
						case "mode-cleared":
							stage[33] = missingV4Words(nil, 0640)
						}
					}
					if mode == "missing-ack" {
						return blockCLIBitmap(nil, []uint32{33}), 0, nil, true
					}
					e = blockCLIBitmap(nil, bits)
				case 32:
				case 19:
					create := d.word()
					if *current == "original" && create == 0 {
						*current = "old-attrs"
					} else if *current == "stage" {
						*current = "new-attrs"
					} else {
						return nil, 0, errors.New("OPENATTR outside files"), true
					}
				case 26:
					if *current != "old-attrs" && *current != "new-attrs" {
						return nil, 0, nil, false
					}
					d.take(8)
					d.take(8)
					d.word()
					d.word()
					if !slices.Equal(d.bitmap(), []uint32{1, 19}) {
						return nil, 0, errors.New("wrong named listing fields"), true
					}
					e = append(e, []byte("verifier")...)
					if *current == "old-attrs" || (*current == "new-attrs" && namedCreated) {
						handle := "old-named"
						if *current == "new-attrs" {
							handle = "new-named"
						}
						e = blockCLIQuad(missingV4Words(e, 1), 1)
						e = missingV4Opaque(e, []byte("binary"))
						e = missingV4Opaque(blockCLIBitmap(e, []uint32{1, 19}), missingV4Opaque(missingV4Words(nil, 9), []byte(handle)))
					}
					e = missingV4Words(e, 0, 1)
				case 25:
					d.take(16)
					off := uint64(d.word())<<32 | uint64(d.word())
					count := d.word()
					value := oldNamed
					if *current == "new-named" {
						value = newNamed
					} else if *current != "old-named" {
						return nil, 0, errors.New("READ outside named files"), true
					}
					if off > uint64(len(value)) {
						return nil, 0, errors.New("named READ offset"), true
					}
					n := min(uint64(count), uint64(len(value))-off)
					e = missingV4Opaque(missingV4Words(nil, 1), value[off:off+n])
				case 74:
					d.take(8)
					d.word()
					x := oldX
					if *current == "stage" {
						x = newX
					}
					e = missingV4Words(blockCLIQuad(nil, 0), uint32(len(x)))
					for _, name := range []string{"user.binary", "user.empty"} {
						if _, ok := x[name]; ok {
							e = missingV4Opaque(e, []byte(name))
						}
					}
					e = missingV4Words(e, 1)
				case 72:
					name := string(d.opaque())
					value := oldX[name]
					if *current == "stage" {
						value = newX[name]
						if mode == "attributes-readback" {
							value = []byte("wrong")
						}
					}
					e = missingV4Opaque(nil, value)
				case 73:
					if *current != "stage" || d.word() != 1 || !bytes.Equal(stageData, want) {
						return nil, 0, errors.New("xattr outside private stage"), true
					}
					name := string(d.opaque())
					value := d.opaque()
					if mode == "attributes-denied" || mode == "attributes-cli-denied" {
						return nil, 13, nil, true
					}
					if !bytes.Equal(value, oldX[name]) {
						return nil, 0, errors.New("wrong xattr bytes"), true
					}
					if _, exists := newX[name]; exists {
						return nil, 0, errors.New("replayed xattr mutation"), true
					}
					newX[name] = bytes.Clone(value)
					if mode == "attributes-source-change" {
						oldX[name] = []byte("changed")
					}
					e = blockCLIQuad(blockCLIQuad(missingV4Words(nil, 1), 1), 2)
				case 29:
					if string(d.opaque()) != stageName || string(d.opaque()) != "target" || !bytes.Equal(stageData, want) {
						return nil, 0, errors.New("invalid replacement publication"), true
					}
					if attributes && (!reflect.DeepEqual(oldX, newX) || !bytes.Equal(oldNamed, newNamed)) {
						return nil, 0, errors.New("unpreserved attributes at RENAME"), true
					}
					for _, bit := range []uint32{12, 33, 36, 37, 58, 59, 80} {
						if !bytes.Equal(stage[bit], original[bit]) {
							return nil, 0, fmt.Errorf("unpreserved metadata %d", bit), true
						}
					}
					published = true
					originalData = bytes.Clone(stageData)
					e = missingV4Words(nil, 1)
					e = blockCLIQuad(blockCLIQuad(e, 1), 2)
					e = missingV4Words(e, 1)
					e = blockCLIQuad(blockCLIQuad(e, 1), 2)
				case 28:
					if string(d.opaque()) != stageName {
						return nil, 0, errors.New("cleanup removed original"), true
					}
					removed = true
					e = missingV4Words(nil, 1)
					e = blockCLIQuad(blockCLIQuad(e, 1), 2)
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
			go func() { done <- p.serve(listener) }()
			closed := false
			stop := func() {
				if closed {
					return
				}
				closed = true
				listener.Close()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(stop)
			if mode == "cli" || mode == "attributes-cli" || mode == "attributes-cli-denied" {
				args := []string{"127.0.0.1", "--nfs-version", "4.2", "--nfs-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never", "-c", "replace " + strconv.Quote(path) + " target"}
				out, err := runKerberosCLI(t, args)
				if mode == "attributes-cli-denied" && err == nil {
					t.Fatal("CLI published after attribute refusal", out)
				}
				if mode != "attributes-cli-denied" && err != nil {
					t.Fatal(err, out)
				}
			} else {
				c, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: "4.2", Transport: "tcp", NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: 2 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(c, "127.0.0.1", false, false, io.Discard)
				if err := s.Use(ctx, "/"); err != nil {
					t.Fatal(err)
				}
				_, err = s.PutWithOptions(ctx, path, "target", session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
					if done > 0 && mode == "identity-change" {
						c.Auth.UID++
					}
				}})
				c.Close()
				if mode == "api" || mode == "attributes-api" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("unsafe replacement succeeded", mode)
				}
			}
			stop()
			if mode == "api" || mode == "cli" || mode == "attributes-api" || mode == "attributes-cli" {
				if !published || !bytes.Equal(originalData, want) || len(setters) != 2 {
					t.Fatal("replacement/policy was not published")
				}
			} else if published || string(originalData) != "old contents" {
				t.Fatal("refused replacement changed original")
			}
		})
	}
}
