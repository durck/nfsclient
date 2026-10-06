package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These synthetic peers allow one exact GUARDED CREATE surrounded by read-only
// observations. Any WRITE, SETACL, REMOVE, retry or unrelated name is a failure.
type stageCreateRPCStep struct {
	program, procedure uint32
	args, body         encoder
}

func stageCreateArgs(name string) encoder {
	var e encoder
	e.opaque(replacementRPCParent())
	e.str(name)
	for _, value := range []uint32{1, 1, 0600, 0, 0, 1, 0, 0, 0, 0} {
		e.u32(value) // GUARDED; mode; omitted UID/GID; size=0; omitted times.
	}
	return e
}

func stageCreateAck(stage replacementRPCObject, fullWCC bool) encoder {
	var e encoder
	e.u32(0)
	e.u32(1)
	e.opaque(stage.handle)
	e.u32(1)
	e = append(e, stage.acl[8:92]...)
	if fullWCC {
		e.u32(1)
		e.u64(0)
		for i := 0; i < 2; i++ {
			e.u32(100)
			e.u32(0)
		}
		e.u32(1)
		parent := append([]byte(nil), stage.acl[8:92]...)
		binary.BigEndian.PutUint32(parent, 2)
		binary.BigEndian.PutUint32(parent[4:], 02770)
		binary.BigEndian.PutUint32(parent[8:], 2)
		e = append(e, parent...)
	} else {
		e.u32(0)
		e.u32(0)
	}
	return e
}

func stageCreateObservation(o replacementRPCObject, step int) stageCreateRPCStep {
	program, procedure, args, body := replacementRPCStep(o, step)
	return stageCreateRPCStep{program, procedure, args, body}
}

func stageCreatePlan(source, stage replacementRPCObject, fullWCC bool) []stageCreateRPCStep {
	var steps []stageCreateRPCStep
	for i := 0; i < 6; i++ { // Initial capture, then mandatory source recheck.
		steps = append(steps, stageCreateObservation(source, i%3))
	}
	steps = append(steps, stageCreateRPCStep{100003, 8, stageCreateArgs(stage.name), stageCreateAck(stage, fullWCC)})
	for i := 0; i < 6; i++ { // Privacy check, then comparison against CREATE.
		steps = append(steps, stageCreateObservation(stage, i%3))
	}
	return steps
}

func stageCreatePeer(t *testing.T, service uint32, steps []stageCreateRPCStep) *Client {
	t.Helper()
	return aclRPCClient(t, service, len(steps), func(index int, raw []byte) ([]byte, error) {
		step, seq := steps[index], uint32(51+index)
		if err := aclRPCRequest(raw, step.program, 3, step.procedure, service, seq, step.args); err != nil {
			return nil, fmt.Errorf("staging step %d: %w", index, err)
		}
		return aclRPCReply(binary.BigEndian.Uint32(raw), service, seq, step.body), nil
	})
}

func requireUnverifiedStage(t *testing.T, n Node, err error) {
	t.Helper()
	if !reflect.DeepEqual(n, Node{}) || !errors.Is(err, ErrNFS3StageUnverified) || !errors.Is(err, ErrNFS3ReplacementRefused) {
		t.Fatalf("unverified CREATE returned a usable node or lost its classification: %+v / %v", n, err)
	}
}

func TestNFS3StageCreateExactWireAndIdentity(t *testing.T) {
	for _, service := range []uint32{0, 1, 2, 3} {
		for _, fullWCC := range []bool{false, true} {
			t.Run(fmt.Sprintf("service-%d/wcc-%v", service, fullWCC), func(t *testing.T) {
				source, stage := replacementRPCSource(), replacementRPCStage()
				// Exercise the largest legal handle and full CREATE reply too.
				stage.handle = bytes.Repeat([]byte{0x61}, 64)
				c := stageCreatePeer(t, service, stageCreatePlan(source, stage, fullWCC))
				original := replacementRPCCapture(t, c)
				gss := c.nfs.gss
				got, err := c.CreateNFS3ReplacementStage(context.Background(), stage.name, original)
				if err != nil || !bytes.Equal(got.Handle, stage.handle) || got.Attr.Mode != 0600 || got.Attr.Size != 0 || got.Attr.FileID != 42 {
					t.Fatalf("private acknowledged stage failed: %+v / %v", got, err)
				}
				if c.nfs.xid != 13 || !reflect.DeepEqual(c.Auth, aclRPCAuth) || c.nfs.gss != gss || (gss != nil && gss.seq != 63) {
					t.Fatal("CREATE changed identity/context or sent an unexpected RPC")
				}
			})
		}
	}
}

func TestNFS3StageCreateRejectsBeforeMutation(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", "a\x00b", strings.Repeat("x", 256), "original.bin"} {
		t.Run(fmt.Sprintf("name-%q", name), func(t *testing.T) {
			source := replacementRPCSource()
			c := replacementRPCPeer(t, 0, []replacementRPCObject{source, source, source})
			original := replacementRPCCapture(t, c)
			got, err := c.CreateNFS3ReplacementStage(context.Background(), name, original)
			if !reflect.DeepEqual(got, Node{}) || !errors.Is(err, ErrNFS3ReplacementRefused) || errors.Is(err, ErrNFS3StageUnverified) || c.nfs.xid != 3 {
				t.Fatalf("invalid local name sent RPC or claimed CREATE uncertainty: %v", err)
			}
		})
	}
	for _, scenario := range []string{"missing-snapshot", "changed-identity", "changed-source", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			source, changed := replacementRPCSource(), replacementRPCSource()
			observations := []replacementRPCObject{source, source, source}
			if scenario == "changed-source" {
				binary.BigEndian.PutUint32(changed.acl[124:], 3) // Mask-hidden ACL-only change.
				observations = append(observations, changed, changed, changed)
			}
			c := replacementRPCPeer(t, 0, observations)
			original := replacementRPCCapture(t, c)
			ctx := context.Background()
			switch scenario {
			case "missing-snapshot":
				original = nil
			case "changed-identity":
				c.Auth.UID++
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := c.CreateNFS3ReplacementStage(ctx, "stage", original)
			if !reflect.DeepEqual(got, Node{}) || !errors.Is(err, ErrNFS3ReplacementRefused) || errors.Is(err, ErrNFS3StageUnverified) || c.nfs.xid != uint32(len(observations)) {
				t.Fatalf("failed preflight sent mutation or claimed an attempt: xid=%d err=%v", c.nfs.xid, err)
			}
		})
	}
	var c *Client
	if _, err := c.CreateNFS3ReplacementStage(context.Background(), "stage", nil); !errors.Is(err, ErrNFS3ReplacementRefused) {
		t.Fatalf("nil client was not refused: %v", err)
	}
}

func TestNFS3StageCreateReplyMustProveCreatedObject(t *testing.T) {
	for _, scenario := range []string{"missing-handle", "empty-handle", "large-handle", "missing-attrs", "invalid-handle-bool", "trailing", "truncated", "oversized", "invalid-wcc-bool", "invalid-wcc-mtime", "invalid-wcc-ctime", "invalid-wcc-after-time"} {
		t.Run(scenario, func(t *testing.T) {
			source, stage := replacementRPCSource(), replacementRPCStage()
			body := stageCreateAck(stage, true)
			attrFlag := 12 + ((len(stage.handle) + 3) &^ 3)
			wccStart := attrFlag + 4 + 84
			switch scenario {
			case "missing-handle":
				body = encoder{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
				body = append(body, stage.acl[8:92]...)
				body = append(body, make([]byte, 8)...)
			case "empty-handle", "large-handle":
				stage.handle = nil
				if scenario == "large-handle" {
					stage.handle = make([]byte, 65)
				}
				body = stageCreateAck(stage, false)
			case "missing-attrs":
				body = append(append(encoder(nil), body[:attrFlag]...), make([]byte, 12)...)
			case "invalid-handle-bool":
				binary.BigEndian.PutUint32(body[4:], 2)
			case "trailing":
				body = append(body, 0, 0, 0, 0)
			case "truncated":
				body = body[:len(body)-1]
			case "oversized":
				body = append(body, make([]byte, 281-len(body))...)
			case "invalid-wcc-bool":
				binary.BigEndian.PutUint32(body[wccStart:], 2)
			case "invalid-wcc-mtime":
				binary.BigEndian.PutUint32(body[wccStart+16:], 1e9)
			case "invalid-wcc-ctime":
				binary.BigEndian.PutUint32(body[wccStart+24:], 1e9)
			case "invalid-wcc-after-time":
				binary.BigEndian.PutUint32(body[wccStart+32+72:], 1e9)
			}
			steps := stageCreatePlan(source, stage, true)[:7]
			steps[6].body = body
			c := stageCreatePeer(t, 2, steps)
			original := replacementRPCCapture(t, c)
			got, err := c.CreateNFS3ReplacementStage(context.Background(), stage.name, original)
			requireUnverifiedStage(t, got, err)
			if c.nfs.xid != 7 || !strings.Contains(err.Error(), stage.name) {
				t.Fatalf("malformed acknowledgement caused follow-up/adoption or omitted uncertain name: %v", err)
			}
		})
	}
}

func TestNFS3StageCreateRefusesUnsafeAcknowledgedAttributes(t *testing.T) {
	for _, scenario := range []string{"directory", "symlink", "multiple-links", "unlinked", "mode-suppressed", "mode-zero", "mode-expanded", "special-mode", "nonempty", "owner", "group", "filesystem", "same-fileid", "same-handle"} {
		t.Run(scenario, func(t *testing.T) {
			source, stage := replacementRPCSource(), replacementRPCStage()
			switch scenario {
			case "directory":
				binary.BigEndian.PutUint32(stage.acl[8:], 2)
			case "symlink":
				binary.BigEndian.PutUint32(stage.acl[8:], 5)
			case "multiple-links":
				binary.BigEndian.PutUint32(stage.acl[16:], 2)
			case "unlinked":
				binary.BigEndian.PutUint32(stage.acl[16:], 0)
			case "mode-suppressed":
				binary.BigEndian.PutUint32(stage.acl[12:], 0400)
			case "mode-zero":
				binary.BigEndian.PutUint32(stage.acl[12:], 0)
			case "mode-expanded":
				binary.BigEndian.PutUint32(stage.acl[12:], 0644)
			case "special-mode":
				binary.BigEndian.PutUint32(stage.acl[12:], 04600)
			case "nonempty":
				binary.BigEndian.PutUint64(stage.acl[28:], 1)
			case "owner":
				binary.BigEndian.PutUint32(stage.acl[20:], 20007)
			case "group":
				binary.BigEndian.PutUint32(stage.acl[24:], 20007)
			case "filesystem":
				binary.BigEndian.PutUint64(stage.acl[52:], 10)
			case "same-fileid":
				binary.BigEndian.PutUint64(stage.acl[60:], 41)
			case "same-handle":
				stage.handle = source.handle
			}
			c := stageCreatePeer(t, 0, stageCreatePlan(source, stage, false)[:7])
			original := replacementRPCCapture(t, c)
			got, err := c.CreateNFS3ReplacementStage(context.Background(), stage.name, original)
			requireUnverifiedStage(t, got, err)
			if c.nfs.xid != 7 {
				t.Fatal("unsafe CREATE attributes caused follow-up RPC")
			}
		})
	}
}

func TestNFS3StageCreateRejectsPolicyAndIdentityRaces(t *testing.T) {
	for _, scenario := range []string{"inherited-user", "inherited-group", "inherited-owning-group", "first-handle-swap", "ctime-after-create", "final-handle-swap", "final-masked-grant"} {
		t.Run(scenario, func(t *testing.T) {
			source, stage, changed := replacementRPCSource(), replacementRPCStage(), replacementRPCStage()
			steps := stageCreatePlan(source, stage, false)
			first := 7
			switch scenario {
			case "inherited-user", "final-masked-grant":
				binary.BigEndian.PutUint32(changed.acl[124:], 7)
				if scenario == "final-masked-grant" {
					first = 10
				}
			case "inherited-group":
				binary.BigEndian.PutUint32(changed.acl[148:], 7)
			case "inherited-owning-group":
				binary.BigEndian.PutUint32(changed.acl[136:], 7)
			case "first-handle-swap", "final-handle-swap":
				changed.handle = []byte{0x91, 0x92}
				if scenario == "final-handle-swap" {
					first = 10
				}
			case "ctime-after-create":
				binary.BigEndian.PutUint32(changed.acl[88:], 1)
			}
			for i := first; i < len(steps); i++ {
				steps[i] = stageCreateObservation(changed, (i-7)%3)
			}
			if first == 7 && scenario != "ctime-after-create" {
				steps = steps[:10]
			}
			c := stageCreatePeer(t, 3, steps)
			original := replacementRPCCapture(t, c)
			got, err := c.CreateNFS3ReplacementStage(context.Background(), stage.name, original)
			requireUnverifiedStage(t, got, err)
			if c.nfs.xid != uint32(len(steps)) {
				t.Fatal("unsafe stage caused additional RPCs")
			}
		})
	}
}

func TestNFS3StageCreateErrorsRetainCauseAndUncertainty(t *testing.T) {
	for _, scenario := range []string{"collision", "permission", "post-create-io", "malformed-error-wcc", "readback-unavailable", "readback-denied", "tampered-ack"} {
		t.Run(scenario, func(t *testing.T) {
			source, stage := replacementRPCSource(), replacementRPCStage()
			steps := stageCreatePlan(source, stage, false)
			status := Status(0)
			switch scenario {
			case "collision":
				status = 17
			case "permission":
				status = 13
			case "post-create-io", "malformed-error-wcc":
				status = 5
			case "readback-unavailable":
				status = 10004
			case "readback-denied":
				status = 13
			}
			index := 6
			if strings.HasPrefix(scenario, "readback-") {
				index = 8
			}
			steps = steps[:index+1]
			if status != 0 {
				var body encoder
				body.u32(uint32(status))
				body.u32(0)
				if index == 6 {
					body.u32(0)
				}
				if scenario == "malformed-error-wcc" {
					body = body[:len(body)-4] // Keep the GSS body aligned; truncate NFS WCC.
				}
				steps[index].body = body
			}
			c := aclRPCClient(t, 2, len(steps), func(i int, raw []byte) ([]byte, error) {
				step, seq := steps[i], uint32(51+i)
				if err := aclRPCRequest(raw, step.program, 3, step.procedure, 2, seq, step.args); err != nil {
					return nil, err
				}
				reply := aclRPCReply(binary.BigEndian.Uint32(raw), 2, seq, step.body)
				if scenario == "tampered-ack" && i == index {
					reply[len(reply)-1] ^= 1
				}
				return reply, nil
			})
			original := replacementRPCCapture(t, c)
			got, err := c.CreateNFS3ReplacementStage(context.Background(), stage.name, original)
			requireUnverifiedStage(t, got, err)
			if (status != 0 && !errors.Is(err, status)) || c.nfs.xid != uint32(len(steps)) || !strings.Contains(err.Error(), stage.name) {
				t.Fatalf("CREATE failure lost cause/name or was replayed: %v", err)
			}
		})
	}
}

func TestNFS3StageCreateRejectsEveryTruncatedAck(t *testing.T) {
	valid := stageCreateAck(replacementRPCStage(), true)
	for length := 0; length < len(valid); length++ {
		if _, err := decodeNFS3StageCreate(&decoder{b: valid[:length]}); err == nil {
			t.Fatalf("truncated CREATE acknowledgement accepted at %d/%d bytes", length, len(valid))
		}
	}
}

func TestNFS3StageCreateUDPReplyLossNeverReplays(t *testing.T) {
	for _, service := range []uint32{0, 1} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			source, stage := replacementRPCSource(), replacementRPCStage()
			steps := stageCreatePlan(source, stage, false)[:7]
			var count, creates atomic.Int32
			peerErrors := make(chan error, 8)
			_, port := udpPeer(t, func(s *net.UDPConn, addr *net.UDPAddr, raw []byte) {
				i := int(count.Add(1)) - 1
				var err error
				if i >= len(steps) {
					err = errors.New("unexpected retry or follow-up after lost CREATE reply")
				} else {
					step, seq := steps[i], uint32(51+i)
					err = aclRPCRequest(raw, step.program, 3, step.procedure, service, seq, step.args)
					if err == nil && i == 6 {
						creates.Add(1)
						return // Applied on the synthetic peer; acknowledgement is lost.
					}
					if err == nil {
						_, err = s.WriteToUDP(aclRPCReply(binary.BigEndian.Uint32(raw), service, seq, step.body), addr)
					}
				}
				if err != nil {
					select {
					case peerErrors <- err:
					default:
					}
				}
			})
			rpc := udpClient(t, port)
			if service != 0 {
				rpc.gss = &rpcGSS{context: testMIC{}, handle: []byte("acl-existing-context"), seq: 50, service: service, established: true}
			}
			c := &Client{nfs: rpc, version: "3", Auth: aclRPCAuth}
			original := replacementRPCCapture(t, c)
			start := time.Now()
			got, err := c.CreateNFS3ReplacementStage(context.Background(), stage.name, original)
			requireUnverifiedStage(t, got, err)
			if creates.Load() != 1 || count.Load() != 7 || time.Since(start) > 2*time.Second || !strings.Contains(err.Error(), "outcome unknown") {
				t.Fatalf("uncertain CREATE replayed or hidden: creates=%d calls=%d err=%v", creates.Load(), count.Load(), err)
			}
			select {
			case err := <-peerErrors:
				t.Fatal(err)
			default:
			}
		})
	}
}
