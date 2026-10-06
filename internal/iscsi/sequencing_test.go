package iscsi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/testiscsi"
)

func TestOSDIncomingSequences(t *testing.T) {
	for _, tc := range []struct {
		name, fault, wantErr string
		dataFirst, splitR2T  bool
	}{
		{name: "r2t-first"},
		{name: "data-first", dataFirst: true},
		{name: "r2t-first-split-bursts", splitR2T: true},
		{name: "data-first-split-bursts", dataFirst: true, splitR2T: true},
		{name: "independent-data-counter", fault: "osd-data-counter-reset", wantErr: "invalid/out-of-order SCSI Data-In"},
		{name: "independent-r2t-counter", dataFirst: true, fault: "osd-r2t-sequence", wantErr: "invalid/overlapping iSCSI R2T"},
		{name: "wrong-expdatasn-r2t-first", fault: "osd-response-sequence", wantErr: "SCSI response refused"},
		{name: "wrong-expdatasn-data-first", dataFirst: true, fault: "osd-response-sequence", wantErr: "SCSI response refused"},
		{name: "bidirectional-data-in-status", fault: "osd-data-in-status", wantErr: "invalid SCSI Data-In status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "storage")
			if err := os.WriteFile(path, make([]byte, 512), 0600); err != nil {
				t.Fatal(err)
			}
			id := bytes.Repeat([]byte{0x29}, 20)
			data := bytes.Repeat([]byte("sequenced-object-data"), 500)
			peer := testiscsi.Start(t, path, testiscsi.Options{
				OSDSystemID: id, OSDName: []byte("sequence-target"), OSDObjects: map[[2]uint64][]byte{{0x10000, 0x10001}: data},
				OSDDataFirst: tc.dataFirst, OSDSplitR2T: tc.splitR2T, ReadSequencePDUs: 1,
				Fault: tc.fault, AllowProcessKill: tc.wantErr != "",
			})
			target, err := ParseTarget(peer.URL())
			if err != nil {
				t.Fatal(err)
			}
			capability := make([]byte, 80)
			v, err := OpenObject(context.Background(), target, testiscsi.Initiator, time.Second, id, []byte("sequence-target"), capability)
			if tc.wantErr != "" {
				if v != nil {
					v.Close()
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			length, err := v.Length(0x10000, 0x10001, capability)
			if err != nil || length != uint64(len(data)) {
				t.Fatalf("object length %d: %v", length, err)
			}
			got := make([]byte, 4099)
			if err := v.Read(0x10000, 0x10001, 513, capability, got); err != nil || !bytes.Equal(got, data[513:513+len(got)]) {
				t.Fatalf("object read mismatch: %v", err)
			}
		})
	}
}

func TestTCPReadSequences(t *testing.T) {
	for _, tc := range []struct {
		name, fault, wantErr string
		sequencePDUs         int
		pduBytes             int
		separateStatus       bool
	}{
		{name: "single-pdu-sequences", sequencePDUs: 1},
		{name: "multi-pdu-sequences", sequencePDUs: 2},
		{name: "single-pdu-sequences-separate-status", sequencePDUs: 1, separateStatus: true},
		{name: "multi-pdu-sequences-separate-status", sequencePDUs: 2, separateStatus: true},
		{name: "exactly-1024-data-pdus", sequencePDUs: 1, pduBytes: 64, separateStatus: true},
		{name: "datasn-must-not-reset", fault: "data-sequence-reset", wantErr: "invalid/out-of-order SCSI Data-In"},
		{name: "status-requires-final", fault: "status-without-final", wantErr: "invalid/out-of-order SCSI Data-In"},
		{name: "response-requires-ended-sequence", fault: "separate-status-open-sequence", wantErr: "SCSI response refused"},
		{name: "response-requires-expdatasn", fault: "separate-status-sequence", wantErr: "SCSI response refused"},
		{name: "data-pdu-limit", fault: "data-pdu-limit", sequencePDUs: 1, wantErr: "invalid/out-of-order SCSI Data-In"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "storage")
			before := make([]byte, 131072)
			for i := range before {
				before[i] = byte(i*31 + i/511)
			}
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			peer := testiscsi.Start(t, path, testiscsi.Options{
				ReadSequencePDUs: tc.sequencePDUs, ReadPDUBytes: tc.pduBytes, SeparateReadStatus: tc.separateStatus,
				Fault: tc.fault, AllowProcessKill: tc.wantErr != "",
			})
			target, err := ParseTarget(peer.URL())
			if err != nil {
				t.Fatal(err)
			}
			v, err := Open(context.Background(), target, testiscsi.Initiator, time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			got := make([]byte, 70003)
			n, err := v.ReadAt(got, 511)
			if tc.wantErr != "" {
				if n != 0 || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected no progress and %q, got %d, %v", tc.wantErr, n, err)
				}
				events := peer.Events()
				if n, err := v.ReadAt(got, 511); n != 0 || err == nil || !bytes.Equal(events, peer.Events()) {
					t.Fatalf("failed session reused or command replayed: %d, %v", n, err)
				}
				return
			}
			if err != nil || n != len(got) || !bytes.Equal(got, before[511:511+len(got)]) {
				t.Fatalf("read mismatch: %d, %v", n, err)
			}
		})
	}
}
