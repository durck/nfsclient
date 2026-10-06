package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestPNFSSequenceInvalidation(t *testing.T) {
	for _, flags := range []uint32{1, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096} {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			v := lockPeer4(t, 1, &lockPeerState{sequenceFlags: flags})
			v.recall = &layoutRecall{active: true}
			if err := v.compound(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !v.stateLost.Load() {
				t.Fatal("pNFS state remained usable after server invalidation")
			}
		})
	}
}

func TestPNFSMetadataChannelLoss(t *testing.T) {
	done := make(chan struct{})
	v := &v4Client{c: &Client{nfs: &rpcClient{duplex: &rpcDuplex{done: done}}}, recall: &layoutRecall{active: true}}
	close(done)
	if err := v.layoutUsable([]byte("file")); err == nil {
		t.Fatal("DS I/O allowed after metadata callback channel closed")
	}
}

func TestPNFSCallbackBadSlotDoesNotConsumeSequence(t *testing.T) {
	r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16), minor: 1}
	b := callbackCall(r, 1, false)
	// RPC header 40, compound header 16, CB_SEQUENCE opcode + session +
	// sequence + slot: highest_slotid begins at byte 84.
	binary.BigEndian.PutUint32(b[84:88], 1)
	reply, err := r.callback(b)
	if err != nil || binary.BigEndian.Uint32(reply[24:28]) != 10053 || r.sequence != 0 {
		t.Fatal("CB_SEQUENCE error consumed a slot sequence", err, r.sequence)
	}
	reply, err = r.callback(callbackCall(r, 1, false))
	if err != nil || binary.BigEndian.Uint32(reply[24:28]) != 0 {
		t.Fatal("valid sequence refused after slot error", err)
	}
}

func TestPNFSStripeMapping(t *testing.T) {
	for _, dense := range []bool{false, true} {
		util := uint32(64)
		if dense {
			util |= 1
		}
		l := fileLayout{util: util, first: 1, pattern: 128, indices: []uint32{2, 0, 1}, servers: make([][]string, 3), handles: [][]byte{[]byte("a"), []byte("b"), []byte("c")}}
		for i := uint64(0); i < 1000; i++ {
			server, fh, offset, left, err := l.position(128+i, []byte("mds"))
			if err != nil {
				t.Fatal(err)
			}
			stripe := (i/64 + 1) % 3
			wantOffset := 128 + i
			wantFH := l.handles[l.indices[stripe]]
			if dense {
				wantOffset = (i/192)*64 + i%64
				wantFH = l.handles[stripe]
			}
			if server != l.indices[stripe] || !bytes.Equal(fh, wantFH) || offset != wantOffset || left != 64-i%64 {
				t.Fatalf("dense=%v logical=%d result=%d %s %d %d", dense, i, server, fh, offset, left)
			}
		}
		if _, _, _, _, err := l.position(127, nil); err == nil {
			t.Fatal("offset before pattern accepted")
		}
	}
}
func TestPNFSEndpoints(t *testing.T) {
	for _, s := range []string{"server:2049", "127.0.0.1:0", "0.0.0.0:2049", "224.0.0.1:2049", "[fe80::1%eth0]:2049", "127.0.0.1:65536"} {
		if _, err := pnfsEndpoint(s); err == nil {
			t.Fatal(s)
		}
	}
	for _, tc := range []struct{ network, address, want string }{{"tcp", "192.0.2.20.8.1", "192.0.2.20:2049"}, {"tcp6", "2001:db8::20.8.1", "[2001:db8::20]:2049"}} {
		got, err := universalEndpoint(tc.network, tc.address)
		if err != nil || got != tc.want {
			t.Fatal(got, err)
		}
	}
	for _, s := range []string{"192.0.2.1.256.1", "192.0.2.1.8.-1", "host.8.1", "127.0.0.1.0.0"} {
		if _, err := universalEndpoint("tcp", s); err == nil {
			t.Fatal(s)
		}
	}
	if _, err := validatePNFSOptions(PNFSOptions{}); err == nil {
		t.Fatal("implicit data-server access accepted")
	}
}
func callbackCall(r *layoutRecall, seq uint32, recall bool) encoder {
	var e encoder
	e.u32(17)
	e.u32(0)
	e.u32(2)
	e.u32(pnfsCallbackProgram)
	e.u32(1)
	e.u32(1)
	e.u32(0)
	e.u32(0)
	e.u32(0)
	e.u32(0)
	e.str("")
	e.u32(1)
	e.u32(0)
	if recall {
		e.u32(2)
	} else {
		e.u32(1)
	}
	e.u32(11)
	e = append(e, r.session...)
	e.u32(seq)
	e.u32(0)
	e.u32(0)
	e.u32(1)
	e.u32(0)
	if recall {
		e.u32(5)
		e.u32(1)
		e.u32(1)
		e.u32(0)
		e.u32(1)
		e.opaque(r.fh)
		e.u64(0)
		e.u64(^uint64(0))
		e = append(e, r.state...)
	}
	return e
}
func TestPNFSCallbackRecallReplayAndBounds(t *testing.T) {
	r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{2}, 16)}
	b := callbackCall(r, 1, true)
	reply, err := r.callback(b)
	if err != nil || !r.recalled || binary.BigEndian.Uint32(reply[24:28]) != 0 {
		t.Fatal(err, r.recalled)
	}
	r.recalled = false
	replay, err := r.callback(b)
	if err != nil || !bytes.Equal(reply, replay) || r.recalled {
		t.Fatal("callback executed twice", err)
	}
	changed := append([]byte(nil), b...)
	changed[len(changed)-1] ^= 1
	if _, err := r.callback(changed); err == nil {
		t.Fatal("changed callback retry accepted")
	}
	gap, err := r.callback(callbackCall(r, 3, false))
	if err != nil || binary.BigEndian.Uint32(gap[24:28]) != 10063 {
		t.Fatal("sequence gap accepted", err)
	}
	for i := 0; i < len(b); i++ {
		fresh := &layoutRecall{session: r.session, active: true, fh: r.fh, state: r.state}
		if _, err := fresh.callback(b[:i]); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
}
func TestPNFSDuplexIdleCallback(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16)}
	c := &rpcClient{conn: a, timeout: time.Second}
	m := startDuplex(c, r.callback)
	done := make(chan error, 1)
	callbackDone := make(chan struct{})
	go func() {
		call := callbackCall(r, 1, false)
		_, err := b.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(call))|0x80000000), call...))
		if err != nil {
			done <- err
			return
		}
		response, err := readRecord(b)
		if err != nil {
			done <- err
			return
		}
		if binary.BigEndian.Uint32(response[24:28]) != 0 {
			done <- Status(10063)
			return
		}
		close(callbackDone)
		request, err := readRecord(b)
		if err != nil {
			done <- err
			return
		}
		request[7] = 1
		_, err = b.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(request))|0x80000000), request...))
		done <- err
	}()
	var request encoder
	select {
	case <-callbackDone:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("idle callback not served")
	}
	request.u32(55)
	request.u32(0)
	response, err := m.exchange(context.Background(), request, time.Now().Add(time.Second))
	if err != nil || len(response) != 8 || response[7] != 1 {
		t.Fatal(err, response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b.Close()
	<-m.done
}
func FuzzPNFSLayoutAndDevice(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		d := &decoder{b: b}
		l := decodeFileLayout(d)
		if d.err == nil {
			dev := &decoder{b: b}
			decodeDevice(dev, l)
		}
	})
}
func FuzzPNFSCallback(f *testing.F) {
	r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16), fh: []byte("file"), state: bytes.Repeat([]byte{2}, 16)}
	f.Add([]byte{})
	f.Add([]byte(callbackCall(r, 1, true)))
	f.Fuzz(func(t *testing.T, b []byte) {
		fresh := &layoutRecall{session: r.session, active: true, fh: r.fh, state: r.state}
		_, _ = fresh.callback(b)
	})
}
