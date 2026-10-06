package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func record(data []byte, last bool) []byte {
	n := uint32(len(data))
	if last {
		n |= 0x80000000
	}
	return append(binary.BigEndian.AppendUint32(nil, n), data...)
}

func TestReadRecord(t *testing.T) {
	fragmented := append(record([]byte("ab"), false), record([]byte("cd"), true)...)
	got, err := readRecord(bytes.NewReader(fragmented))
	if err != nil || string(got) != "abcd" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range [][]byte{{0, 0}, binary.BigEndian.AppendUint32(nil, uint32(maxRecord+1)|0x80000000), append(record([]byte("x"), false), 0), bytes.Repeat([]byte{0, 0, 0, 0}, 1024)} {
		if _, err := readRecord(bytes.NewReader(bad)); err == nil {
			t.Fatal("accepted malformed RPC record")
		}
	}
}

func TestXDRBoundsAndPadding(t *testing.T) {
	var e encoder
	e.str("abc")
	e.u64(0x1020304050607080)
	d := &decoder{b: e}
	if d.str() != "abc" || d.u64() != 0x1020304050607080 || d.err != nil || len(d.b) != 0 {
		t.Fatal("XDR round trip failed")
	}
	for _, data := range [][]byte{{0, 0, 0, 2}, {0, 0, 0, 3, 'a', 'b', 'c'}, {255, 255, 255, 255}} {
		d := &decoder{b: data}
		if len(data) == 4 && data[3] == 2 {
			d.boolean()
		} else {
			d.opaque(64)
		}
		if d.err == nil {
			t.Fatal("accepted invalid XDR")
		}
	}
}

func TestRPCCancelClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := &rpcClient{conn: client, timeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	read := make(chan struct{})
	go func() { readRecord(server); close(read) }()
	done := make(chan error, 1)
	go func() { _, err := c.call(ctx, 1, 1, 1, nil, nil); done <- err }()
	<-read
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled call succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock RPC")
	}
	if _, err := c.call(context.Background(), 1, 1, 1, nil, nil); err == nil {
		t.Fatal("reused an interrupted connection")
	}
}

func TestRPCFragmentedReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := &rpcClient{conn: client, timeout: time.Second}
	go func() {
		request, err := readRecord(server)
		if err != nil {
			return
		}
		var reply encoder
		reply.u32(binary.BigEndian.Uint32(request))
		reply.u32(1)
		reply.u32(0)
		reply.u32(0)
		reply.u32(0)
		reply.u32(0)
		reply.u32(42)
		server.Write(append(record(reply[:9], false), record(reply[9:], true)...))
	}()
	d, err := c.call(context.Background(), 1, 1, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.u32() != 42 || d.err != nil {
		t.Fatal("incorrect RPC payload")
	}
}

func FuzzReadRecord(f *testing.F) {
	f.Add(record([]byte("hello"), true))
	f.Add([]byte{0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) { readRecord(bytes.NewReader(data)) })
}

func TestTruncatedDecoder(t *testing.T) {
	d := &decoder{b: []byte{1}}
	d.u64()
	if !errors.Is(d.err, io.ErrUnexpectedEOF) {
		t.Fatal(d.err)
	}
	d.str()
	if d.err == nil {
		t.Fatal("lost decoder error")
	}
}

func TestRPCConnectionLossVersusMalformedXDR(t *testing.T) {
	for _, truncatedRecord := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete_bad_xdr", true: "truncated_record"}[truncatedRecord], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			c := &rpcClient{conn: client, timeout: time.Second}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				request, err := readRecord(server)
				if err != nil {
					return
				}
				var reply encoder
				reply.u32(binary.BigEndian.Uint32(request))
				reply.u32(1)
				// A full record missing the RPC reply status is malformed XDR.
				packet := record(reply, true)
				if truncatedRecord {
					packet = packet[:len(packet)-1]
				}
				server.Write(packet)
			}()
			_, err := c.call(context.Background(), 1, 1, 1, nil, nil)
			<-done
			if !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrConnectionLost) != truncatedRecord {
				t.Fatalf("wrong transport classification: %v", err)
			}
		})
	}
}
