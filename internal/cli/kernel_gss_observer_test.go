package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A fixture-only loopback relay records sizes, never ticket or key contents.
// Both directions retain their original bytes and RPC fragment markers.
type kernelGSSObserver struct {
	port       int
	initCount  atomic.Int32
	minInitLen atomic.Int32
}

func startKernelGSSObserver(t *testing.T, upstreamPort int) *kernelGSSObserver {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &kernelGSSObserver{port: l.Addr().(*net.TCPAddr).Port}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	t.Cleanup(func() { cancel(); l.Close(); wg.Wait() })
	go func() {
		defer wg.Done()
		for {
			client, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				stopClient := context.AfterFunc(ctx, func() { client.Close() })
				defer stopClient()
				server, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(upstreamPort)))
				if err != nil {
					if ctx.Err() == nil {
						t.Errorf("GSS observer upstream: %v", err)
					}
					return
				}
				defer server.Close()
				stopServer := context.AfterFunc(ctx, func() { server.Close() })
				defer stopServer()
				client.SetDeadline(time.Now().Add(90 * time.Second))
				server.SetDeadline(time.Now().Add(90 * time.Second))
				replied := make(chan struct{})
				go func() {
					defer close(replied)
					io.Copy(client, server)
					client.Close()
				}()
				defer func() { server.Close(); <-replied }()
				for {
					record, wire, err := readObservedRPC(client)
					if err != nil {
						if ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
							t.Errorf("GSS observer record: %v", err)
						}
						return
					}
					size, err := rpcInitTokenLength(record)
					if err != nil {
						t.Errorf("GSS observer parse: %v", err)
						return
					}
					if size > 0 {
						o.initCount.Add(1)
						for current := o.minInitLen.Load(); current == 0 || int32(size) < current; current = o.minInitLen.Load() {
							if o.minInitLen.CompareAndSwap(current, int32(size)) {
								break
							}
						}
					}
					if _, err := io.Copy(server, bytes.NewReader(wire)); err != nil {
						if ctx.Err() == nil {
							t.Errorf("GSS observer forward: %v", err)
						}
						return
					}
				}
			}()
		}
	}()
	return o
}

func readObservedRPC(r io.Reader) (record, wire []byte, err error) {
	for fragments := 0; fragments < 1024; fragments++ {
		var prefix [4]byte
		if _, err := io.ReadFull(r, prefix[:]); err != nil {
			return nil, nil, err
		}
		marker := binary.BigEndian.Uint32(prefix[:])
		size := int(marker & 0x7fffffff)
		if size > 1<<20-len(record) {
			return nil, nil, errors.New("fixture RPC record exceeds 1 MiB")
		}
		fragment := make([]byte, size)
		if _, err := io.ReadFull(r, fragment); err != nil {
			return nil, nil, err
		}
		wire = append(wire, prefix[:]...)
		wire = append(wire, fragment...)
		record = append(record, fragment...)
		if marker&0x80000000 != 0 {
			return record, wire, nil
		}
	}
	return nil, nil, errors.New("fixture RPC fragment count exceeds 1024")
}

func rpcInitTokenLength(record []byte) (int, error) {
	if len(record) < 24 || binary.BigEndian.Uint32(record[4:]) != 0 || binary.BigEndian.Uint32(record[8:]) != 2 {
		return 0, errors.New("invalid fixture RPC call header")
	}
	if binary.BigEndian.Uint32(record[12:]) != 100003 || binary.BigEndian.Uint32(record[16:]) != 4 {
		return 0, nil
	}
	r := bytes.NewReader(record[24:])
	word := func() (uint32, error) { var n uint32; err := binary.Read(r, binary.BigEndian, &n); return n, err }
	opaque := func(limit uint32) ([]byte, error) {
		n, err := word()
		if err != nil || n > limit || uint64(n)+uint64((4-n%4)%4) > uint64(r.Len()) {
			return nil, errors.New("invalid fixture RPC opaque length")
		}
		b := make([]byte, n)
		io.ReadFull(r, b)
		r.Seek(int64((4-n%4)%4), io.SeekCurrent)
		return b, nil
	}
	flavor, err := word()
	if err != nil {
		return 0, err
	}
	cred, err := opaque(400)
	if err != nil {
		return 0, err
	}
	if flavor != 6 || len(cred) < 8 || binary.BigEndian.Uint32(cred[4:]) != 1 {
		return 0, nil
	}
	if binary.BigEndian.Uint32(record[20:]) != 0 || len(cred) != 20 || binary.BigEndian.Uint32(cred) != 1 || binary.BigEndian.Uint32(cred[16:]) != 0 {
		return 0, errors.New("invalid fixture RPCSEC_GSS INIT credential")
	}
	verifier, err := word()
	if err != nil || verifier != 0 {
		return 0, errors.New("invalid fixture GSS INIT verifier")
	}
	v, err := opaque(400)
	if err != nil || len(v) != 0 {
		return 0, errors.New("non-empty fixture GSS INIT verifier")
	}
	token, err := opaque(1 << 20)
	if err != nil || len(token) == 0 || r.Len() != 0 {
		return 0, errors.New("invalid fixture GSS INIT token")
	}
	return len(token), nil
}

func TestKernelGSSObserverFraming(t *testing.T) {
	call := []byte{}
	for _, v := range []uint32{7, 0, 2, 100003, 4, 0, 6, 20, 1, 1, 0, 1, 0, 0, 0, 4097} {
		call = binary.BigEndian.AppendUint32(call, v)
	}
	call = append(call, bytes.Repeat([]byte{0x41}, 4097)...)
	call = append(call, 0, 0, 0)
	wire := binary.BigEndian.AppendUint32(nil, 13)
	wire = append(wire, call[:13]...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(call)-13)|0x80000000)
	wire = append(wire, call[13:]...)
	record, forwarded, err := readObservedRPC(bytes.NewReader(wire))
	if err != nil || !bytes.Equal(record, call) || !bytes.Equal(forwarded, wire) {
		t.Fatalf("fragmented observer altered bytes: %v", err)
	}
	if n, err := rpcInitTokenLength(record); n != 4097 || err != nil {
		t.Fatalf("observed INIT size: %d %v", n, err)
	}
	for _, bad := range [][]byte{call[:20], call[:60], call[:len(call)-1], append(append([]byte(nil), call...), 0)} {
		if _, err := rpcInitTokenLength(bad); err == nil {
			t.Fatal("accepted truncated/trailing INIT")
		}
	}
	for _, bad := range [][]byte{wire[:len(wire)-1], binary.BigEndian.AppendUint32(nil, 0x80100001), make([]byte, 4*1024)} {
		if _, _, err := readObservedRPC(bytes.NewReader(bad)); err == nil {
			t.Fatal("accepted truncated/oversized/excess-fragment record")
		}
	}
	dataCall := append([]byte(nil), call...)
	binary.BigEndian.PutUint32(dataCall[36:], 0) // RPCSEC_GSS DATA is not INIT.
	if n, err := rpcInitTokenLength(dataCall); n != 0 || err != nil {
		t.Fatalf("counted DATA as INIT: %d %v", n, err)
	}
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	reply := []byte{0x80, 0, 0, 4, 1, 2, 3, 4}
	done := make(chan error, 1)
	go func() {
		c, err := upstream.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, got, err := readObservedRPC(c)
		if err == nil && !bytes.Equal(got, wire) {
			err = errors.New("relay changed request fragments")
		}
		if err == nil {
			_, err = io.Copy(c, bytes.NewReader(reply))
		}
		done <- err
	}()
	observer := startKernelGSSObserver(t, upstream.Addr().(*net.TCPAddr).Port)
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(observer.port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(c, bytes.NewReader(wire)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(reply))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("relay changed response: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if observer.initCount.Load() != 1 || observer.minInitLen.Load() != 4097 {
		t.Fatal("relay failed to observe INIT size")
	}
}
