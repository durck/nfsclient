package nfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSGSSBindingRequiresHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := tlsGSSBinding(tls.Client(a, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "unused.test"})); err == nil {
		t.Fatal("exporter before handshake")
	}
}

func TestTLSMITChannelBinding(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/server.nfs.test")
	var bindings [][]byte
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		for _, mode := range []string{"matching", "different", "missing"} {
			t.Run(security+"/"+mode, func(t *testing.T) {
				var calls atomic.Int32
				c := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
					calls.Add(1)
					if program != nfsProgram || proc != 0 || len(d.b) != 0 {
						return nil, errors.New("unexpected NFS operation")
					}
					return nil, nil
				})
				c.version = "4.2"
				policy, server := pnfsTLSFixture(t, "data")
				policy.ServerName = "127.0.0.1"
				options := mitTLSOptions{server: server(0), client: policy}
				options.native = os.Getenv("NFS_VIEWER_GSS_NATIVE_ACCEPTOR") != "" && mode != "missing"
				if mode != "matching" {
					options.badBinding = mode
				}
				endpoint := pnfsMITEndpoint(t, c.nfs.conn, nil, options)
				cfg := pnfsMITConfig(t, security, "nfs/server.nfs.test")
				cfg.Version = "4.2"
				cfg.TLS = policy
				conn, err := net.DialTimeout("tcp", endpoint, cfg.Timeout)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				c.nfs = &rpcClient{conn: conn, timeout: cfg.Timeout}
				tlsPolicy, err := cfg.tlsConfig()
				if err != nil {
					t.Fatal(err)
				}
				if err = c.nfs.startTLS(context.Background(), nfsProgram, 4, tlsPolicy); err != nil {
					t.Fatal(err)
				}
				binding, err := tlsGSSBinding(c.nfs.conn.(*tls.Conn))
				if err != nil {
					t.Fatal(err)
				}
				if len(binding) != 45 || !bytes.HasPrefix(binding, []byte("tls-exporter:")) {
					t.Fatal("invalid exporter envelope")
				}
				for _, old := range bindings {
					if bytes.Equal(binding, old) {
						t.Fatal("binding reused across TLS connections")
					}
				}
				bindings = append(bindings, binding)
				err = c.authenticateKerberos(context.Background(), cfg)
				defer c.Close()
				if mode != "matching" {
					if err == nil || calls.Load() != 0 {
						t.Fatal("binding failure reached NFS", err, calls.Load())
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err = c.nfs.call(context.Background(), nfsProgram, 4, 0, nil, nil); err != nil {
					t.Fatal(err)
				}
				if calls.Load() != 1 {
					t.Fatal("wrong request count", calls.Load())
				}
			})
		}
	}
}

func nativeGSSBindingCheck(token, binding []byte, mismatch bool) error {
	conn, err := net.DialTimeout("tcp", os.Getenv("NFS_VIEWER_GSS_NATIVE_ACCEPTOR"), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var request []byte
	for _, field := range [][]byte{binding, token} {
		request = binary.BigEndian.AppendUint32(request, uint32(len(field)))
		request = append(request, field...)
	}
	if _, err = io.Copy(conn, bytes.NewReader(request)); err != nil {
		return err
	}
	var response [16]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	major, minor, replySize := binary.BigEndian.Uint32(response[:4]), binary.BigEndian.Uint32(response[4:8]), binary.BigEndian.Uint32(response[12:])
	if mismatch {
		if major != 4<<16 {
			return fmt.Errorf("native MIT expected GSS_S_BAD_BINDINGS, major=%d minor=%d", major, minor)
		}
	} else if major != 0 || replySize == 0 {
		return fmt.Errorf("native MIT accept failed: major=%d minor=%d reply_size=%d", major, minor, replySize)
	}
	return nil
}
