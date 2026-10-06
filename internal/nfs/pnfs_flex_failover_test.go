package nfs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestFlexMITFailover(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, mode := range []string{"recover", "parallel", "default", "minor-id", "owner", "scope", "client-id", "unconfirmed", "spn", "service", "principal", "unknown-sequence", "uncertain-sequence", "second-loss", "bad-xdr", "denied", "recall", "cancel", "create-lost"} {
					t.Run(fmt.Sprintf("4.%d/%s/tls=%v/%s", minor, security, secure, mode), func(t *testing.T) { runPNFSMITReadFailover(t, minor, security, secure, mode, true) })
				}
			}
		}
	}
}

func TestFlexMITFailoverPublic(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, width := range []int{1, 3} {
					for _, mode := range []string{"data", "short"} {
						t.Run(fmt.Sprintf("4.%d/%s/tls=%v/w%d/%s", minor, security, secure, width, mode), func(t *testing.T) {
							p := newFlexMITProfile(t, security, secure)
							p.failover = true
							runFlexReadWire(t, minor, 2, width, width, mode, p)
						})
					}
				}
			}
		}
	}
}

func TestFlexRecoveryReportsAndBudget(t *testing.T) {
	v := &v4Client{recall: &layoutRecall{}}
	calls := 0
	recoverRead := v.flexReadRecovery(func(r *pnfsRead) error { calls++; return nil })
	for i := 0; i < 16; i++ {
		r := &pnfsRead{flex: &flexDS{major: 4, device: bytes.Repeat([]byte{byte(i)}, 16)}, offset: uint64(i * 64), limit: 64, ioErr: &rpcTransportFailure{io.EOF}}
		err := recoverRead(r)
		if (err == nil) != (i < 8) {
			t.Fatal(i, err)
		}
		if i < 8 && r.ioErr != nil {
			t.Fatal("recovered error would be reported twice")
		}
		if i >= 8 {
			v.recordFlexError(r.flex, r.offset, uint64(r.limit), r.ioErr)
		}
	}
	if calls != 8 || len(v.recall.flexErrors) != 16 {
		t.Fatal(calls, len(v.recall.flexErrors))
	}
	for i, e := range v.recall.flexErrors {
		if e.status != 6 || e.op != 25 || e.offset != uint64(i*64) || e.length != 64 || e.device[0] != byte(i) {
			t.Fatal(i, e)
		}
	}
}

func TestFlexFailoverSecurityPreflight(t *testing.T) {
	for _, security := range []string{"sys", "krb5"} {
		t.Run(security, func(t *testing.T) {
			c := &Client{ReadSize: 128, config: &Config{PNFS: true, Security: security}, nfs: &rpcClient{}}
			c.v4 = &v4Client{c: c, recall: &layoutRecall{}}
			o := PNFSOptions{Layout: "flex", ReadFailover: true, DataServers: map[string]string{"192.0.2.1:2049": "127.0.0.1:2049"}}
			n, err := c.ReadPNFSToProgress(context.Background(), []byte("file"), 1, io.Discard, o, nil)
			if n != 0 || err == nil || !strings.Contains(err.Error(), "requires krb5i or krb5p") {
				t.Fatal(n, err)
			}
			if err := c.ValidatePNFSWriteOptions(o); err == nil {
				t.Fatal("Flex write recovery accepted")
			}
		})
	}
}
