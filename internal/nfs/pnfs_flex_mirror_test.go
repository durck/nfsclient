package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestFlexMITMirrorRecovery(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, secure := range []bool{false, true} {
				for _, width := range []int{1, 3} {
					for _, mode := range []string{"data", "short", "holes", "denied", "bad-count", "zero", "recall", "return-failure", "loose", "unapproved", "alternate-loose", "alternate-unapproved", "second-loss", "disabled", "cancel"} {
						t.Run(fmt.Sprintf("4.%d/%s/tls=%v/w%d/%s", minor, security, secure, width, mode), func(t *testing.T) {
							p := newFlexMITProfile(t, security, secure)
							p.mirrorFailover = true
							runFlexReadWire(t, minor, 2, width, width, mode, p)
						})
					}
				}
			}
		}
	}
}

func TestFlexMirrorRecoverySelectionAndGuards(t *testing.T) {
	for _, mode := range []string{"recover", "same-batch", "second-loss", "single", "cancel", "recall", "service", "principal", "unconfirmed", "loose", "get-error", "changed-service", "changed-principal", "changed-confirmation"} {
		t.Run(mode, func(t *testing.T) {
			client := func() *Client {
				return &Client{security: "krb5p", principal: "user@TEST", v4: &v4Client{serverIdentity: &createSessionKey{}}}
			}
			parent, old, other := client(), client(), client()
			component := func(id byte, score uint32) *flexDS {
				return &flexDS{major: 4, minor: 2, efficiency: score, rsize: 31, endpoints: []string{fmt.Sprint(id)}, handle: []byte{id}, state: []byte{id}}
			}
			a, b, c, d, e, f := component(1, 10), component(2, 10), component(3, 20), component(4, 20), component(5, 30), component(6, 30)
			l := &flexLayout{stripe: 64, mirrors: [][]*flexDS{{a, b}, {c, d}, {e, f}}, selected: []*flexDS{e, f}}
			r := &pnfsRead{ds: old, flex: e, flexLayout: l, offset: 128, limit: 64}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			usable := func() error { return nil }
			switch mode {
			case "single":
				l.mirrors = [][]*flexDS{l.selected}
			case "cancel":
				cancel()
			case "recall":
				usable = func() error { return errors.New("recall") }
			case "service":
				old.security = "krb5"
			case "principal":
				old.principal = "different"
			case "unconfirmed":
				old.v4.serverIdentity = nil
			case "loose":
				c.major = 3
			case "changed-service":
				other.security = "krb5"
			case "changed-principal":
				other.principal = "different"
			case "changed-confirmation":
				other.v4.serverIdentity = nil
			}
			gets, retired := 0, 0
			recoverRead := parent.flexMirrorRecovery(ctx, usable, func(ds *flexDS) (*Client, string, error) {
				gets++
				if ds != c && ds != d {
					t.Fatal("not the next-best mirror")
				}
				if mode == "get-error" {
					return nil, "", io.EOF
				}
				return other, "alternate", nil
			}, func(*pnfsRead) { retired++ })
			err := recoverRead(r)
			success := mode == "recover" || mode == "same-batch" || mode == "second-loss"
			if (err == nil) != success {
				t.Fatal(err)
			}
			if !success {
				if mode != "get-error" && mode != "changed-service" && mode != "changed-principal" && mode != "changed-confirmation" && (gets != 0 || retired != 0) {
					t.Fatal("contacted alternate before preflight")
				}
				return
			}
			if r.flex != c || r.ds != other || string(r.handle) != string(c.handle) || r.endpoint != "alternate" || r.offset != 128 || r.limit != 64 {
				t.Fatal("wrong recovered range or component")
			}
			if mode == "same-batch" {
				r = &pnfsRead{ds: old, flex: f, flexLayout: l}
				if err := recoverRead(r); err != nil || r.flex != d {
					t.Fatal("second original worker", err)
				}
			}
			if mode == "second-loss" {
				if err := recoverRead(r); err == nil || gets != 1 {
					t.Fatal("second mirror switch accepted")
				}
			}
		})
	}
}

func TestFlexMirrorRecoveryOptions(t *testing.T) {
	o := PNFSOptions{Layout: "flex", MirrorFailover: true, DataServers: map[string]string{"192.0.2.1:2049": "127.0.0.1:2049"}}
	if got, err := validatePNFSOptions(o); err != nil || !got.MirrorFailover {
		t.Fatal(got, err)
	}
	for _, mode := range []string{"file", "combined", "sys", "krb5", "write"} {
		t.Run(mode, func(t *testing.T) {
			p := o
			if mode == "file" {
				p.Layout = "file"
			}
			if mode == "combined" {
				p.ReadFailover = true
			}
			if mode == "file" || mode == "combined" {
				if _, err := validatePNFSOptions(p); err == nil {
					t.Fatal("invalid policy accepted")
				}
				return
			}
			c := &Client{ReadSize: 128, config: &Config{PNFS: true, Security: mode}, nfs: &rpcClient{}}
			c.v4 = &v4Client{c: c, recall: &layoutRecall{}}
			if mode == "write" {
				if c.ValidatePNFSWriteOptions(p) == nil {
					t.Fatal("write recovery accepted")
				}
				return
			}
			if n, err := c.ReadPNFSToProgress(context.Background(), []byte("file"), 1, io.Discard, p, nil); n != 0 || err == nil {
				t.Fatal(n, err)
			}
		})
	}
}
