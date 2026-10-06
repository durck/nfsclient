package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bgss "nfs-viewer/internal/krbgss"
)

type callbackRenewPeer struct {
	t                                *testing.T
	keytab, mode                     string
	recall                           *layoutRecall
	oldHandle                        []byte
	service                          uint32
	rpcVersion                       uint32
	cancel                           context.CancelFunc
	inits, controls, work, callbacks atomic.Int32
}

func (p *callbackRenewPeer) callback(conn net.Conn, a *bgss.Acceptor, handle []byte, seq uint32) error {
	g := &gssBackchannel{context: a, handle: handle, service: max(uint32(2), p.service), rpcVersion: p.rpcVersion}
	rpcSeq := seq
	if p.mode == "callback-exhaustion" && bytes.Equal(handle, p.oldHandle) {
		rpcSeq = 0x7ffffffc + seq
	}
	plain := callbackCall(p.recall, seq, p.mode == "active-recall" && seq == 1)
	binary.BigEndian.PutUint32(plain[44:48], p.recall.minor)
	if p.mode == "offload" && seq == 2 {
		plain = offloadCallback(p.recall, seq, []byte("destination"), bytes.Repeat([]byte{5}, 16), offloadReply{count: 4096, stable: 2, verifier: bytes.Repeat([]byte{6}, 8)})
	}
	call := gssProtectCallback(p.t, g, plain, rpcSeq)
	if _, err := conn.Write(record(call, true)); err != nil {
		return err
	}
	raw, err := readRecord(conn)
	if err != nil {
		return err
	}
	d := &decoder{b: raw}
	if d.u32() != binary.BigEndian.Uint32(call) || d.u32() != 1 || d.u32() != 0 || d.u32() != 6 {
		return errors.New("bad protected callback reply header")
	}
	signedReply := binary.BigEndian.AppendUint32(nil, rpcSeq)
	if p.rpcVersion == 3 {
		credSize := int(binary.BigEndian.Uint32(call[28:32]))
		signedReply = bytes.Clone(call[:32+(credSize+3)/4*4])
		binary.BigEndian.PutUint32(signedReply[4:8], 1)
	}
	if err := a.VerifySignature(signedReply, d.opaque(400)); err != nil {
		return err
	}
	if d.u32() != 0 {
		return errors.New("callback RPC refused")
	}
	if err := (&rpcGSS{context: a, service: g.service, seq: rpcSeq}).unprotect(d); err != nil {
		return err
	}
	if d.u32() != 0 {
		return errors.New("callback COMPOUND refused")
	}
	p.callbacks.Add(1)
	return d.err
}

func (p *callbackRenewPeer) serve(conn net.Conn) error {
	defer conn.Close()
	acceptors := map[string]*bgss.Acceptor{}
	defer func() {
		for _, a := range acceptors {
			a.Close()
		}
	}()
	var newHandle []byte
	for {
		raw, err := readRecord(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		}
		d := &decoder{b: raw}
		xid := d.u32()
		if d.u32() != 0 || d.u32() != 2 || d.u32() != nfsProgram || d.u32() != 4 {
			return errors.New("renewal changed RPC/NFS version")
		}
		proc := d.u32()
		if d.u32() != 6 {
			return errors.New("renewal downgraded security")
		}
		cred := &decoder{b: d.opaque(400)}
		signed := len(raw) - len(d.b)
		if cred.u32() != p.rpcVersion {
			return errors.New("unexpected GSS version")
		}
		control, seq, service := cred.u32(), cred.u32(), cred.u32()
		handle := cred.opaque(380)
		flavor, mic := d.u32(), d.opaque(400)
		var body encoder
		var a *bgss.Acceptor
		replySeq := seq
		if control == 1 {
			if proc != 0 || flavor != 0 || service != 1 || seq != 0 || len(handle) != 0 {
				return errors.New("invalid renewal INIT")
			}
			n := p.inits.Add(1)
			if n > 2 {
				return errors.New("unexpected repeated INIT")
			}
			a, err = bgss.NewAcceptor(bgss.WithKeytab[bgss.Acceptor](p.keytab))
			if err != nil {
				return err
			}
			handle = []byte(fmt.Sprintf("fore-%d", n))
			acceptors[string(handle)] = a
			token, more, err := a.Accept(d.opaque(1 << 20))
			if err != nil || more {
				return fmt.Errorf("mutual renewal: %v", err)
			}
			if n == 2 {
				// The old context remains usable while the replacement INIT is
				// in flight, before the new context has reached BACKCHANNEL_CTL.
				if err = p.callback(conn, acceptors["fore-1"], p.oldHandle, 1); err != nil {
					return err
				}
				if p.mode == "init-cancel" {
					p.cancel()
					return nil
				}
			}
			body.opaque(handle)
			body.u32(0)
			body.u32(0)
			body.u32(64)
			body.opaque(token)
			replySeq = 64
		} else {
			a = acceptors[string(handle)]
			if a == nil || flavor != 6 || service != p.service || a.VerifySignature(raw[:signed], mic) != nil {
				return errors.New("invalid renewed request protection")
			}
			if control == 3 {
				return nil
			}
			if control != 0 || proc != 1 {
				return errors.New("unexpected renewal control")
			}
			g := &rpcGSS{context: a, service: service, seq: seq}
			if err := g.unprotect(d); err != nil {
				return err
			}
			d.str()
			if d.u32() != p.recall.minor || d.u32() != 2 || d.u32() != 53 || !bytes.Equal(d.take(16), p.recall.session) {
				return errors.New("renewal replaced session")
			}
			number := d.u32()
			if number != uint32(p.controls.Load()+p.work.Load()+1) || d.u32() != 0 || d.u32() != 0 {
				return errors.New("renewal changed slot sequencing")
			}
			d.u32()
			code := d.u32()
			status := uint32(0)
			if code == 40 {
				if p.controls.Add(1) != 1 || string(handle) != "fore-2" || d.u32() != pnfsCallbackProgram || d.u32() != 1 || d.u32() != 6 || d.u32() != max(uint32(2), p.service) || !bytes.Equal(d.opaque(380), handle) {
					return errors.New("invalid BACKCHANNEL_CTL binding")
				}
				newHandle = bytes.Clone(d.opaque(380))
				if len(newHandle) == 0 || bytes.Equal(newHandle, p.oldHandle) {
					return errors.New("callback handle was reused")
				}
				switch p.mode {
				case "lost":
					return nil
				case "cancel":
					p.cancel()
					return nil
				case "reject":
					status = 10004
				default:
					if err = p.callback(conn, a, newHandle, 2); err != nil {
						return err
					}
				}
			} else if code == 24 {
				p.work.Add(1)
				if string(handle) != "fore-2" {
					return errors.New("new work used old context")
				}
				if err = p.callback(conn, acceptors["fore-1"], p.oldHandle, 3); err != nil {
					return err
				}
				if err = p.callback(conn, a, newHandle, 4); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unexpected state creation/mutation %d", code)
			}
			if d.err != nil || len(d.b) != 0 {
				return errors.New("trailing renewal request")
			}
			body.u32(status)
			body.str("")
			body.u32(2)
			body.u32(53)
			body.u32(0)
			body = append(body, p.recall.session...)
			body.u32(number)
			for range 4 {
				body.u32(0)
			}
			body.u32(code)
			body.u32(status)
			body, err = g.protect(body)
			if err != nil {
				return err
			}
		}
		signedReply := binary.BigEndian.AppendUint32(nil, replySeq)
		if p.rpcVersion == 3 {
			signedReply = bytes.Clone(raw[:signed])
			binary.BigEndian.PutUint32(signedReply[4:8], 1)
		}
		sig, err := a.MakeSignature(signedReply)
		if err != nil {
			return err
		}
		var response encoder
		response.u32(xid)
		response.u32(1)
		response.u32(0)
		response.u32(6)
		response.opaque(sig)
		response.u32(0)
		response = append(response, body...)
		if _, err = conn.Write(record(response, true)); err != nil {
			if p.mode == "cancel" {
				return nil
			}
			return err
		}
	}
}

func TestProtectedBackchannelRenewal(t *testing.T) {
	for _, profile := range []string{"krb5", "krb5i", "krb5p", "krb5p-v3"} {
		security := strings.TrimSuffix(profile, "-v3")
		for _, mode := range []string{"lifetime", "exhaustion", "callback-exhaustion", "server-warning", "active-recall", "offload", "reject", "lost", "cancel", "init-cancel"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				k, kt := autoCredentials(t)
				left, right := net.Pipe()
				rpc := &rpcClient{conn: left, timeout: time.Second}
				service := map[string]uint32{"krb5": 1, "krb5i": 2, "krb5p": 3}[security]
				r := &layoutRecall{minor: 1, session: bytes.Repeat([]byte{3}, 16), active: true, fh: []byte("held-layout"), state: bytes.Repeat([]byte{4}, 16)}
				version := uint32(1)
				if profile == "krb5p-v3" {
					version = 3
					k.RPCVersion = 3
					r.minor = 2
				}
				var offload *offloadPending
				if mode == "offload" {
					r.minor = 2
					r.offloadEnabled = true
					offload = &offloadPending{fh: []byte("destination"), id: bytes.Repeat([]byte{5}, 16), length: 4096}
					r.offload = offload
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				p := &callbackRenewPeer{t: t, keytab: kt, mode: mode, recall: r, service: service, rpcVersion: version, cancel: cancel}
				done := make(chan error, 1)
				go func() { done <- p.serve(right) }()
				cleanup, err := rpc.establishKerberos(ctx, k, security, 4)
				if err != nil {
					t.Fatal(err)
				}
				old := rpc.gss
				g, err := newGSSBackchannel(old)
				if err != nil {
					t.Fatal(err)
				}
				r.gss = g
				p.oldHandle = bytes.Clone(g.handle)
				rpc.backchannel = newGSSBackchannelSet(g, r)
				rpc.pinnedBackchannelGSS = true
				rpc.duplex = startDuplex(rpc, rpc.backchannel.callback)
				var retired atomic.Int32
				oldCleanup := rpc.kerberos.cleanup
				rpc.kerberos.cleanup = func() { retired.Add(1); oldCleanup() }
				t.Cleanup(func() {
					left.Close()
					<-rpc.duplex.done
					rpc.backchannel.close()
					cleanup()
					if err := <-done; err != nil {
						t.Error(err)
					}
					if retired.Load() != 1 {
						t.Error("old context cleanup count", retired.Load())
					}
				})
				c := &Client{nfs: rpc}
				v := &v4Client{c: c, minor: r.minor, session: bytes.Clone(r.session), sequence: 1, recall: r}
				v.recoverCached = func(context.Context, *v4ReplayRequest) (*rpcClient, func(bool), error) {
					t.Error("control replay attempted")
					return nil, nil, errors.New("no control replay")
				}
				c.v4 = v
				if mode == "exhaustion" {
					old.seq = 0x7ffffffe
				} else if mode == "callback-exhaustion" {
					g.highest = 0x7ffffffe
				} else if mode == "server-warning" {
					v.callbackRenewalNeeded = true
				} else {
					old.renewAt = time.Now().Add(-time.Second)
				}
				err = v.compound(ctx, op4(24, nil, nil))
				bad := mode == "reject" || mode == "lost" || mode == "cancel" || mode == "init-cancel"
				if bad {
					if err == nil || !rpc.closed || !v.stateLost.Load() || p.work.Load() != 0 || rpc.kerberos.renewals != 0 {
						t.Fatal("unconfirmed renewal permitted work", err, p.work.Load())
					}
					if err = v.compound(context.Background(), op4(24, nil, nil)); err == nil {
						t.Fatal("failed renewal revived session")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if rpc.gss == old || rpc.kerberos.renewals != 1 || v.sequence != 3 || p.work.Load() != 1 || p.callbacks.Load() != 4 || r.sequence != 4 || !r.active || !bytes.Equal(r.state, bytes.Repeat([]byte{4}, 16)) {
						t.Fatal("session/callback state was not retained", v.sequence, r.sequence, p.callbacks.Load())
					}
					if mode == "active-recall" && !r.recalled {
						t.Fatal("live layout recall lost during renewal")
					}
					if mode == "offload" && (r.offload != offload || offload.result == nil || offload.result.count != 4096) {
						t.Fatal("offload completion lost during renewal")
					}
				}
				controls := int32(1)
				if mode == "init-cancel" {
					controls = 0
				}
				if p.inits.Load() != 2 || p.controls.Load() != controls || retired.Load() != 0 {
					t.Fatal("context replaced or destroyed prematurely", p.inits.Load(), p.controls.Load(), retired.Load())
				}
			})
		}
	}
}

func TestCallbackRenewalKeepsIndependentCopyPins(t *testing.T) {
	for _, original := range []bool{false, true} {
		c := &rpcClient{pinnedBackchannelGSS: original, gss: &rpcGSS{context: callbackTestPrivacy{}, handle: []byte("parent"), established: true, rpcVersion: 3, service: 3, expiry: time.Now().Add(time.Hour), renewAt: time.Now().Add(time.Hour)}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, first, err := c.pinCopyParent(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_, second, err := c.pinCopyParent(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		first()
		first()
		if c.copyParentPins != 1 || !c.pinnedBackchannelGSS {
			t.Fatal("released another COPY pin")
		}
		second()
		if c.copyParentPins != 0 || c.pinnedBackchannelGSS != original {
			t.Fatal("lost original callback pin")
		}
	}
}

func TestProtectedBackchannelRenewalGuards(t *testing.T) {
	for _, mode := range []string{"uncertain", "moved", "recover-only", "saved-replay", "exact-request", "lock-recorder", "offload-recorder", "copy-pin", "canceled", "unestablished"} {
		t.Run(mode, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			g := &rpcGSS{context: testMIC{}, handle: []byte("original"), window: 16, established: true, expiry: time.Now().Add(time.Hour), renewAt: time.Now().Add(-time.Second)}
			back, err := newGSSBackchannel(g)
			if err != nil {
				t.Fatal(err)
			}
			rpc := &rpcClient{conn: left, gss: g, kerberos: &kerberosSession{}, pinnedBackchannelGSS: true}
			r := &layoutRecall{}
			rpc.backchannel = newGSSBackchannelSet(back, r)
			v := &v4Client{c: &Client{nfs: rpc}, session: bytes.Repeat([]byte{9}, 16), sequence: 27, recall: r}
			ctx := context.Background()
			saved := []byte("saved exact mutation bytes")
			switch mode {
			case "uncertain":
				v.stateLost.Store(true)
			case "moved":
				v.leaseMoved.Store(true)
			case "recover-only":
				v.recoverBindOnly = true
			case "saved-replay":
				v.replayFrom = &v4ReplayRequest{}
			case "exact-request":
				ctx = context.WithValue(ctx, savedCompoundExactKey{}, saved)
			case "lock-recorder":
				v.journal = &lockJournal{}
			case "offload-recorder":
				v.beforeCached = func(SavedCompound) error { t.Error("saved request overwritten"); return nil }
			case "copy-pin":
				rpc.copyParentPins = 1
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unestablished":
				g.established = false
			}
			if err := v.compound(ctx, op4(24, nil, nil)); err == nil || !rpc.closed || v.sequence != 27 || rpc.gss != g || rpc.kerberos.renewals != 0 || len(rpc.backchannel.entries) != 1 || !bytes.Equal(saved, []byte("saved exact mutation bytes")) {
				t.Fatal("unsafe renewal altered slot/context", err)
			}
		})
	}
}

func TestBackchannelRotationRetainsReplayAndCleansExpired(t *testing.T) {
	r := &layoutRecall{minor: 1, session: bytes.Repeat([]byte{3}, 16)}
	makeBack := func() *gssBackchannel {
		g, err := newGSSBackchannel(&rpcGSS{context: callbackTestPrivacy{}, handle: []byte("fore"), service: 3, window: 16, established: true, expiry: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	old, fresh := makeBack(), makeBack()
	s := newGSSBackchannelSet(old, r)
	first := gssProtectCallback(t, old, callbackCall(r, 1, false), 1)
	if _, err := s.callback(first); err != nil {
		t.Fatal(err)
	}
	var cleanups int
	if err := s.retire(func() { cleanups++ }); err != nil {
		t.Fatal(err)
	}
	s.add(fresh)
	if _, err := s.callback(gssProtectCallback(t, fresh, callbackCall(r, 2, false), 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.callback(first); err == nil {
		t.Fatal("rotation reset old RPC replay window")
	}
	if _, err := s.callback(gssProtectCallback(t, old, callbackCall(r, 2, false), 2)); err != nil {
		t.Fatal("old-context slot replay lost", err)
	}
	if r.sequence != 2 || cleanups != 0 {
		t.Fatal("old context or session slot retired early")
	}
	old.expiry = time.Now().Add(-time.Second)
	if _, err := s.callback(gssProtectCallback(t, fresh, callbackCall(r, 3, false), 2)); err != nil {
		t.Fatal(err)
	}
	if cleanups != 1 || len(s.entries) != 1 {
		t.Fatal("expired context retained", cleanups, len(s.entries))
	}
	s.close()
	if cleanups != 1 {
		t.Fatal("retired cleanup repeated")
	}
}

func TestBackchannelRotationRetentionBound(t *testing.T) {
	r := &layoutRecall{}
	g := &gssBackchannel{expiry: time.Now().Add(time.Hour)}
	s := newGSSBackchannelSet(g, r)
	cleaned := 0
	for range 7 {
		if err := s.retire(func() { cleaned++ }); err != nil {
			t.Fatal(err)
		}
		s.add(&gssBackchannel{expiry: time.Now().Add(time.Hour)})
	}
	if err := s.retire(func() { t.Error("refused context ownership transferred") }); err == nil {
		t.Fatal("unbounded live contexts")
	}
	s.close()
	if cleaned != 7 {
		t.Fatal("retained cleanup count", cleaned)
	}
}
