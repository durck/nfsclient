package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const nsmProgram = 100024

// Automatic callback ports are used by isolated fixtures. TCP and UDP have
// different excluded ranges on Windows; bind both before accepting a candidate.
// Explicit ports (including the public port 111 profile) never move on failure.
func listenNSMPair(listen string, port int) (net.Listener, *net.UDPConn, error) {
	attempts := 1
	if port == 0 {
		attempts = 32
	}
	var last error
	for range attempts {
		candidate := port
		if candidate == 0 {
			candidate = 16384 + rand.IntN(65536-16384)
		}
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(listen), Port: candidate})
		if err != nil {
			last = err
			continue
		}
		l, err := net.Listen("tcp4", net.JoinHostPort(listen, strconv.Itoa(candidate)))
		if err == nil {
			return l, u, nil
		}
		u.Close()
		last = err
	}
	return nil, nil, fmt.Errorf("exclusive NSM/portmapper TCP/UDP listener: %w", last)
}

type nsmMonitor struct {
	state       *nsmState
	cfg         Config
	peer        string
	peerState   uint32
	localEpoch  atomic.Uint32
	statRPC     *rpcClient // Retain transport; per-RPC dials exhaust ephemeral ports.
	lost        atomic.Bool
	active      atomic.Int32
	onLost      func()
	health      func(context.Context) error
	tcp         net.Listener
	udp         *net.UDPConn
	port        int
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]bool
	probeMu     sync.Mutex
	callbacks   atomic.Pointer[nlmCallbacks]
}

func validateNLMConfig(cfg Config) error {
	if cfg.NLMAutoNotify && !cfg.NLMAutoRecover {
		return errors.New("--nlm-auto-notify requires --nlm-auto-recover")
	}
	if cfg.NLMClientIP == "" && cfg.NLMListenIP == "" && cfg.NLMStateDir == "" && !cfg.NLMReclaim && !cfg.NLMAutoRecover && !cfg.NLMAutoNotify {
		return nil
	}
	if cfg.Version != "2" && cfg.Version != "3" || cfg.Security != "" && cfg.Security != "sys" || cfg.TLS.Enabled || cfg.Transport == "iwarp" {
		return errors.New("retained NLM requires explicit NFSv2/v3 and AUTH_SYS without TLS")
	}
	ip := net.ParseIP(cfg.NLMClientIP)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || cfg.NLMStateDir == "" {
		return errors.New("NLM requires an explicit client IPv4 address and persistent --nlm-state-dir")
	}
	if cfg.NLMListenIP != "" {
		ip := net.ParseIP(cfg.NLMListenIP)
		if ip == nil || ip.To4() == nil || ip.IsMulticast() {
			return errors.New("NLM listen IP must be a local IPv4 address or 0.0.0.0")
		}
	}
	return nil
}

func readNSMState(ctx context.Context, rpc *rpcClient, clientIP string) (uint32, error) {
	var e encoder
	e.str(clientIP)
	d, err := rpc.call(ctx, nsmProgram, 1, 1, nil, e)
	if err != nil {
		return 0, err
	}
	status, state := d.u32(), d.u32()
	if d.err != nil {
		return 0, d.err
	}
	if len(d.b) != 0 || status != 0 || state == 0 || state > 0x7fffffff || state%2 != 1 {
		return 0, errors.New("NSM did not confirm a valid running epoch")
	}
	return state, nil
}

// port is 111 in the public profile. Tests use a free high port without taking
// ownership of a machine's RPC services. Only the pinned NFS peer is admitted.
func startNSM(ctx context.Context, cfg Config, peer string, port int, onLost func(), health func(context.Context) error) (_ *nsmMonitor, err error) {
	return startNSMMode(ctx, cfg, peer, port, onLost, health, false)
}

func startNSMMode(ctx context.Context, cfg Config, peer string, port int, onLost func(), health func(context.Context) error, recoverLocks bool) (_ *nsmMonitor, err error) {
	if err := validateNLMConfig(cfg); err != nil {
		return nil, err
	}
	cfg.Host = peer
	cfg.ReservedPort = false
	statPort, err := discoverSidePort(ctx, cfg, nsmProgram, 1, "NSM")
	if err != nil {
		return nil, err
	}
	statRPC, err := dialConfiguredRPC(ctx, cfg, statPort, nsmProgram, 1)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			statRPC.conn.Close()
		}
	}()
	if cfg.NLMAutoNotify {
		local, _, splitErr := net.SplitHostPort(statRPC.conn.LocalAddr().String())
		if splitErr != nil || !net.ParseIP(local).Equal(net.ParseIP(cfg.NLMClientIP)) {
			return nil, errors.New("automatic NSM notification requires the dedicated client address as its direct transport source")
		}
	}
	peerState, err := readNSMState(ctx, statRPC, cfg.NLMClientIP)
	if err != nil {
		return nil, fmt.Errorf("NSM server state: %w", err)
	}
	listen := cfg.NLMListenIP
	if listen == "" {
		listen = cfg.NLMClientIP
	}
	l, u, err := listenNSMPair(listen, port)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			l.Close()
			u.Close()
		}
	}()
	port = l.Addr().(*net.TCPAddr).Port
	state, err := openNSMStateMode(cfg.NLMStateDir, cfg.NLMClientIP, peer, recoverLocks)
	if err != nil {
		return nil, err
	}
	if state.record.NotifyEpoch != 0 && !cfg.NLMAutoNotify {
		state.close()
		return nil, errors.New("unfinished NSM notification requires --nlm-auto-notify; no lock may precede it")
	}
	n := &nsmMonitor{state: state, cfg: cfg, peer: peer, peerState: peerState, statRPC: statRPC, onLost: onLost, health: health, tcp: l, udp: u, port: port, connections: make(map[net.Conn]bool)}
	n.localEpoch.Store(state.record.State)
	bg, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	n.wg.Add(3)
	go n.serveTCP(bg)
	go n.serveUDP(bg)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-bg.Done():
				return
			case <-ticker.C:
				if n.active.Load() > 0 && !n.lost.Load() {
					n.probe(bg)
				}
			}
		}
	}()
	return n, nil
}

func (n *nsmMonitor) invalidate() {
	if !n.lost.Swap(true) && n.active.Load() > 0 && n.onLost != nil {
		n.onLost()
	}
}

func (n *nsmMonitor) probe(ctx context.Context) error {
	n.probeMu.Lock()
	defer n.probeMu.Unlock()
	if n.lost.Load() {
		return ErrLockUncertain
	}
	ctx, cancel := context.WithTimeout(ctx, n.cfg.Timeout)
	defer cancel()
	state, err := readNSMState(ctx, n.statRPC, n.cfg.NLMClientIP)
	if err == nil && state == n.peerState && n.health != nil {
		err = n.health(ctx)
	}
	if err != nil || state != n.peerState {
		n.invalidate()
		return errors.Join(ErrLockUncertain, err)
	}
	if n.lost.Load() {
		return ErrLockUncertain
	}
	return nil
}

func (n *nsmMonitor) close() {
	n.cancel()
	n.statRPC.conn.Close()
	n.tcp.Close()
	n.udp.Close()
	n.mu.Lock()
	for c := range n.connections {
		c.Close()
	}
	n.mu.Unlock()
	n.wg.Wait()
	n.state.close()
}

func (n *nsmMonitor) accepts(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	return err == nil && net.ParseIP(host).Equal(net.ParseIP(n.peer))
}

func (n *nsmMonitor) serveUDP(ctx context.Context) {
	defer n.wg.Done()
	b := make([]byte, 4097)
	for {
		size, peer, err := n.udp.ReadFromUDP(b)
		if err != nil {
			if ctx.Err() == nil {
				n.invalidate()
			}
			return
		}
		if size > 4096 || !n.accepts(peer) {
			continue
		}
		n.respond(b[:size], func(reply []byte) error {
			if err := n.udp.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return err
			}
			written, err := n.udp.WriteToUDP(reply, peer)
			if err == nil && written != len(reply) {
				err = io.ErrShortWrite
			}
			return err
		})
	}
}

func (n *nsmMonitor) serveTCP(ctx context.Context) {
	defer n.wg.Done()
	for {
		c, err := n.tcp.Accept()
		if err != nil {
			if ctx.Err() == nil {
				n.invalidate()
			}
			return
		}
		n.mu.Lock()
		if !n.accepts(c.RemoteAddr()) || len(n.connections) >= 16 || ctx.Err() != nil {
			n.mu.Unlock()
			c.Close()
			continue
		}
		n.connections[c] = true
		n.wg.Add(1)
		n.mu.Unlock()
		go func() {
			defer n.wg.Done()
			defer c.Close()
			defer func() { n.mu.Lock(); delete(n.connections, c); n.mu.Unlock() }()
			// One bounded RPC per connection; rpc.statd can reconnect as needed.
			c.SetDeadline(time.Now().Add(3 * time.Second))
			b, err := readNSMRecord(c)
			if err != nil {
				return
			}
			n.respond(b, func(reply []byte) error {
				record := nsmRecordBytes(reply)
				written, err := c.Write(record)
				if err == nil && written != len(record) {
					err = io.ErrShortWrite
				}
				return err
			})
		}()
	}
}
