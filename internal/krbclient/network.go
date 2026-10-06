package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"nfsclient/internal/resolve"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

const maxKDCMessage = 4 << 20

type kdcEndpointKey struct{ realm, network, address string }

// Network deadlines and context timer callbacks run independently. Consult the
// deadline too, so a socket timeout cannot become an early failover or lose the
// caller's DeadlineExceeded identity while Err() is still being published.
func kdcContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Preserve Kerberos transport preference, but share one caller deadline across
// discovery, fallback, preauthentication and referrals. Never leave detached I/O.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	if realm == "" {
		realm = cl.Config.LibDefaults.DefaultRealm
	}
	ctx := cl.settings.networkContext
	if ctx == nil {
		ctx = context.Background()
	}
	networks := []string{"tcp"}
	if cl.Config.LibDefaults.UDPPreferenceLimit != 1 {
		if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
			networks = []string{"udp", "tcp"}
		} else {
			networks = []string{"tcp", "udp"}
		}
	}
	var last error = errors.New("no KDC endpoints available")
	for _, network := range networks {
		if err := kdcContextError(ctx); err != nil {
			return nil, err
		}
		endpoints, err := cl.kdcEndpoints(ctx, realm, network)
		if err != nil {
			last = err
			continue
		}
		// Retain configured/SRV order among healthy candidates. Endpoints that
		// failed earlier in this AS/TGS setup go last, not into a global blacklist.
		ordered := make([]string, 0, len(endpoints))
		failed := make([]string, 0, len(endpoints))
		for _, endpoint := range endpoints {
			if _, known := cl.kdcFailures.Load(kdcEndpointKey{realm, network, endpoint}); known {
				failed = append(failed, endpoint)
			} else {
				ordered = append(ordered, endpoint)
			}
		}
		ordered = append(ordered, failed...)
		for i, endpoint := range ordered {
			if err := kdcContextError(ctx); err != nil {
				return nil, err
			}
			// Do not let one silent endpoint consume the entire caller deadline
			// while another configured KDC remains. The final candidate gets the
			// remainder; kdcExchange still enforces its five-second ceiling.
			candidateCtx := ctx
			cancel := func() {}
			if deadline, ok := ctx.Deadline(); ok && len(ordered)-i > 1 {
				candidateCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(ordered)-i))
			}
			reply, err := kdcExchange(candidateCtx, network, endpoint, b, cl.settings.dns)
			cancel()
			key := kdcEndpointKey{realm, network, endpoint}
			if err != nil {
				last = err
				if kdcContextError(ctx) == nil {
					cl.kdcFailures.Store(key, struct{}{})
				}
				continue
			}
			var krbErr messages.KRBError
			if krbErr.Unmarshal(reply) == nil {
				// Like MIT krb5, continue only for service unavailability. Other
				// errors (including preauth challenges/denials) go to AS/TGS logic.
				if krbErr.ErrorCode == errorcode.KDC_ERR_SVC_UNAVAILABLE {
					last = krbErr
					cl.kdcFailures.Store(key, struct{}{})
					continue
				}
				cl.kdcFailures.Delete(key)
				if network == "udp" && krbErr.ErrorCode == errorcode.KRB_ERR_RESPONSE_TOO_BIG {
					last = krbErr
					break
				}
				return nil, krbErr
			}
			cl.kdcFailures.Delete(key)
			return reply, nil
		}
	}
	if err := kdcContextError(ctx); err != nil {
		return nil, err
	}
	if krbErr, ok := last.(messages.KRBError); ok {
		return nil, krbErr
	}
	return nil, fmt.Errorf("KDC communication failed: %w", last)
}

func (cl *Client) kdcEndpoints(ctx context.Context, realm, network string) ([]string, error) {
	if err := kdcContextError(ctx); err != nil {
		return nil, err
	}
	if realm == "" {
		realm = cl.Config.LibDefaults.DefaultRealm
	}
	for _, r := range cl.Config.Realms {
		if r.Realm == realm && len(r.KDC) > 0 {
			return append([]string(nil), r.KDC...), nil
		}
	}
	if !cl.Config.LibDefaults.DNSLookupKDC {
		return nil, fmt.Errorf("no KDC configured for realm %s", realm)
	}
	resolver, err := resolve.New(ctx, cl.settings.dns)
	if err != nil {
		return nil, err
	}
	_, records, err := resolver.LookupSRV(ctx, "kerberos", network, realm)
	if err != nil {
		return nil, err
	}
	var endpoints []string
	for _, r := range records {
		if r.Target != "." {
			endpoints = append(endpoints, net.JoinHostPort(strings.TrimSuffix(r.Target, "."), strconv.Itoa(int(r.Port))))
		}
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no KDC SRV records for realm %s", realm)
	}
	return endpoints, nil
}

func kdcExchange(parent context.Context, network, endpoint string, request []byte, dns resolve.Config) (reply []byte, err error) {
	if len(request) == 0 || len(request) > maxKDCMessage {
		return nil, errors.New("invalid KDC request size")
	}
	if network == "udp" && len(request) > 65507 {
		return nil, errors.New("KDC request exceeds UDP limit")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	defer func() {
		if deadlineErr := kdcContextError(ctx); deadlineErr != nil {
			reply, err = nil, deadlineErr
		}
	}()
	resolver, err := resolve.New(ctx, dns)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Resolver: resolver}).DialContext(ctx, network, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if network == "udp" {
		reply, err = kdcUDPRoundTrip(ctx, conn, request, time.Second)
	} else {
		reply, err = kdcRoundTrip(conn, network, request)
	}
	return reply, err
}

// RFC 4120 permits retransmitting AS/TGS requests. Reuse the same encoded
// request/socket so a lost reply does not consume the entire setup budget.
// This is KDC traffic only; it never replays an NFS mutation or GSS control call.
func kdcUDPRoundTrip(ctx context.Context, conn net.Conn, request []byte, retryDelay time.Duration) ([]byte, error) {
	deadline, _ := ctx.Deadline()
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		until := time.Now().Add(retryDelay << attempt)
		if !deadline.IsZero() && deadline.Before(until) {
			until = deadline
		}
		if err := conn.SetDeadline(until); err != nil {
			return nil, err
		}
		reply, err := kdcRoundTrip(conn, "udp", request)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		var timeout net.Error
		if err == nil || !errors.As(err, &timeout) || !timeout.Timeout() || attempt == 2 {
			return reply, err
		}
	}
	panic("unreachable KDC retry state")
}

func kdcRoundTrip(conn net.Conn, network string, request []byte) ([]byte, error) {
	if network == "udp" {
		if n, err := conn.Write(request); err != nil {
			return nil, err
		} else if n != len(request) {
			return nil, io.ErrShortWrite
		}
		buf := make([]byte, 65536)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return buf[:n], nil
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(request)))
	packet = append(packet, request...)
	for len(packet) > 0 {
		n, err := conn.Write(packet)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		packet = packet[n:]
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxKDCMessage {
		return nil, errors.New("invalid KDC TCP response size (limit 4 MiB)")
	}
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	return reply, nil
}
