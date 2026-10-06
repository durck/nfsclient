package nfs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// TLSConfig selects mandatory RFC 9289 STARTTLS on every RPC connection,
// including discovery and MOUNT. There is deliberately no plaintext fallback.
type TLSConfig struct {
	Enabled                               bool
	InsecureSkipVerify                    bool
	CAFile, ServerName, CertFile, KeyFile string
}

func (cfg Config) tlsConfig() (*tls.Config, error) {
	t := cfg.TLS
	if !t.Enabled {
		if t.InsecureSkipVerify || t.CAFile != "" || t.ServerName != "" || t.CertFile != "" || t.KeyFile != "" {
			return nil, errors.New("TLS options require --tls")
		}
		return nil, nil
	}
	if cfg.Transport != "tcp" {
		return nil, errors.New("RPC-over-TLS requires TCP; DTLS is unsupported")
	}
	if (t.CertFile == "") != (t.KeyFile == "") {
		return nil, errors.New("TLS client certificate and key must be specified together")
	}
	name := t.ServerName
	if name == "" {
		name = cfg.Host
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: name, NextProtos: []string{"sunrpc"}, InsecureSkipVerify: t.InsecureSkipVerify}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, err
		}
		c.RootCAs = x509.NewCertPool()
		if !c.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("TLS CA file contains no certificates")
		}
	}
	if t.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, err
		}
		c.Certificates = []tls.Certificate{cert}
	}
	return c, nil
}

func dialConfiguredRPC(ctx context.Context, cfg Config, port int, program, version uint32) (*rpcClient, error) {
	tlsConfig, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	transport := cfg.Transport
	if transport == "iwarp" {
		transport = "tcp"
	}
	c, err := dialRPCResolved(ctx, cfg.Host, port, cfg.Timeout, cfg.ReservedPort, transport, cfg.DNS)
	if err != nil {
		return nil, err
	}
	if cfg.Transport == "iwarp" {
		if err := c.startIWARP(ctx); err != nil {
			c.conn.Close()
			return nil, fmt.Errorf("software iWARP: %w", err)
		}
	}
	if tlsConfig != nil {
		if err := c.startTLS(ctx, program, version, tlsConfig); err != nil {
			c.conn.Close()
			return nil, fmt.Errorf("RPC-over-TLS: %w", err)
		}
	}
	return c, nil
}

// Called only before ordinary RPC/GSS and before the connection is published.
func (c *rpcClient) startTLS(ctx context.Context, program, version uint32, config *tls.Config) (resultErr error) {
	c.tlsVerifiedChains = nil
	if c.udp {
		return errors.New("STARTTLS is TCP-only")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := c.conn.SetDeadline(deadline); err != nil {
		return err
	}
	raw := c.conn
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		if resultErr == nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
		if resultErr != nil {
			c.tlsVerifiedChains = nil
			raw.Close()
		}
	}()
	c.xid++
	var call encoder
	for _, v := range []uint32{c.xid, 0, 2, program, version, 0, 7, 0, 0, 0} {
		call.u32(v)
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(call))|0x80000000)
	packet = append(packet, call...)
	for len(packet) > 0 {
		n, err := raw.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		packet = packet[n:]
	}
	response, err := readRecord(raw)
	if err != nil {
		return err
	}
	d := &decoder{b: response}
	if d.u32() != c.xid || d.u32() != 1 || d.u32() != 0 || d.u32() != 0 || string(d.opaque(400)) != "STARTTLS" {
		return errors.New("server did not acknowledge AUTH_TLS; plaintext fallback refused")
	}
	status := d.u32()
	if status == 2 {
		d.u32()
		d.u32()
	}
	if d.err != nil || len(d.b) != 0 || status > 5 {
		return errors.New("malformed AUTH_TLS acknowledgement")
	}
	// Go's TLS verifier supports serverAuth, but not the RPC-specific EKU.
	// Keep the actual verified chains separately: crypto/tls leaves its own
	// VerifiedChains empty when verification is supplied by VerifyConnection.
	config = config.Clone()
	var verifiedChains [][]*x509.Certificate
	if !config.InsecureSkipVerify {
		verifyConnection := config.VerifyConnection
		config.InsecureSkipVerify = true
		config.VerifyConnection = func(state tls.ConnectionState) error {
			chains, err := verifyRPCCertificate(state.PeerCertificates, config)
			if err != nil {
				return err
			}
			if verifyConnection != nil {
				if err := verifyConnection(state); err != nil {
					return err
				}
			}
			verifiedChains = chains
			return nil
		}
	}
	secured := tls.Client(raw, config)
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	if secured.ConnectionState().NegotiatedProtocol != "sunrpc" {
		return errors.New("server did not negotiate sunrpc ALPN")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.conn = secured
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	c.tlsVerifiedChains = verifiedChains
	return nil
}

func verifyRPCCertificate(peers []*x509.Certificate, config *tls.Config) ([][]*x509.Certificate, error) {
	if len(peers) == 0 || config.ServerName == "" {
		return nil, errors.New("RPC TLS verification requires a peer certificate and server name")
	}
	// RFC 9289 5.2.1 prohibits wildcard DNS identifiers for RPC servers.
	for _, name := range peers[0].DNSNames {
		if strings.Contains(name, "*") {
			return nil, errors.New("RPC TLS server certificate contains a wildcard DNS identifier")
		}
	}
	opts := x509.VerifyOptions{Roots: config.RootCAs, DNSName: config.ServerName,
		Intermediates: x509.NewCertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if config.Time != nil {
		opts.CurrentTime = config.Time()
	}
	for _, cert := range peers[1:] {
		opts.Intermediates.AddCert(cert)
	}
	chains, err := peers[0].Verify(opts)
	if err != nil {
		return nil, err
	}
	// Verify all ordinary X.509 requirements above, then intersect the two
	// accepted purposes across each complete chain, including CA constraints.
	// Allowing each certificate to choose a different purpose is insufficient.
	var verified [][]*x509.Certificate
	for _, chain := range chains {
		purposes := uint8(3) // serverAuth and id-kp-rpcTLSServer
		for _, cert := range chain {
			if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
				continue
			}
			var allowed uint8
			for _, usage := range cert.ExtKeyUsage {
				switch usage {
				case x509.ExtKeyUsageAny:
					allowed = 3
				case x509.ExtKeyUsageServerAuth:
					allowed |= 1
				}
			}
			for _, usage := range cert.UnknownExtKeyUsage {
				if usage.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 34}) {
					allowed |= 2
				}
			}
			purposes &= allowed
		}
		if purposes != 0 {
			verified = append(verified, chain)
		}
	}
	if len(verified) == 0 {
		return nil, errors.New("RPC TLS certificate chain does not permit serverAuth or rpcTLSServer")
	}
	return verified, nil
}

func (c *Client) TLSActive() bool {
	if c.nfs == nil {
		return false
	}
	_, ok := c.nfs.conn.(*tls.Conn)
	return ok
}

func (c *Client) TLSCertificateVerified() bool {
	if c.nfs == nil {
		return false
	}
	conn, ok := c.nfs.conn.(*tls.Conn)
	if !ok {
		return false
	}
	state := conn.ConnectionState()
	return state.HandshakeComplete && (len(state.VerifiedChains) != 0 || len(c.nfs.tlsVerifiedChains) != 0)
}

// RFC 9266 exporter plus the RFC 5056 type prefix. This is binding data,
// not key material for another use, and must come from this exact connection.
func tlsGSSBinding(conn *tls.Conn) ([]byte, error) {
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "sunrpc" {
		return nil, errors.New("GSS channel binding requires completed TLS 1.3 with sunrpc ALPN")
	}
	exporter, err := state.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, 32)
	if err != nil {
		return nil, fmt.Errorf("GSS TLS exporter: %w", err)
	}
	return append([]byte("tls-exporter:"), exporter...), nil
}
