package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

// ValidateCCacheSelection is shared with the NFS pre-network configuration gate.
// KCM names are explicit subsidiaries; no ambient/default collection selection.
func ValidateCCacheSelection(name, socket string) error {
	if strings.HasPrefix(name, "MSLSA:") {
		if name != lsaCurrentCache || socket != "" {
			return errors.New("MSLSA requires exactly --ccache MSLSA:CURRENT without --kcm-socket")
		}
		return lsaPlatform()
	}
	if strings.HasPrefix(name, "KEYRING:") {
		if socket != "" {
			return errors.New("--kcm-socket requires an explicit KCM credential cache")
		}
		if _, err := parseKeyringName(name); err != nil {
			return err
		}
		return keyringPlatform()
	}
	if !strings.HasPrefix(name, "KCM:") {
		if socket != "" {
			return errors.New("--kcm-socket requires an explicit KCM credential cache")
		}
		return nil
	}
	residual := strings.TrimPrefix(name, "KCM:")
	if residual == "" || len(residual) > 256 || !utf8.ValidString(residual) || strings.ContainsAny(residual, "\x00\r\n") {
		return errors.New("KCM requires a nonempty explicit cache name of at most 256 bytes")
	}
	if !filepath.IsAbs(socket) || len(socket) > 107 || strings.HasPrefix(socket, "@") {
		return errors.New("KCM requires an explicit absolute --kcm-socket path of at most 107 bytes")
	}
	return kcmPlatform()
}

func readSelectedCCache(ctx stdcontext.Context, name, socket string, principal ...string) (*credentials.CCache, error) {
	if err := ValidateCCacheSelection(name, socket); err != nil {
		return nil, err
	}
	if name == lsaCurrentCache {
		if len(principal) != 1 {
			return nil, errors.New("MSLSA requires an explicit pinned canonical principal")
		}
		return readLSACCache(ctx, principal[0])
	}
	if strings.HasPrefix(name, "KEYRING:") {
		return readKernelCCache(ctx, name)
	}
	if !strings.HasPrefix(name, "KCM:") {
		return readCCache(name)
	}
	if ctx == nil {
		ctx = stdcontext.Background()
	}
	ctx, cancel := stdcontext.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dialKCM(ctx, socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return readKCMConn(ctx, conn, strings.TrimPrefix(name, "KCM:"))
}

type kcmReader struct{ conn net.Conn }

func (k *kcmReader) call(op uint16, name string, extra []byte) ([]byte, error) {
	request := binary.BigEndian.AppendUint16([]byte{2, 0}, op)
	request = append(request, []byte(name)...)
	request = append(request, 0)
	request = append(request, extra...)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(request)))
	frame = append(frame, request...)
	for len(frame) > 0 {
		n, err := k.conn.Write(frame)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
		frame = frame[n:]
	}
	var header [8]byte
	if _, err := io.ReadFull(k.conn, header[:]); err != nil {
		return nil, err
	}
	size, status := binary.BigEndian.Uint32(header[:4]), binary.BigEndian.Uint32(header[4:])
	if status != 0 {
		return nil, fmt.Errorf("KCM transport status %d", status)
	}
	if size < 4 || size > maxCCacheSize {
		return nil, errors.New("KCM reply outside the 4 MiB budget")
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(k.conn, response); err != nil {
		clear(response)
		return nil, err
	}
	if code := int32(binary.BigEndian.Uint32(response[:4])); code != 0 {
		clear(response)
		return nil, fmt.Errorf("KCM operation %d failed (%d)", op, code)
	}
	return response[4:], nil
}

func kcmUUIDs(b []byte) error {
	if len(b) == 0 || len(b)%16 != 0 || len(b) > 64*16 {
		return errors.New("KCM requires 1..64 complete credential UUIDs")
	}
	seen := map[[16]byte]bool{}
	for i := 0; i < len(b); i += 16 {
		id := [16]byte(b[i : i+16])
		if id == [16]byte{} || seen[id] {
			return errors.New("KCM has a zero or duplicate credential UUID")
		}
		seen[id] = true
	}
	return nil
}

// Read-only KCM 2.0: GET_PRINCIPAL, GET_CRED_UUID_LIST, GET_CRED_BY_UUID and
// GET_KDC_OFFSET. Framing follows MIT krb5; blobs use FILE v4 serialization.
func readKCMConn(ctx stdcontext.Context, conn net.Conn, name string) (_ *credentials.CCache, resultErr error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := stdcontext.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		if ctx.Err() != nil {
			resultErr = ctx.Err()
		}
	}()
	k := &kcmReader{conn: conn}
	offset := func() error {
		b, err := k.call(22, name, nil)
		if err != nil {
			return err
		}
		defer clear(b)
		if len(b) != 4 || binary.BigEndian.Uint32(b) != 0 {
			return errors.New("KCM clock offset is malformed or nonzero; synchronize clocks")
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := offset(); err != nil {
		return nil, err
	}
	principalWire, err := k.call(8, name, nil)
	if err != nil {
		return nil, err
	}
	defer clear(principalWire)
	p := &cacheReader{b: principalWire}
	p.principal()
	// MIT's published KCM test daemon appends one terminal NUL. Accept exactly
	// that suffix; it is not part of the FILE v4 principal serialization.
	if p.err != nil || len(p.b) != 0 && !bytes.Equal(p.b, []byte{0}) {
		return nil, errors.New("KCM principal encoding is incomplete or has trailing data")
	}
	principal := principalWire[:len(principalWire)-len(p.b)]
	ids, err := k.call(9, name, nil)
	if err != nil {
		return nil, err
	}
	defer clear(ids)
	if err := kcmUUIDs(ids); err != nil {
		return nil, err
	}
	// Fixed capacity prevents append from leaving discarded backing arrays with
	// credential bytes that the final clear cannot reach.
	cache := make([]byte, 4, maxCCacheSize)
	copy(cache, []byte{5, 4, 0, 0})
	cache = append(cache, principal...)
	defer func() { clear(cache) }()
	values := make([][]byte, 0, len(ids)/16)
	defer func() {
		for _, b := range values {
			clear(b)
		}
	}()
	for i := 0; i < len(ids); i += 16 {
		b, err := k.call(10, name, ids[i:i+16])
		if err != nil {
			return nil, err
		}
		values = append(values, b)
		if len(b) > maxCCacheSize-len(cache) {
			return nil, errors.New("KCM snapshot exceeds 4 MiB")
		}
		one := append(append([]byte{5, 4, 0, 0}, principal...), b...)
		parsed, err := parseCCache(one)
		clear(one)
		if err != nil {
			return nil, err
		}
		if len(parsed.Credentials) != 1 {
			return nil, errors.New("KCM UUID must identify exactly one credential")
		}
		// The final parser retains the snapshot; these temporary parsed keys are discarded.
		for _, cred := range parsed.Credentials {
			clear(cred.Key.KeyValue)
			clear(cred.Ticket)
			clear(cred.SecondTicket)
		}
		cache = append(cache, b...)
	}
	for i, b := range values {
		after, err := k.call(10, name, ids[i*16:(i+1)*16])
		if err != nil {
			return nil, err
		}
		same := bytes.Equal(after, b)
		clear(after)
		if !same {
			return nil, errors.New("KCM credential changed during snapshot")
		}
	}
	for _, item := range []struct {
		op       uint16
		expected []byte
	}{{8, principalWire}, {9, ids}} {
		after, err := k.call(item.op, name, nil)
		if err != nil {
			return nil, err
		}
		same := bytes.Equal(after, item.expected)
		clear(after)
		if !same {
			return nil, errors.New("KCM principal or credential list changed during snapshot")
		}
	}
	if err := offset(); err != nil {
		return nil, err
	}
	return parseCCache(cache)
}
