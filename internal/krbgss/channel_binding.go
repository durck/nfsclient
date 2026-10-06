package gssapi

import (
	"bytes"
	"crypto/md5" // RFC 4121 specifies this hash inside the encrypted authenticator.
	"encoding/binary"
	"errors"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// WithChannelBinding supplies application data; network addresses are omitted
// using GSS_C_AF_NULLADDR. Nil selects no binding; nonnil data is copied.
func WithChannelBinding[T Initiator | Acceptor](data []byte) Option[T] {
	return func(value *T) error {
		if data != nil && (len(data) == 0 || len(data) > 4096) {
			return errors.New("channel binding application data must contain 1..4096 bytes")
		}
		switch ctx := any(value).(type) {
		case *Initiator:
			ctx.channelBinding = bytes.Clone(data)
		case *Acceptor:
			ctx.channelBinding = bytes.Clone(data)
		}
		return nil
	}
}

func channelBindingHash(data []byte) [16]byte {
	if data == nil {
		return [16]byte{}
	}
	// RFC 4121 4.1.1.2: include all five integer/length fields in little
	// endian, then the application bytes. No socket address is part of TLS
	// exporter bindings (RFC 2744 3.11 uses address type 255 for no address).
	var encoded []byte
	for _, n := range []uint32{255, 0, 255, 0, uint32(len(data))} {
		encoded = binary.LittleEndian.AppendUint32(encoded, n)
	}
	encoded = append(encoded, data...)
	return md5.Sum(encoded)
}

func validateAuthenticatorChecksum(checksum types.Checksum, binding []byte) (int, error) {
	b := checksum.Checksum
	if checksum.CksumType != chksumtype.GSSAPI || len(b) < 24 || binary.LittleEndian.Uint32(b[:4]) != 16 {
		return 0, errors.New("invalid Kerberos GSS authenticator checksum")
	}
	want := channelBindingHash(binding)
	if !bytes.Equal(b[4:20], want[:]) {
		return 0, errors.New("kerberos GSS channel binding mismatch")
	}
	flags := binary.LittleEndian.Uint32(b[20:24])
	if flags&gssapi.ContextFlagDeleg != 0 {
		return 0, errors.New("kerberos GSS delegation is unsupported")
	}
	return int(flags & supportedFlags), nil
}
