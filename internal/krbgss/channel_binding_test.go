package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestChannelBindingChecksum(t *testing.T) {
	data := append([]byte("tls-exporter:"), make([]byte, 32)...)
	for i := range 32 {
		data[len("tls-exporter:")+i] = byte(i)
	}
	got := channelBindingHash(data)
	// Independent Python struct.pack('<5I',255,0,255,0,45) plus fixture
	// application bytes, hashed with hashlib.md5, not the implementation.
	if hex.EncodeToString(got[:]) != "cba061f18a9fd11d871fa14fb0c3f16b" {
		t.Fatal("wrong binding encoding")
	}
	if channelBindingHash(nil) != ([16]byte{}) {
		t.Fatal("no-bindings sentinel")
	}
	valid := make([]byte, 24)
	binary.LittleEndian.PutUint32(valid, 16)
	copy(valid[4:20], got[:])
	binary.LittleEndian.PutUint32(valid[20:], gssapi.ContextFlagMutual|gssapi.ContextFlagInteg)
	for _, mode := range []string{"ok", "type", "length", "hash", "none", "delegation", "extension"} {
		t.Run(mode, func(t *testing.T) {
			b := bytes.Clone(valid)
			kind := int32(chksumtype.GSSAPI)
			binding := data
			switch mode {
			case "type":
				kind = 0
			case "length":
				b[0] = 15
			case "hash":
				b[4] ^= 1
			case "none":
				binding = nil
			case "delegation":
				b[20] |= 1
			case "extension":
				b = append(b, 0, 0, 0, 0)
			}
			flags, err := validateAuthenticatorChecksum(types.Checksum{CksumType: kind, Checksum: b}, binding)
			ok := mode == "ok" || mode == "extension"
			if (err == nil) != ok || ok && flags != gssapi.ContextFlagMutual|gssapi.ContextFlagInteg {
				t.Fatal(flags, err)
			}
		})
	}
	for length := range 24 {
		if _, err := validateAuthenticatorChecksum(types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: valid[:length]}, data); err == nil {
			t.Fatal("truncated checksum accepted", length)
		}
	}
	clear(valid[4:20])
	if _, err := validateAuthenticatorChecksum(types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: valid}, data); err == nil {
		t.Fatal("missing required binding accepted")
	}
	if _, err := validateAuthenticatorChecksum(types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: valid}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestChannelBindingOptionCopiesAndBounds(t *testing.T) {
	c := &Initiator{}
	data := []byte("binding")
	if err := WithChannelBinding[Initiator](data)(c); err != nil {
		t.Fatal(err)
	}
	data[0] = 'x'
	if string(c.channelBinding) != "binding" {
		t.Fatal("binding aliases caller data")
	}
	for _, data := range [][]byte{{}, make([]byte, 4097)} {
		if err := WithChannelBinding[Initiator](data)(c); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
}
