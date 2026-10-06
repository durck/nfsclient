package gssapi

import (
	"bytes"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestFileCacheCancelPreservesKeysUntilClose(t *testing.T) {
	m := NewFileCacheRenewal()
	defer m.Close()
	key := bytes.Repeat([]byte{0x42}, 32)
	m.mu.Lock()
	m.cache = &credentials.CCache{Credentials: []*credentials.Credential{{Key: types.EncryptionKey{KeyType: 18, KeyValue: key}}}}
	// An active exchange owns the credential mutex. Cancellation must neither
	// wait for it nor clear key material that exchange may still be using.
	done := make(chan struct{})
	go func() { m.Cancel(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		m.mu.Unlock()
		t.Fatal("Cancel waited for active credential work")
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{0x42}, 32)) {
		m.mu.Unlock()
		t.Fatal("Cancel destroyed active key material")
	}
	m.mu.Unlock()
	m.Close()
	if !bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("Close retained credential key material")
	}
}
